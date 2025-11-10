"""
Database configuration, phone validation, and operations for Ardent Survey API
"""

import logging
import os
import re
import time
from typing import Any, Dict, Optional

import psycopg2
from psycopg2 import pool, extras, Error

# Configure logging
logger = logging.getLogger(__name__)


# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

class DatabaseConfig:
    """PostgreSQL database configuration from environment variables"""
    
    def __init__(self):
        self.host = os.getenv('POSTGRES_HOST', 'localhost')
        self.port = int(os.getenv('POSTGRES_PORT', '5432'))
        self.database = os.getenv('POSTGRES_DB', 'ardent_survey')
        self.user = os.getenv('POSTGRES_USER', 'postgres')
        self.password = os.getenv('POSTGRES_PASSWORD', 'password')
        
        logger.info(f"Database config - Host: {self.host}, DB: {self.database}, Port: {self.port}")


# Global database connection pool
db_config = DatabaseConfig()
db_pool: Optional[pool.ThreadedConnectionPool] = None


# ============================================================================
# PHONE NUMBER VALIDATION
# ============================================================================

class PhoneValidator:
    """Phone number validation with Canadian focus"""
    
    VALID_CANADIAN_AREA_CODES = [
        '403', '587', '780', '825',  # Alberta
        '236', '250', '604', '672', '778',  # British Columbia
        '204', '431',  # Manitoba
        '506',  # New Brunswick
        '709',  # Newfoundland and Labrador
        '867',  # NWT/Nunavut/Yukon
        '782', '902',  # Nova Scotia/PEI
        '226', '249', '289', '343', '365', '416', '437', '519', '548',  # Ontario
        '613', '647', '705', '807', '905',  # Ontario cont.
        '367', '418', '438', '450', '514', '579', '581', '819', '873',  # Quebec
        '306', '639',  # Saskatchewan
    ]
    
    PREMIUM_PREFIXES = ['900', '976', '540']
    SPECIAL_SERVICE_NUMBERS = ['911', '999', '112', '000', '110', '411', '311', '211', '511', '611', '711', '811']
    TOLL_FREE_PREFIXES = ['800', '833', '844', '855', '866', '877', '888']
    
    @staticmethod
    def clean_phone_number(phone: str) -> str:
        """Remove all non-digit characters except +"""
        if not phone or not isinstance(phone, str):
            return ''
        return re.sub(r'[^\d+]', '', phone).strip()
    
    @staticmethod
    def validate(phone: str, user_ip: str = 'unknown') -> Dict[str, Any]:
        """Validate phone number with comprehensive checks"""
        cleaned = PhoneValidator.clean_phone_number(phone)
        logger.info(f"[PHONE_VALIDATION] Validating: {phone} -> {cleaned}, IP: {user_ip}")
        
        if not cleaned or len(cleaned) < 7:
            return {
                'status': 'rejected',
                'reason': 'Invalid phone number format',
                'risk_level': 'medium',
                'validated': False,
                'original_number': phone,
                'cleaned_number': cleaned
            }
        
        # Blocked patterns
        blocked_patterns = [
            r'^(\+?1)?900\d{7}$', r'^(\+?1)?976\d{7}$', r'^(\+?1)?540\d{7}$',
            r'^\+90[0-9]\d+$', r'^0+$', r'^1+$', r'^\d{1,5}$', r'^\d{16,}$'
        ]
        
        for pattern in blocked_patterns:
            if re.match(pattern, cleaned):
                return {
                    'status': 'rejected',
                    'reason': 'Blocked pattern - potential premium/restricted',
                    'risk_level': 'high',
                    'validated': False,
                    'original_number': phone,
                    'cleaned_number': cleaned
                }
        
        # Emergency/special service
        for special in PhoneValidator.SPECIAL_SERVICE_NUMBERS:
            if special in cleaned:
                return {
                    'status': 'rejected',
                    'reason': 'Emergency/special service numbers not accepted',
                    'risk_level': 'high',
                    'validated': False,
                    'original_number': phone,
                    'cleaned_number': cleaned
                }
        
        # US/Canada format
        if re.match(r'^(\+?1)?[2-9]\d{2}[2-9]\d{2}\d{4}$', cleaned):
            area_code = cleaned[2:5] if cleaned.startswith('+1') else (
                cleaned[1:4] if cleaned.startswith('1') else cleaned[:3]
            )
            
            if area_code in PhoneValidator.TOLL_FREE_PREFIXES:
                return {
                    'status': 'rejected',
                    'reason': 'Toll-free numbers not accepted',
                    'risk_level': 'medium',
                    'validated': False,
                    'original_number': phone,
                    'cleaned_number': cleaned
                }
            
            return {
                'status': 'approved',
                'reason': 'Standard business number',
                'risk_level': 'none',
                'validated': True,
                'original_number': phone,
                'cleaned_number': cleaned
            }
        
        # International (if enabled)
        if os.getenv('INTERNATIONAL_NUMBERS_ALLOWED', 'false').lower() == 'true':
            if re.match(r'^\+(?!90[0-9])[1-9]\d{6,14}$', cleaned):
                return {
                    'status': 'approved',
                    'reason': 'Valid international number',
                    'risk_level': 'none',
                    'validated': True,
                    'original_number': phone,
                    'cleaned_number': cleaned
                }
        
        return {
            'status': 'rejected',
            'reason': 'Unverified number format',
            'risk_level': 'medium',
            'validated': False,
            'original_number': phone,
            'cleaned_number': cleaned
        }


# ============================================================================
# DATABASE OPERATIONS
# ============================================================================

class DatabaseOperations:
    """Database operations with retry mechanism"""
    
    @staticmethod
    def get_connection():
        """Get database connection from pool"""
        if db_pool is None:
            raise RuntimeError("Database pool not initialized")
        return db_pool.getconn()
    
    @staticmethod
    def release_connection(conn):
        """Release connection back to pool"""
        if db_pool and conn:
            db_pool.putconn(conn)
    
    @staticmethod
    def retry_operation(operation, max_retries=3, initial_delay=0.1):
        """Retry database operation with exponential backoff"""
        last_exception = None
        delay = initial_delay
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Database operation attempt {attempt + 1}/{max_retries}")
                return operation()
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                last_exception = e
                logger.warning(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                    delay *= 2
            except Exception as e:
                logger.error(f"Non-transient error: {str(e)}")
                raise
        
        raise last_exception if last_exception else Exception("Operation failed after retries")
    
    @staticmethod
    def insert_customer_and_survey(survey_data, phone_validated: bool, submission_id: str, company_id: str) -> int:
        """
        Insert customer and survey response into database with retry logic
        
        Args:
            survey_data: SurveyRequest pydantic model
            phone_validated: Whether phone number passed validation
            submission_id: Unique submission identifier
            company_id: Company identifier
        
        Returns:
            customer_id of the inserted/updated customer
        """
        def _perform_insert():
            conn = None
            try:
                conn = DatabaseOperations.get_connection()
                logger.debug("Opening database transaction")
                with conn:  # starts a transaction; commits on success, rollbacks on exception
                    try:
                        with conn.cursor(cursor_factory=extras.RealDictCursor) as cursor:
                            logger.debug("Transaction started")
                    
                            # Insert/update customer
                            cursor.execute("""
                                INSERT INTO customers (email, name, phone_number, phone_number_validated, privacy_consent)
                                VALUES (%s, %s, %s, %s, %s)
                                ON CONFLICT (email)
                                DO UPDATE SET 
                                    name = EXCLUDED.name,
                                    phone_number = EXCLUDED.phone_number,
                                    phone_number_validated = EXCLUDED.phone_number_validated,
                                    privacy_consent = EXCLUDED.privacy_consent,
                                    created_at = CURRENT_TIMESTAMP
                                RETURNING id
                            """, (
                                survey_data.email,
                                survey_data.name,
                                survey_data.phoneNumber,
                                phone_validated,
                                survey_data.privacyConsent
                            ))
                    
                            customer_id = cursor.fetchone()['id']
                            logger.info(f"Customer ID: {customer_id}")
                            
                            # Insert survey response with all data in JSONB
                            survey_answers = survey_data.dict()
                            cursor.execute("""
                                INSERT INTO survey_responses (customer_id, business_type, survey_answers, submission_id, company_id)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (customer_id, survey_data.businessType, extras.Json(survey_answers), submission_id, company_id))
                            
                            # cursor.execute("COMMIT")
                            # cursor.close()
                            logger.debug("All statements executed successfully — pending commit")
                    except Exception as inner_e:
                        logger.warning("Error inside transaction block — forcing rollback: %s", inner_e)
                        raise  # this triggers automatic rollback by psycopg2

                logger.debug("Transaction committed successfully")
                return customer_id
            
            except Exception as e:
                err_info = {
                    "type": type(e).__name__,
                    "pgcode": getattr(e, "pgcode", None),
                    "pgerror": getattr(e, "pgerror", None),
                }
                diag = getattr(e, "diag", None)
                if diag:
                    err_info.update({
                        "severity": getattr(diag, "severity", None),
                        "sqlstate": getattr(diag, "sqlstate", None),
                        "message_primary": getattr(diag, "message_primary", None),
                        "detail": getattr(diag, "detail", None),
                        "hint": getattr(diag, "hint", None),
                        "schema_name": getattr(diag, "schema_name", None),
                        "table_name": getattr(diag, "table_name", None),
                        "constraint_name": getattr(diag, "constraint_name", None),
                    })
                logger.exception("Database error outside transaction contex: %s", err_info)
                raise
            finally:
                if conn:
                    DatabaseOperations.release_connection(conn)
                    logger.debug("Database connection released")
        
        return DatabaseOperations.retry_operation(_perform_insert, max_retries=3)


# ============================================================================
# DATABASE POOL INITIALIZATION
# ============================================================================

def initialize_db_pool() -> Optional[pool.ThreadedConnectionPool]:
    """Initialize database connection pool"""
    global db_pool
    
    try:
        if db_config.host and db_config.user:
            db_pool = pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                host=db_config.host,
                port=db_config.port,
                database=db_config.database,
                user=db_config.user,
                password=db_config.password
            )
            logger.info("Database connection pool created successfully")
            
            # Test connection
            conn = db_pool.getconn()
            cursor = conn.cursor()
            cursor.execute("SELECT version()")
            version = cursor.fetchone()
            logger.info(f"Connected to PostgreSQL: {version[0]}")
            cursor.close()
            db_pool.putconn(conn)
            
            return db_pool
        else:
            logger.warning("Database credentials not provided, survey endpoint will not be available")
            return None
    except Exception as e:
        logger.error(f"Failed to initialize database pool: {str(e)}")
        return None


def close_db_pool():
    """Close database connection pool"""
    global db_pool
    if db_pool:
        db_pool.closeall()
        logger.info("Database connection pool closed")
        db_pool = None