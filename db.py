"""
Database configuration and operations for Ardent Survey API
"""

import logging
import os
import time
from typing import Any, Dict, Optional

import psycopg2
from psycopg2 import pool, extras, Error

# Import PhoneValidator from dedicated module
from PhoneValidator import PhoneValidator

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
    
    @staticmethod
    def get_lead_status(company_id: str, submission_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve call_summary and processed status from survey_responses table
        
        Args:
            company_id: Company identifier
            submission_id: Unique submission identifier
        
        Returns:
            Dictionary with call_summary and processed status, or None if not found
        """
        def _perform_query():
            conn = None
            try:
                conn = DatabaseOperations.get_connection()
                with conn.cursor(cursor_factory=extras.RealDictCursor) as cursor:
                    cursor.execute("""
                        SELECT call_summary, processed
                        FROM survey_responses
                        WHERE company_id = %s AND submission_id = %s
                    """, (company_id, submission_id))
                    
                    result = cursor.fetchone()
                    if result:
                        return dict(result)
                    return None
            
            finally:
                if conn:
                    DatabaseOperations.release_connection(conn)
        
        return DatabaseOperations.retry_operation(_perform_query, max_retries=3)
    
    @staticmethod
    def get_api_key_by_public_key(public_key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve API key information by public key with company validation
        
        Args:
            public_key: Public key identifier
        
        Returns:
            Dictionary with api_key and company info, or None if not found/invalid
            Returns: {
                'api_key_id': int,
                'public_key': str,
                'secret_key': str,
                'api_key_active': bool,
                'api_key_expires_at': datetime or None,
                'company_id': int,
                'company_name': str,
                'company_active': bool
            }
        """
        def _perform_query():
            conn = None
            try:
                conn = DatabaseOperations.get_connection()
                with conn.cursor(cursor_factory=extras.RealDictCursor) as cursor:
                    cursor.execute("""
                        SELECT
                            ak.id as api_key_id,
                            ak.public_key,
                            ak.secret_key,
                            ak.active as api_key_active,
                            ak.expires_at as api_key_expires_at,
                            c.id as company_id,
                            c.name as company_name,
                            c.active as company_active
                        FROM api_keys ak
                        INNER JOIN companies c ON ak.company_id = c.id
                        WHERE ak.public_key = %s
                    """, (public_key,))
                    
                    result = cursor.fetchone()
                    if result:
                        return dict(result)
                    return None
            
            finally:
                if conn:
                    DatabaseOperations.release_connection(conn)
        
        return DatabaseOperations.retry_operation(_perform_query, max_retries=3)
    
    @staticmethod
    def update_api_key_last_used(api_key_id: int) -> bool:
        """
        Update the last_used_at timestamp for an API key
        
        Args:
            api_key_id: API key ID
        
        Returns:
            True if successful, False otherwise
        """
        def _perform_update():
            conn = None
            try:
                conn = DatabaseOperations.get_connection()
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE api_keys
                        SET last_used_at = CURRENT_TIMESTAMP
                        WHERE id = %s
                    """, (api_key_id,))
                    conn.commit()
                    return True
            
            except Exception as e:
                logger.error(f"Failed to update last_used_at for api_key_id={api_key_id}: {str(e)}")
                if conn:
                    conn.rollback()
                return False
            
            finally:
                if conn:
                    DatabaseOperations.release_connection(conn)
        
        return DatabaseOperations.retry_operation(_perform_update, max_retries=2)


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