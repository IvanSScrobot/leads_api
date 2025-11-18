"""
Phone Number Validation Module for Ardent Leads API

This module provides comprehensive phone number validation with Canadian focus,
including detection of premium rate numbers, emergency services, and invalid formats.

Usage:
    from PhoneValidator import PhoneValidator
    
    result = PhoneValidator.validate('+12045551234', user_ip='127.0.0.1')
    if result['validated']:
        # Phone number is valid
        pass
    else:
        # Phone number is invalid
        print(result['reason'])
"""

import logging
import os
import re
from typing import Any, Dict

# Configure logging
logger = logging.getLogger(__name__)


class PhoneValidator:
    """
    Phone number validation with Canadian focus
    
    Validates phone numbers for:
    - Proper length (minimum 10 digits for North American numbers)
    - Premium rate numbers (both area codes and exchanges)
    - Emergency and special service numbers
    - Toll-free numbers
    - Invalid patterns and formats
    
    Supports Canadian area codes and validates against E.164 format.
    """
    
    # Canadian area codes (as of 2024)
    VALID_CANADIAN_AREA_CODES = [
        '403', '587', '780', '825',  # Alberta
        '236', '250', '604', '672', '778',  # British Columbia
        '204', '431',  # Manitoba
        '506',  # New Brunswick
        '709',  # Newfoundland and Labrador
        '867',  # Northwest Territories/Nunavut/Yukon
        '782', '902',  # Nova Scotia/Prince Edward Island
        '226', '249', '289', '343', '365', '416', '437', '519', '548',  # Ontario
        '613', '647', '705', '807', '905',  # Ontario (continued)
        '367', '418', '438', '450', '514', '579', '581', '819', '873',  # Quebec
        '306', '639',  # Saskatchewan
    ]
    
    # Premium rate prefixes (can appear as area code or exchange)
    PREMIUM_PREFIXES = ['900', '976', '540']
    
    # Emergency and special service numbers
    SPECIAL_SERVICE_NUMBERS = [
        '911',  # Emergency
        '999',  # Emergency (international)
        '112',  # Emergency (international)
        '000',  # Emergency (Australia)
        '110',  # Emergency (Asia)
        '411',  # Directory assistance
        '311',  # Municipal services
        '211',  # Community services
        '511',  # Traffic information
        '611',  # Telephone company services
        '711',  # Telecommunications relay service
        '811',  # Health services
    ]
    
    # Toll-free prefixes
    TOLL_FREE_PREFIXES = ['800', '833', '844', '855', '866', '877', '888']
    
    @staticmethod
    def clean_phone_number(phone: str) -> str:
        """
        Remove all non-digit characters except the plus sign
        
        Args:
            phone: Phone number string to clean
            
        Returns:
            Cleaned phone number with only digits and optional leading +
        """
        if not phone or not isinstance(phone, str):
            return ''
        return re.sub(r'[^\d+]', '', phone).strip()
    
    @staticmethod
    def validate(phone: str, user_ip: str = 'unknown') -> Dict[str, Any]:
        """
        Validate phone number with comprehensive checks
        
        Enhanced to match Ardent-Landing-Page validation logic for Canadian numbers.
        Performs multiple validation steps:
        1. Basic format and length checks
        2. Blocked patterns (premium, emergency, etc.)
        3. Premium number detection (area code and exchange levels)
        4. Format validation (E.164 standard)
        
        Args:
            phone: Phone number to validate (preferably in E.164 format)
            user_ip: IP address of the user (for logging/security)
            
        Returns:
            Dictionary with validation result:
            {
                'status': 'approved' | 'rejected',
                'reason': str,
                'risk_level': 'none' | 'low' | 'medium' | 'high',
                'validated': bool,
                'original_number': str,
                'cleaned_number': str,
                'log_security_event': bool,
                'is_canadian': bool (only if validated)
            }
        """
        cleaned = PhoneValidator.clean_phone_number(phone)
        logger.info(f"[PHONE_VALIDATION] Validating: {phone} -> {cleaned}, IP: {user_ip}")
        
        # Step 1: Basic format check - must be at least 10 digits for valid phone
        if not cleaned or len(cleaned) < 10:
            return {
                'status': 'rejected',
                'reason': 'Phone number too short - minimum 10 digits required for valid Canadian/US numbers',
                'risk_level': 'medium',
                'validated': False,
                'original_number': phone,
                'cleaned_number': cleaned,
                'log_security_event': True
            }
        
        # Step 2: Check for numbers that are too long (max 15 digits per E.164)
        if len(cleaned) > 16:  # +1 + 15 digits max
            return {
                'status': 'rejected',
                'reason': 'Phone number too long - exceeds maximum length',
                'risk_level': 'medium',
                'validated': False,
                'original_number': phone,
                'cleaned_number': cleaned,
                'log_security_event': True
            }
        
        # Step 3: Blocked patterns - premium/emergency/special services
        blocked_patterns = [
            # Premium numbers (US/Canada)
            (r'^(\+?1)?900\d{7}$', 'Premium 900 numbers not accepted'),
            (r'^(\+?1)?976\d{7}$', 'Premium 976 numbers not accepted'),
            (r'^(\+?1)?540\d{7}$', 'Premium 540 numbers not accepted'),
            
            # International premium
            (r'^\+90[0-9]\d+$', 'International premium numbers not accepted'),
            
            # Invalid patterns
            (r'^0+$', 'Invalid number - all zeros'),
            (r'^1+$', 'Invalid number - all ones'),
            (r'^\d{1,9}$', 'Phone number too short'),
            (r'^\+?[0]\d+$', 'Invalid number - starts with zero after country code')
        ]
        
        for pattern, message in blocked_patterns:
            if re.match(pattern, cleaned):
                return {
                    'status': 'rejected',
                    'reason': message,
                    'risk_level': 'high',
                    'validated': False,
                    'original_number': phone,
                    'cleaned_number': cleaned,
                    'log_security_event': True
                }
        
        # Step 4: Check for emergency/special service numbers
        for special in PhoneValidator.SPECIAL_SERVICE_NUMBERS:
            if special in cleaned:
                return {
                    'status': 'rejected',
                    'reason': f'Emergency/special service numbers ({special}) not accepted',
                    'risk_level': 'high',
                    'validated': False,
                    'original_number': phone,
                    'cleaned_number': cleaned,
                    'log_security_event': True
                }
        
        # Step 5: Validate US/Canada format - Must be exactly 10 digits (plus optional +1)
        # Pattern: +1NXXNXXXXXX where N=[2-9] and X=[0-9]
        us_canada_pattern = r'^(\+?1)?[2-9]\d{2}[2-9]\d{2}\d{4}$'
        
        if re.match(us_canada_pattern, cleaned):
            # Extract area code and exchange for validation
            if cleaned.startswith('+1'):
                area_code = cleaned[2:5]
                exchange = cleaned[5:8]
            elif cleaned.startswith('1') and len(cleaned) == 11:
                area_code = cleaned[1:4]
                exchange = cleaned[4:7]
            else:
                area_code = cleaned[:3]
                exchange = cleaned[3:6]
            
            # Check toll-free area codes
            if area_code in PhoneValidator.TOLL_FREE_PREFIXES:
                return {
                    'status': 'rejected',
                    'reason': 'Toll-free numbers not accepted - please provide a local business number',
                    'risk_level': 'medium',
                    'validated': False,
                    'original_number': phone,
                    'cleaned_number': cleaned,
                    'log_security_event': False
                }
            
            # Check premium exchanges (middle 3 digits)
            if exchange in PhoneValidator.PREMIUM_PREFIXES:
                return {
                    'status': 'rejected',
                    'reason': f'Premium rate numbers (exchange {exchange}) not accepted',
                    'risk_level': 'high',
                    'validated': False,
                    'original_number': phone,
                    'cleaned_number': cleaned,
                    'log_security_event': True
                }
            
            # Valid Canadian/US number
            is_canadian = area_code in PhoneValidator.VALID_CANADIAN_AREA_CODES
            return {
                'status': 'approved',
                'reason': f'Valid {"Canadian" if is_canadian else "US/Canada"} business number',
                'risk_level': 'none',
                'validated': True,
                'original_number': phone,
                'cleaned_number': cleaned,
                'log_security_event': False,
                'is_canadian': is_canadian
            }
        
        # Step 6: International numbers (if enabled)
        if os.getenv('INTERNATIONAL_NUMBERS_ALLOWED', 'false').lower() == 'true':
            # International format: +[1-9]... (7-14 digits after country code)
            if re.match(r'^\+(?!90[0-9])[1-9]\d{6,14}$', cleaned):
                return {
                    'status': 'approved',
                    'reason': 'Valid international number',
                    'risk_level': 'none',
                    'validated': True,
                    'original_number': phone,
                    'cleaned_number': cleaned,
                    'log_security_event': False
                }
        
        # Step 7: Default rejection
        return {
            'status': 'rejected',
            'reason': 'Invalid phone number format - must be a valid Canadian or US number in E.164 format (e.g., +12045551234)',
            'risk_level': 'medium',
            'validated': False,
            'original_number': phone,
            'cleaned_number': cleaned,
            'log_security_event': True
        }