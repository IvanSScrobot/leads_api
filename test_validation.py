"""
Test script for phone and email validation in leads_api
Tests the enhanced validation logic to ensure invalid numbers and emails are rejected
"""

import sys
import os

# Add the leads_api directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db import PhoneValidator
from main import SurveyRequest
from pydantic import ValidationError

def test_phone_validation():
    """Test phone number validation"""
    print("=" * 80)
    print("TESTING PHONE NUMBER VALIDATION")
    print("=" * 80)
    
    test_cases = [
        # Valid Canadian numbers
        ('+12045551234', True, 'Valid Winnipeg number'),
        ('+14165551234', True, 'Valid Toronto number'),
        ('+16045551234', True, 'Valid Vancouver number'),
        ('+15145551234', True, 'Valid Montreal number'),
        
        # Invalid: Too short
        ('+17741231', False, 'Too short - only 7 digits'),
        ('+1774123', False, 'Too short - only 6 digits'),
        ('+177', False, 'Too short - only 2 digits'),
        ('123', False, 'Way too short'),
        
        # Invalid: Premium numbers
        ('+19005551234', False, 'Premium 900 number'),
        ('+19765551234', False, 'Premium 976 number'),
        ('+15405551234', False, 'Premium 540 number'),
        
        # Invalid: Emergency numbers
        ('911', False, 'Emergency number'),
        ('411', False, 'Directory assistance'),
        ('811', False, 'Health services'),
        
        # Invalid: Toll-free
        ('+18005551234', False, 'Toll-free 800 number'),
        ('+18885551234', False, 'Toll-free 888 number'),
        
        # Invalid: All zeros/ones
        ('0000000000', False, 'All zeros'),
        ('1111111111', False, 'All ones'),
        
        # Invalid: Starts with 0
        ('+10555551234', False, 'Starts with 0 after country code'),
        
        # Invalid: Too long
        ('+123456789012345678', False, 'Too long'),
        
        # Edge cases
        ('', False, 'Empty string'),
        ('+1234567890123456', False, 'Too long by 1 digit'),
    ]
    
    passed = 0
    failed = 0
    
    for phone, should_be_valid, description in test_cases:
        result = PhoneValidator.validate(phone, '127.0.0.1')
        is_valid = result['validated']
        
        if is_valid == should_be_valid:
            print(f"✅ PASS: {description}")
            print(f"   Phone: '{phone}' -> {result['status']} ({result['reason']})")
            passed += 1
        else:
            print(f"❌ FAIL: {description}")
            print(f"   Phone: '{phone}' -> Expected: {'valid' if should_be_valid else 'invalid'}, Got: {'valid' if is_valid else 'invalid'}")
            print(f"   Result: {result['status']} ({result['reason']})")
            failed += 1
        print()
    
    print(f"\n{'='*80}")
    print(f"Phone Validation Results: {passed} passed, {failed} failed")
    print(f"{'='*80}\n")
    
    return failed == 0


def test_email_validation():
    """Test email validation in SurveyRequest model"""
    print("=" * 80)
    print("TESTING EMAIL VALIDATION")
    print("=" * 80)
    
    test_cases = [
        # Valid emails
        ('user@example.com', True, 'Standard email'),
        ('john.doe@company.co.uk', True, 'Email with dot in name'),
        ('test+tag@domain.com', True, 'Email with plus sign'),
        ('user123@test-domain.com', True, 'Email with numbers and dash in domain'),
        
        # Invalid: Disposable domains
        ('test@tempmail.com', False, 'Disposable domain - tempmail.com'),
        ('user@mailinator.com', False, 'Disposable domain - mailinator.com'),
        ('test@10minutemail.com', False, 'Disposable domain - 10minutemail.com'),
        
        # Invalid: Format issues
        ('.user@example.com', False, 'Starts with period'),
        ('user.@example.com', False, 'Ends with period before @'),
        ('user..name@example.com', False, 'Consecutive periods'),
        ('user@domain', False, 'Missing domain extension'),
        ('user@domain.c', False, 'Single character domain extension'),
        ('@example.com', False, 'Missing local part'),
        ('user@', False, 'Missing domain'),
        ('', False, 'Empty email'),
        
        # Invalid: Bad format
        ('not-an-email', False, 'No @ sign'),
        ('user @example.com', False, 'Space in email'),
    ]
    
    passed = 0
    failed = 0
    
    # Create base valid data
    base_data = {
        'name': 'Test User',
        'businessName': 'Test Business',
        'email': 'valid@example.com',  # Will be replaced
        'phoneNumber': '+12045551234',
        'privacyConsent': True,
        'consentToUseAI': True
    }
    
    for email, should_be_valid, description in test_cases:
        test_data = base_data.copy()
        test_data['email'] = email
        
        try:
            survey = SurveyRequest(**test_data)
            is_valid = True
            error_msg = None
        except ValidationError as e:
            is_valid = False
            error_msg = str(e.errors()[0]['msg']) if e.errors() else 'Validation error'
        except Exception as e:
            is_valid = False
            error_msg = str(e)
        
        if is_valid == should_be_valid:
            print(f"✅ PASS: {description}")
            print(f"   Email: '{email}' -> {'Valid' if is_valid else f'Invalid ({error_msg})'}")
            passed += 1
        else:
            print(f"❌ FAIL: {description}")
            print(f"   Email: '{email}' -> Expected: {'valid' if should_be_valid else 'invalid'}, Got: {'valid' if is_valid else 'invalid'}")
            if error_msg:
                print(f"   Error: {error_msg}")
            failed += 1
        print()
    
    print(f"\n{'='*80}")
    print(f"Email Validation Results: {passed} passed, {failed} failed")
    print(f"{'='*80}\n")
    
    return failed == 0


def test_integration():
    """Test that invalid data is rejected by SurveyRequest model"""
    print("=" * 80)
    print("TESTING INTEGRATION - SurveyRequest Model")
    print("=" * 80)
    
    # Test: Invalid phone should be rejected
    print("\n1. Testing invalid phone number rejection...")
    try:
        survey = SurveyRequest(
            name='Test User',
            businessName='Test Business',
            email='valid@example.com',
            phoneNumber='+17741231',  # Too short
            privacyConsent=True,
            consentToUseAI=True
        )
        print("❌ FAIL: Invalid phone was accepted (should have been rejected)")
        phone_test_passed = False
    except ValidationError as e:
        print(f"✅ PASS: Invalid phone correctly rejected")
        print(f"   Error: {e.errors()[0]['msg']}")
        phone_test_passed = True
    
    # Test: Invalid email should be rejected
    print("\n2. Testing invalid email rejection...")
    try:
        survey = SurveyRequest(
            name='Test User',
            businessName='Test Business',
            email='test@tempmail.com',  # Disposable
            phoneNumber='+12045551234',
            privacyConsent=True,
            consentToUseAI=True
        )
        print("❌ FAIL: Invalid email was accepted (should have been rejected)")
        email_test_passed = False
    except ValidationError as e:
        print(f"✅ PASS: Invalid email correctly rejected")
        print(f"   Error: {e.errors()[0]['msg']}")
        email_test_passed = True
    
    # Test: Valid data should be accepted
    print("\n3. Testing valid data acceptance...")
    try:
        survey = SurveyRequest(
            name='Test User',
            businessName='Test Business',
            email='valid@example.com',
            phoneNumber='+12045551234',
            privacyConsent=True,
            consentToUseAI=True
        )
        print(f"✅ PASS: Valid data correctly accepted")
        print(f"   Email: {survey.email}, Phone: {survey.phoneNumber}")
        valid_test_passed = True
    except Exception as e:
        print(f"❌ FAIL: Valid data was rejected")
        print(f"   Error: {str(e)}")
        valid_test_passed = False
    
    print(f"\n{'='*80}")
    print(f"Integration Test Results: {'All Passed' if all([phone_test_passed, email_test_passed, valid_test_passed]) else 'Some Failed'}")
    print(f"{'='*80}\n")
    
    return all([phone_test_passed, email_test_passed, valid_test_passed])


if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("LEADS_API VALIDATION TEST SUITE")
    print("=" * 80 + "\n")
    
    phone_ok = test_phone_validation()
    email_ok = test_email_validation()
    integration_ok = test_integration()
    
    print("\n" + "=" * 80)
    print("FINAL RESULTS")
    print("=" * 80)
    print(f"Phone Validation: {'✅ PASSED' if phone_ok else '❌ FAILED'}")
    print(f"Email Validation: {'✅ PASSED' if email_ok else '❌ FAILED'}")
    print(f"Integration Tests: {'✅ PASSED' if integration_ok else '❌ FAILED'}")
    print("=" * 80)
    
    if all([phone_ok, email_ok, integration_ok]):
        print("\n🎉 ALL TESTS PASSED!")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED!")
        sys.exit(1)