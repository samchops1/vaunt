#!/usr/bin/env python3
"""
Priority Score V2 Testing - Does v2 API affect priority score?
"""

import requests
import json
import time
from datetime import datetime

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def get_priority_score():
    """Get current priority score"""
    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}
    try:
        r = requests.get(f"{API_URL}/v1/user", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return data.get('priorityScore')
    except Exception as e:
        print(f"Error getting priority score: {e}")
    return None

def get_current_flights_v2():
    """Get current flights using v2 API"""
    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}
    try:
        r = requests.get(f"{API_URL}/v2/flight/current", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"Error getting flights: {e}")
    return []

def join_flight_v2(flight_id):
    """Join flight using v2 API"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
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

def reset_flight_v2(flight_id):
    """Leave flight using v2 API"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
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

def get_available_flights_v3():
    """Get available flights from v3 API"""
    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}
    try:
        r = requests.get(
            f"{API_URL}/v3/flight?includeExpired=false&nearMe=false",
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            response = r.json()
            # v3 API returns {data: [...], availableCount: N, nearMeCount: N}
            if isinstance(response, dict) and 'data' in response:
                return response['data']
            return response
    except Exception as e:
        print(f"Error getting available flights: {e}")
    return []

def main():
    print("="*80)
    print("PRIORITY SCORE V2 TESTING")
    print("="*80)
    print()

    # Step 1: Get baseline priority score
    print("Step 1: Getting baseline priority score...")
    baseline_score = get_priority_score()
    if not baseline_score:
        print("❌ Failed to get baseline priority score")
        return

    print(f"✅ Baseline Priority Score: {baseline_score}")
    print(f"   Date equivalent: {datetime.fromtimestamp(baseline_score).strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Step 2: Get current flights
    print("Step 2: Getting current flights...")
    current_flights = get_current_flights_v2()
    print(f"   Currently on {len(current_flights)} flight(s)")

    if current_flights:
        print("   Current flights:")
        for f in current_flights:
            print(f"     - Flight {f.get('id')}: {f.get('origin', {}).get('code')} → {f.get('destination', {}).get('code')}")
    print()

    # Step 3: Get available flights for testing
    print("Step 3: Finding available flights...")
    available_flights = get_available_flights_v3()

    if not available_flights:
        print("❌ No available flights to test with")
        print("   Cannot proceed with join/reset testing")
        return

    print(f"✅ Found {len(available_flights)} available flight(s)")

    # Find a flight we're not already on
    test_flight = None
    current_flight_ids = [f.get('id') for f in current_flights]

    for flight in available_flights:
        if flight.get('id') not in current_flight_ids:
            test_flight = flight
            break

    if not test_flight:
        print("⚠️  Already on all available flights")
        # Use an existing flight for reset testing only
        if current_flights:
            test_flight = current_flights[0]
            print(f"   Will test reset only with Flight {test_flight.get('id')}")
            test_mode = "reset_only"
        else:
            print("❌ No flights available for testing")
            return
    else:
        print(f"✅ Using Flight {test_flight.get('id')} for testing")
        print(f"   Route: {test_flight.get('origin', {}).get('code')} → {test_flight.get('destination', {}).get('code')}")
        test_mode = "full"

    flight_id = test_flight.get('id')
    print()

    # Step 4: Join flight (if not already on it)
    if test_mode == "full":
        print("Step 4: Joining flight using v2/enter...")
        status, response = join_flight_v2(flight_id)

        if status == 200:
            print(f"✅ Successfully joined flight {flight_id}")
        else:
            print(f"❌ Failed to join flight: Status {status}")
            print(f"   Response: {response[:200]}")
            return

        time.sleep(1)  # Wait a moment

        # Step 5: Check priority score after join
        print()
        print("Step 5: Checking priority score after join...")
        after_join_score = get_priority_score()

        if not after_join_score:
            print("❌ Failed to get priority score after join")
            return

        print(f"   Priority Score: {after_join_score}")

        if after_join_score == baseline_score:
            print("✅ Priority score UNCHANGED after join")
            print(f"   Still: {after_join_score}")
        else:
            print("⚠️  Priority score CHANGED after join")
            print(f"   Before: {baseline_score}")
            print(f"   After:  {after_join_score}")
            print(f"   Diff:   {after_join_score - baseline_score:+,}")

        print()
    else:
        after_join_score = baseline_score
        print("Step 4-5: Skipped join test (already on flight)")
        print()

    # Step 6: Leave flight using v2/reset
    print(f"Step 6: Leaving flight {flight_id} using v2/reset...")
    status, response = reset_flight_v2(flight_id)

    if status == 200:
        print(f"✅ Successfully left flight {flight_id}")
    else:
        print(f"❌ Failed to leave flight: Status {status}")
        print(f"   Response: {response[:200]}")
        return

    time.sleep(1)  # Wait a moment

    # Step 7: Check priority score after reset
    print()
    print("Step 7: Checking priority score after reset...")
    after_reset_score = get_priority_score()

    if not after_reset_score:
        print("❌ Failed to get priority score after reset")
        return

    print(f"   Priority Score: {after_reset_score}")

    if after_reset_score == baseline_score:
        print("✅ Priority score UNCHANGED after reset")
        print(f"   Still: {after_reset_score}")
    else:
        print("⚠️  Priority score CHANGED after reset")
        print(f"   Before: {baseline_score}")
        print(f"   After:  {after_reset_score}")
        print(f"   Diff:   {after_reset_score - baseline_score:+,}")

    print()
    print("="*80)
    print("CONCLUSION")
    print("="*80)

    # Final analysis
    if test_mode == "full":
        if baseline_score == after_join_score == after_reset_score:
            print("✅ Priority score remained CONSTANT throughout testing")
            print("   V2 join/reset operations do NOT affect priority score")
        else:
            print("⚠️  Priority score CHANGED during testing")
            if baseline_score != after_join_score:
                print(f"   - Changed after join: {after_join_score - baseline_score:+,}")
            if after_join_score != after_reset_score:
                print(f"   - Changed after reset: {after_reset_score - after_join_score:+,}")
            print("   V2 operations MAY affect priority score - needs investigation")
    else:
        if baseline_score == after_reset_score:
            print("✅ Priority score UNCHANGED after v2 reset")
            print("   V2 reset operation does NOT affect priority score")
        else:
            print("⚠️  Priority score CHANGED after v2 reset")
            print(f"   Diff: {after_reset_score - baseline_score:+,}")
            print("   V2 reset MAY affect priority score - needs investigation")

    print()
    print("="*80)
    print("COMPARISON WITH V1 BEHAVIOR")
    print("="*80)
    print()
    print("From previous testing (PRIORITY_SCORE_FINAL_ANSWER.md):")
    print("  - V1 API testing showed priority scores are static timestamps")
    print("  - Scores based on subscription tier (Cabin+ gets future date)")
    print("  - No evidence v1 operations affected priority scores")
    print()
    print("V2 API finding:")
    if baseline_score == after_reset_score:
        print("  ✅ V2 behaves same as v1 - priority score remains constant")
    else:
        print("  ⚠️  V2 may behave differently - score changed during testing")

    print()
    print("="*80)

if __name__ == "__main__":
    main()
