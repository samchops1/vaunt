#!/usr/bin/env python3
"""
Test the endpoint captured from mobile app interception.

Once you capture the "leave waitlist" call from the mobile app,
update the variables below and run this script to verify it works.
"""

import requests
import json
import time

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

# ========================================
# UPDATE THESE FROM YOUR CAPTURED REQUEST
# ========================================

# What HTTP method did the app use? (POST, DELETE, PUT, PATCH)
CAPTURED_METHOD = "POST"  # <-- UPDATE THIS

# What was the endpoint path? (e.g., "/v1/flight/{id}/leave")
# Use {id} as placeholder for flight ID
CAPTURED_ENDPOINT = "/v1/flight/{id}/cancel"  # <-- UPDATE THIS

# What was in the request body? (None if empty, or dict with data)
CAPTURED_BODY = None  # <-- UPDATE THIS
# Examples:
# CAPTURED_BODY = None  # No body
# CAPTURED_BODY = {}  # Empty object
# CAPTURED_BODY = {"reason": "user_requested"}  # With data

# Were there any special headers? (besides Authorization and Content-Type)
CAPTURED_HEADERS = {}  # <-- UPDATE THIS IF NEEDED
# Example:
# CAPTURED_HEADERS = {"X-API-Version": "1.0", "X-Client": "mobile-app"}

# ========================================

def make_request(method, endpoint, flight_id, body=None, extra_headers=None):
    """Make the captured request"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    # Add any captured special headers
    if extra_headers:
        headers.update(extra_headers)

    # Replace {id} with actual flight ID
    url = f"{API_URL}{endpoint.replace('{id}', str(flight_id))}"

    print(f"{method} {url}")
    if body:
        print(f"Body: {json.dumps(body, indent=2)}")
    if extra_headers:
        print(f"Extra headers: {extra_headers}")

    try:
        if method.upper() == "POST":
            r = requests.post(url, headers=headers, json=body, timeout=10)
        elif method.upper() == "DELETE":
            r = requests.delete(url, headers=headers, timeout=10)
        elif method.upper() == "PUT":
            r = requests.put(url, headers=headers, json=body, timeout=10)
        elif method.upper() == "PATCH":
            r = requests.patch(url, headers=headers, json=body, timeout=10)
        else:
            print(f"❌ Unsupported method: {method}")
            return None

        return {
            "status": r.status_code,
            "text": r.text,
            "ok": r.ok
        }
    except Exception as e:
        return {
            "status": "error",
            "text": str(e),
            "ok": False
        }

def get_current_flights():
    """Get current flights Sameer is on"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}"
    }

    r = requests.get(f"{API_URL}/v1/flight/current", headers=headers, timeout=10)

    if r.status_code == 200:
        return r.json()
    return []

def main():
    print("="*80)
    print("TESTING CAPTURED ENDPOINT")
    print("="*80)

    print(f"\nMethod: {CAPTURED_METHOD}")
    print(f"Endpoint: {CAPTURED_ENDPOINT}")
    print(f"Body: {CAPTURED_BODY}")
    print(f"Extra Headers: {CAPTURED_HEADERS}")

    # Get current flights
    print("\n" + "="*80)
    print("STEP 1: Check current flights")
    print("="*80)

    flights = get_current_flights()
    print(f"\nSameer is currently on {len(flights)} flight(s):")

    if not flights:
        print("❌ Not on any flights! Join a flight first.")
        return

    for flight in flights:
        flight_id = flight.get('id')
        status = flight.get('status', {}).get('label', 'UNKNOWN')
        origin = flight.get('departAirport', {}).get('code', '???')
        dest = flight.get('arriveAirport', {}).get('code', '???')

        print(f"  - Flight {flight_id}: {origin} → {dest} (Status: {status})")

    # Test on first flight
    test_flight = flights[0]
    flight_id = test_flight.get('id')
    status = test_flight.get('status', {}).get('label', 'UNKNOWN')

    print("\n" + "="*80)
    print(f"STEP 2: Test removal on Flight {flight_id}")
    print("="*80)

    print(f"\nTarget Flight:")
    print(f"  ID: {flight_id}")
    print(f"  Status: {status}")
    print(f"  Route: {test_flight.get('departAirport', {}).get('code')} → {test_flight.get('arriveAirport', {}).get('code')}")

    if status == "PENDING":
        print(f"  ✅ PERFECT! This is a PENDING flight - exactly what we need to test!")
    else:
        print(f"  ⚠️  Flight is {status} (not PENDING)")

    # Make the captured request
    print(f"\n📡 Making captured request...")
    result = make_request(
        CAPTURED_METHOD,
        CAPTURED_ENDPOINT,
        flight_id,
        CAPTURED_BODY,
        CAPTURED_HEADERS
    )

    if not result:
        print("❌ Request failed")
        return

    print(f"\n📥 Response:")
    print(f"  Status: {result['status']}")
    print(f"  Text: {result['text'][:200]}")

    if result['ok']:
        print("\n✅ Request succeeded!")
    else:
        print(f"\n❌ Request failed with status {result['status']}")

        if result['status'] == 404:
            print("  → Endpoint not found")
        elif result['status'] == 400:
            print("  → Bad request (check if endpoint requires different parameters)")
        elif result['status'] == 403:
            print("  → Forbidden (check authorization)")

        return

    # Verify removal
    print("\n" + "="*80)
    print("STEP 3: Verify removal")
    print("="*80)

    print("\nWaiting 1 second...")
    time.sleep(1)

    flights_after = get_current_flights()
    print(f"\nSameer is now on {len(flights_after)} flight(s)")

    # Check if test flight is gone
    still_on_flight = any(f.get('id') == flight_id for f in flights_after)

    if still_on_flight:
        print(f"\n❌ Still on Flight {flight_id}")
        print("  The request succeeded but didn't remove from flight.")
        print("  This might mean:")
        print("  - The endpoint requires different parameters")
        print("  - The endpoint does something else")
        print("  - There's a delay before removal takes effect")
    else:
        print(f"\n✅✅✅ SUCCESS! Removed from Flight {flight_id}!")
        print(f"\n🎉 FOUND IT! This is the working endpoint!")
        print(f"\n📋 Working Endpoint:")
        print(f"   Method: {CAPTURED_METHOD}")
        print(f"   URL: {CAPTURED_ENDPOINT}")
        if CAPTURED_BODY:
            print(f"   Body: {json.dumps(CAPTURED_BODY)}")
        if CAPTURED_HEADERS:
            print(f"   Headers: {CAPTURED_HEADERS}")

        # Test if it works on PENDING flights
        if status == "PENDING":
            print(f"\n✅ CONFIRMED: Works on PENDING flights!")
            print("   This solves our problem!")
        else:
            print(f"\n⚠️  Flight was {status} (not PENDING)")
            print("   Need to test on a PENDING flight to confirm")

    print("\n" + "="*80)

if __name__ == "__main__":
    main()
