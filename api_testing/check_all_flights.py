#!/usr/bin/env python3
"""
Check all flight-related endpoints to find available flights and test join functionality
"""

import requests
import json

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def make_request(endpoint, method="GET", data=None):
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    url = f"{PROD_URL}{endpoint}"

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)

        return {
            "status": r.status_code,
            "data": r.json() if r.text and r.status_code == 200 else None,
            "text": r.text
        }
    except Exception as e:
        return {
            "status": None,
            "error": str(e)
        }

print("="*80)
print("COMPREHENSIVE FLIGHT ENDPOINT CHECK")
print("="*80)

# Test all flight-related endpoints
flight_endpoints = [
    ("GET", "/v1/flight/current", "Current/active flights"),
    ("GET", "/v1/flight/available", "Available flights to join"),
    ("GET", "/v1/flight/upcoming", "Upcoming flights"),
    ("GET", "/v1/flight/open", "Open flights"),
    ("GET", "/v1/flight/list", "All flights"),
    ("GET", "/v1/flight/all", "All flights (alt)"),
    ("GET", "/v1/flight-history", "Flight history"),
    ("GET", "/v1/flights", "Flights list (alt)"),
    ("GET", "/v1/flights/available", "Available flights (alt)"),
]

for method, endpoint, description in flight_endpoints:
    print(f"\n{'='*80}")
    print(f"{description}")
    print(f"{method} {endpoint}")
    print(f"{'='*80}")

    r = make_request(endpoint, method)

    if r['status'] == 200:
        data = r['data']

        if isinstance(data, list):
            print(f"✅ SUCCESS - Returned {len(data)} item(s)")

            if len(data) > 0:
                print(f"\nFirst item preview:")
                first = data[0]
                if isinstance(first, dict):
                    print(f"   ID: {first.get('id')}")
                    print(f"   Route: {first.get('origin')} → {first.get('destination')}")
                    print(f"   Status: {first.get('status')}")
                    print(f"   Date: {first.get('departureDate')}")

                    # Check userData for join capability
                    user_data = first.get('userData', {})
                    if user_data:
                        print(f"\n   userData:")
                        print(f"      canJoinWaitlist: {user_data.get('canJoinWaitlist')}")
                        print(f"      isOnWaitlist: {user_data.get('isOnWaitlist')}")

                # Save this for testing
                if len(data) > 0 and endpoint == "/v1/flight/available":
                    print(f"\n   💾 Saving available flights for testing...")
                    with open('/tmp/available_flights.json', 'w') as f:
                        json.dump(data, f, indent=2)
            else:
                print("   (Empty list)")

        elif isinstance(data, dict):
            print(f"✅ SUCCESS - Returned object")
            print(f"   Keys: {list(data.keys())[:10]}")
        else:
            print(f"✅ SUCCESS - {data}")

    elif r['status'] == 404:
        print(f"❌ 404 Not Found")
    elif r['status'] == 401:
        print(f"❌ 401 Unauthorized")
    else:
        print(f"❌ Status {r['status']}")
        if r.get('text'):
            print(f"   Response: {r['text'][:200]}")

# Now test joining a waitlist
print(f"\n{'='*80}")
print("TESTING WAITLIST JOIN FUNCTIONALITY")
print(f"{'='*80}")

# First, find an available flight
r = make_request("/v1/flight/available")
if r['status'] == 200 and r['data'] and len(r['data']) > 0:
    available_flights = r['data']

    print(f"\n✅ Found {len(available_flights)} available flight(s)")

    # Try to join the first one
    test_flight = available_flights[0]
    flight_id = test_flight.get('id')

    print(f"\nAttempting to join Flight {flight_id}:")
    print(f"   Route: {test_flight.get('origin')} → {test_flight.get('destination')}")
    print(f"   Status: {test_flight.get('status')}")

    # Try different join methods
    join_attempts = [
        ("POST", f"/v1/flight/{flight_id}/waitlist", None),
        ("POST", f"/v1/flight/{flight_id}/join", None),
        ("POST", "/v1/flight/join", {"flightId": flight_id}),
        ("POST", "/v1/waitlist/join", {"flightId": flight_id}),
    ]

    for method, endpoint, body in join_attempts:
        print(f"\n   Trying: {method} {endpoint}")
        if body:
            print(f"   Body: {json.dumps(body)}")

        r = make_request(endpoint, method, body)

        if r['status'] == 200:
            print(f"   ✅ SUCCESS!")
            print(f"   Response: {r['text'][:300]}")
        elif r['status'] == 201:
            print(f"   ✅ CREATED!")
            print(f"   Response: {r['text'][:300]}")
        elif r['status'] == 400:
            print(f"   ⚠️  Bad Request")
            print(f"   Error: {r['text'][:200]}")
        elif r['status'] == 404:
            print(f"   ❌ Not Found")
        else:
            print(f"   ❌ Status {r['status']}")

else:
    print("\n❌ No available flights found")
    print("\nThis means:")
    print("1. There are no open flights right now")
    print("2. All flights are closed or full")
    print("3. You need Cabin+ membership to see available flights")

print("\n" + "="*80)
print("RECOMMENDATION")
print("="*80)
print("\nTo test waitlist join/leave functionality:")
print("1. Wait for new flights to open")
print("2. Or check if user 26927 has a valid token to test with that account")
print("3. The removal system can only be tested if you're on a waitlist")
print("\nFor entrant 34740:")
print("- This entrant is from user 26927's account (not Sameer)")
print("- You need user 26927's JWT token to view their waitlist data")
print("\n" + "="*80)
