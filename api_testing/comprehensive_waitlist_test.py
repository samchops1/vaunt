#!/usr/bin/env python3
"""
Comprehensive Waitlist Testing:
1. Search for entrant 34740 in Sameer's data
2. Test waitlist removal/leave functionality
3. Debug why add to waitlist is not working
"""

import requests
import json
from datetime import datetime

PROD_URL = "https://vauntapi.flyvaunt.com"
QA_URL = "https://qa-vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

TARGET_ENTRANT_ID = 34740

def make_request(base_url, method, endpoint, data=None):
    """Make API request"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    url = f"{base_url}{endpoint}"

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=data, timeout=10)

        return {
            "status": r.status_code,
            "data": r.json() if r.text and r.status_code == 200 else None,
            "text": r.text,
            "headers": dict(r.headers)
        }
    except Exception as e:
        return {
            "status": None,
            "error": str(e)
        }

def search_for_entrant(base_url, entrant_id):
    """Search for entrant ID in all available data"""
    print(f"\n{'='*80}")
    print(f"SEARCHING FOR ENTRANT {entrant_id}")
    print(f"{'='*80}")

    found = False

    # Check user profile
    print("\n1. Checking user profile...")
    r = make_request(base_url, "GET", "/v1/user")
    if r['status'] == 200:
        user_data = r['data']
        user_json = json.dumps(user_data)
        if str(entrant_id) in user_json:
            print(f"✅ Found entrant {entrant_id} in user data!")
            found = True
            # Find where it appears
            if 'waitlistUpgrades' in user_data and user_data['waitlistUpgrades']:
                print("\n   Found in waitlistUpgrades:")
                print(json.dumps(user_data['waitlistUpgrades'], indent=2))

    # Check current flights
    print("\n2. Checking current flights...")
    r = make_request(base_url, "GET", "/v1/flight/current")
    if r['status'] == 200:
        flights = r['data']
        for flight in flights:
            flight_json = json.dumps(flight)
            if str(entrant_id) in flight_json:
                print(f"✅ Found entrant {entrant_id} in flight {flight.get('id')}!")
                found = True

                # Show entrant details
                entrants = flight.get('entrants', [])
                for entrant in entrants:
                    if entrant.get('id') == entrant_id:
                        print("\n   Entrant details:")
                        print(json.dumps(entrant, indent=2))

    # Check flight history
    print("\n3. Checking flight history...")
    r = make_request(base_url, "GET", "/v1/flight-history")
    if r['status'] == 200:
        history = r['data']
        history_json = json.dumps(history)
        if str(entrant_id) in history_json:
            print(f"✅ Found entrant {entrant_id} in flight history!")
            found = True

    if not found:
        print(f"\n❌ Entrant {entrant_id} not found in any Sameer data")
        print("   This entrant may be from a different user account")

    return found

def test_waitlist_removal(base_url):
    """Test waitlist removal/leave functionality"""
    print(f"\n{'='*80}")
    print("TESTING WAITLIST REMOVAL SYSTEM")
    print(f"{'='*80}")

    # Get current flights to find waitlisted flights
    print("\n1. Getting current waitlisted flights...")
    r = make_request(base_url, "GET", "/v1/flight/current")

    if r['status'] != 200:
        print("❌ Could not get current flights")
        return

    flights = r['data']
    waitlisted_flights = []

    for flight in flights:
        user_data = flight.get('userData', {})
        if user_data.get('isOnWaitlist') and not user_data.get('isWinner'):
            waitlisted_flights.append({
                'id': flight.get('id'),
                'route': f"{flight.get('origin')} → {flight.get('destination')}",
                'date': flight.get('departureDate'),
                'position': user_data.get('queuePosition')
            })

    if not waitlisted_flights:
        print("❌ No active waitlist entries found")
        print("\n   You're not on any waitlists currently")
        return

    print(f"\n✅ Found {len(waitlisted_flights)} waitlisted flight(s):")
    for wf in waitlisted_flights:
        print(f"   - Flight {wf['id']}: {wf['route']} (Position: #{wf['position']})")

    # Test removal on first waitlisted flight
    test_flight = waitlisted_flights[0]
    flight_id = test_flight['id']

    print(f"\n2. Testing removal endpoints on Flight {flight_id}...")

    removal_methods = [
        ("DELETE", f"/v1/flight/{flight_id}/waitlist", None, "Delete from waitlist"),
        ("POST", f"/v1/flight/{flight_id}/waitlist/leave", None, "Leave waitlist (POST)"),
        ("POST", f"/v1/flight/{flight_id}/leave", None, "Leave flight"),
        ("DELETE", f"/v1/waitlist/{flight_id}", None, "Delete waitlist entry"),
        ("POST", f"/v1/waitlist/leave", {"flightId": flight_id}, "Leave via body param"),
    ]

    for method, endpoint, data, description in removal_methods:
        print(f"\n   Testing: {method} {endpoint}")
        r = make_request(base_url, method, endpoint, data)

        if r['status'] == 200:
            print(f"   ✅ {description} - SUCCESS!")
            print(f"   Response: {r['text'][:200]}")

            # Check if actually removed
            check = make_request(base_url, "GET", "/v1/flight/current")
            if check['status'] == 200:
                still_on = False
                for f in check['data']:
                    if f.get('id') == flight_id:
                        if f.get('userData', {}).get('isOnWaitlist'):
                            still_on = True

                if still_on:
                    print(f"   ⚠️  Still on waitlist (removal didn't work)")
                else:
                    print(f"   🎉 CONFIRMED - Successfully removed from waitlist!")
                    return  # Stop testing once we find working method

        elif r['status'] == 404:
            print(f"   ❌ {description} - Endpoint not found")
        elif r['status'] == 400:
            print(f"   ⚠️  {description} - Bad Request: {r['text'][:100]}")
        else:
            print(f"   ❌ {description} - Status {r['status']}")

def test_waitlist_join(base_url):
    """Debug why add to waitlist is not working"""
    print(f"\n{'='*80}")
    print("DEBUGGING WAITLIST JOIN/ADD FUNCTIONALITY")
    print(f"{'='*80}")

    # Get available flights
    print("\n1. Getting available flights...")
    r = make_request(base_url, "GET", "/v1/flight/current")

    if r['status'] != 200:
        print("❌ Could not get flights")
        return

    flights = r['data']

    # Find a flight we're NOT on
    not_on_waitlist = []
    for flight in flights:
        user_data = flight.get('userData', {})
        if not user_data.get('isOnWaitlist'):
            not_on_waitlist.append({
                'id': flight.get('id'),
                'route': f"{flight.get('origin')} → {flight.get('destination')}",
                'status': flight.get('status'),
                'canJoinWaitlist': user_data.get('canJoinWaitlist', False),
                'userData': user_data
            })

    if not not_on_waitlist:
        print("❌ Already on all available flight waitlists")
        return

    print(f"\n✅ Found {len(not_on_waitlist)} flight(s) not on waitlist:")
    for f in not_on_waitlist[:3]:  # Show first 3
        print(f"   - Flight {f['id']}: {f['route']}")
        print(f"     Status: {f['status']}")
        print(f"     canJoinWaitlist: {f['canJoinWaitlist']}")

    # Test join on first available
    test_flight = not_on_waitlist[0]
    flight_id = test_flight['id']

    print(f"\n2. Testing JOIN methods on Flight {flight_id}...")
    print(f"   Route: {test_flight['route']}")
    print(f"   Flight Status: {test_flight['status']}")

    join_methods = [
        ("POST", f"/v1/flight/{flight_id}/waitlist", None, "Add to waitlist"),
        ("POST", f"/v1/flight/{flight_id}/join", None, "Join flight"),
        ("POST", "/v1/waitlist/join", {"flightId": flight_id}, "Join via body param"),
        ("POST", "/v1/waitlist", {"flightId": flight_id}, "Create waitlist entry"),
        ("POST", f"/v1/flight/{flight_id}/enter", None, "Enter waitlist"),
        ("PUT", f"/v1/flight/{flight_id}/waitlist", None, "Put to waitlist"),
    ]

    for method, endpoint, data, description in join_methods:
        print(f"\n   Testing: {method} {endpoint}")
        if data:
            print(f"   Body: {json.dumps(data)}")

        r = make_request(base_url, method, endpoint, data)

        if r['status'] == 200:
            print(f"   ✅ {description} - SUCCESS!")
            print(f"   Response: {r['text'][:200]}")

            # Check if actually added
            check = make_request(base_url, "GET", "/v1/flight/current")
            if check['status'] == 200:
                added = False
                for f in check['data']:
                    if f.get('id') == flight_id:
                        if f.get('userData', {}).get('isOnWaitlist'):
                            added = True
                            position = f.get('userData', {}).get('queuePosition')
                            print(f"   🎉 CONFIRMED - Added to waitlist at position #{position}")
                            return  # Success!

                if not added:
                    print(f"   ⚠️  Not on waitlist yet (join didn't work)")

        elif r['status'] == 201:
            print(f"   ✅ {description} - CREATED!")
            print(f"   Response: {r['text'][:200]}")
        elif r['status'] == 404:
            print(f"   ❌ {description} - Endpoint not found")
        elif r['status'] == 400:
            error_msg = r['text'][:200]
            print(f"   ⚠️  {description} - Bad Request")
            print(f"   Error: {error_msg}")

            # Parse common errors
            if 'closed' in error_msg.lower():
                print(f"   → Flight is closed to new entrants")
            elif 'full' in error_msg.lower():
                print(f"   → Waitlist is full")
            elif 'already' in error_msg.lower():
                print(f"   → Already on waitlist")
        else:
            print(f"   ❌ {description} - Status {r['status']}: {r['text'][:100]}")

    print("\n3. Analyzing userData flags...")
    print(f"   canJoinWaitlist: {test_flight['canJoinWaitlist']}")

    if not test_flight['canJoinWaitlist']:
        print("\n   ⚠️  REASON: canJoinWaitlist is FALSE")
        print("   Possible reasons:")
        print("   - Flight is closed")
        print("   - Waitlist is full")
        print("   - User doesn't meet requirements")
        print("   - Flight has already departed")

        # Show full userData
        print(f"\n   Full userData:")
        print(json.dumps(test_flight['userData'], indent=2))

def main():
    print("="*80)
    print("COMPREHENSIVE WAITLIST TESTING")
    print("="*80)
    print(f"Target Entrant ID: {TARGET_ENTRANT_ID}")

    # Use production API
    base_url = PROD_URL
    print(f"API: {base_url}")

    # Part 1: Search for entrant 34740
    search_for_entrant(base_url, TARGET_ENTRANT_ID)

    # Part 2: Test removal system
    test_waitlist_removal(base_url)

    # Part 3: Debug join functionality
    test_waitlist_join(base_url)

    print("\n" + "="*80)
    print("TESTING COMPLETE")
    print("="*80)

if __name__ == "__main__":
    main()
