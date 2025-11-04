#!/usr/bin/env python3
"""
Test the confirm endpoint in detail - it returned 400 (not 404)
"""

import requests
import json

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

FLIGHT_ID = 8795

headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

print("="*80)
print("DETAILED ENDPOINT TESTING")
print("="*80)

# Test the confirm endpoint that returned 400
endpoints = [
    ("POST", f"/v1/flight/{FLIGHT_ID}/confirm", None),
    ("POST", f"/v1/flight/{FLIGHT_ID}/accept", None),
    ("POST", f"/v1/flight/{FLIGHT_ID}/decline", None),
    ("GET", f"/v1/flight/{FLIGHT_ID}", None),
    ("GET", f"/v1/flight/{FLIGHT_ID}/status", None),
    ("GET", f"/v1/flight/{FLIGHT_ID}/entrants", None),
]

for method, endpoint, data in endpoints:
    print(f"\n{'='*80}")
    print(f"{method} {endpoint}")
    print(f"{'='*80}")
    
    try:
        url = f"{PROD_URL}{endpoint}"
        
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        
        print(f"Status: {r.status_code}")
        
        if r.text:
            print(f"\nResponse:")
            try:
                print(json.dumps(r.json(), indent=2)[:500])
            except:
                print(r.text[:500])
    
    except requests.exceptions.Timeout:
        print("❌ Timeout")
    except requests.exceptions.ConnectionError:
        print("❌ Connection error")
    except Exception as e:
        print(f"❌ Error: {str(e)[:100]}")

# Check if there's a way to see available actions
print("\n" + "="*80)
print("CHECK AVAILABLE ACTIONS")
print("="*80)

r = requests.get(f"{PROD_URL}/v1/flight/current", headers=headers)
if r.status_code == 200:
    flights = r.json()
    for flight in flights:
        if flight.get('id') == FLIGHT_ID:
            print(f"\nFlight {FLIGHT_ID} data:")
            print(f"Status: {flight.get('status')}")
            print(f"Winner: {flight.get('winner')}")
            print(f"First in line: {flight.get('firstInLine')}")
            print(f"Is confirmed by winner: {flight.get('isConfirmedByWinner')}")
            print(f"Notify winner at: {flight.get('notifyWinnerAt')}")
            
            # User data
            user_data = flight.get('userData', {})
            print(f"\nYour data:")
            print(json.dumps(user_data, indent=2))
            
            # Entrants
            entrants = flight.get('entrants', [])
            print(f"\nAll entrants:")
            for ent in entrants:
                if ent.get('id') == 20254:
                    print(f"  YOU: Position #{ent.get('queuePosition')}")
                else:
                    print(f"  User {ent.get('id')}: Position #{ent.get('queuePosition')}")
