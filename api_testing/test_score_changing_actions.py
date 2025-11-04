#!/usr/bin/env python3
"""
Test actions that might change priority score
"""

import requests
import json

BASE_URL = "https://qa-vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def check_score():
    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}
    r = requests.get(f"{BASE_URL}/v1/user", headers=headers)
    if r.status_code == 200:
        return r.json().get('priorityScore')
    return None

print("="*80)
print("TESTING: Actions That Might Change Priority Score")
print("="*80)

headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

# Endpoints related to flights/bookings that might affect score
test_endpoints = [
    # Flight-related endpoints
    ("GET", "/v1/flight/current", None, "Get current flights"),
    ("GET", "/v1/flight-history", None, "Get flight history"),
    ("GET", "/v1/flight/upcoming", None, "Get upcoming flights"),
    ("GET", "/v1/flight/past", None, "Get past flights"),
    
    # Cancellation-related (might lower score)
    ("POST", "/v1/flight/cancel", {"flightId": 1}, "Cancel flight (might lower score!)"),
    ("POST", "/v1/booking/cancel", {"bookingId": 1}, "Cancel booking"),
    
    # Subscription/membership actions
    ("GET", "/v1/subscription/status", None, "Get subscription status"),
    ("POST", "/v1/subscription/renew", None, "Renew subscription (might recalculate!)"),
    
    # Profile/account actions
    ("GET", "/v1/user/profile", None, "Get profile (might trigger sync)"),
    ("GET", "/v1/user/settings", None, "Get settings"),
    ("POST", "/v1/user/sync", None, "Sync user data"),
    
    # Waitlist/priority related
    ("GET", "/v1/waitlist", None, "Get waitlist position"),
    ("GET", "/v1/user/priority", None, "Get priority info"),
    ("POST", "/v1/priority/recalculate", None, "Force recalculate?"),
]

initial_score = check_score()
print(f"\n📊 Initial Score: {initial_score}\n")

for method, endpoint, data, description in test_endpoints:
    print(f"🧪 {description}")
    print(f"   {method} {endpoint}")
    
    try:
        url = f"{BASE_URL}{endpoint}"
        
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        
        print(f"   Status: {r.status_code}")
        
        if r.status_code == 200:
            # Check if score changed
            new_score = check_score()
            if new_score != initial_score:
                print(f"\n   🚨 SCORE CHANGED!")
                print(f"   Before: {initial_score}")
                print(f"   After:  {new_score}")
                print(f"   Diff:   {new_score - initial_score}")
                print(f"   ✅ THIS ACTION CHANGES PRIORITY SCORE!\n")
                initial_score = new_score
            
            # Show some response data
            try:
                resp_data = r.json()
                if isinstance(resp_data, dict):
                    if 'priorityScore' in resp_data:
                        print(f"   Response has priorityScore: {resp_data['priorityScore']}")
                elif isinstance(resp_data, list) and len(resp_data) > 0:
                    print(f"   Response: List with {len(resp_data)} items")
            except:
                pass
        
        print()
        
    except Exception as e:
        print(f"   Error: {str(e)[:50]}")
        print()

final_score = check_score()
print("="*80)
print(f"Final Score: {final_score}")
if final_score != initial_score:
    print(f"Total Change: {final_score - initial_score}")
    print("\n✅ SCORE CAN BE CHANGED!")
else:
    print("\n❌ No changes detected")
print("="*80)
