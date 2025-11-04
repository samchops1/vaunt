#!/usr/bin/env python3
"""
Comprehensive waitlist API endpoint discovery and manipulation testing
"""

import requests
import json

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

FLIGHT_ID = 8795
USER_ID = 20254

headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

print("="*80)
print("WAITLIST API ENDPOINT DISCOVERY")
print("="*80)

# Comprehensive waitlist endpoint list
waitlist_endpoints = [
    # General waitlist
    ("GET", "/v1/waitlist", None, "Get waitlist"),
    ("GET", "/v1/waitlist/list", None, "List waitlists"),
    ("GET", "/v1/waitlist/active", None, "Active waitlists"),
    ("GET", "/v1/waitlist/all", None, "All waitlists"),
    
    # Flight-specific waitlist
    ("GET", f"/v1/waitlist/{FLIGHT_ID}", None, "Get flight waitlist"),
    ("GET", f"/v1/flight/{FLIGHT_ID}/waitlist", None, "Flight waitlist alt"),
    
    # User's waitlist entries
    ("GET", "/v1/user/waitlist", None, "User's waitlist entries"),
    ("GET", "/v1/user/waitlist/active", None, "User's active waitlists"),
    
    # Join/leave waitlist
    ("POST", f"/v1/waitlist/join", {"flightId": FLIGHT_ID}, "Join waitlist"),
    ("POST", f"/v1/waitlist/enter", {"flightId": FLIGHT_ID}, "Enter waitlist"),
    ("POST", f"/v1/flight/{FLIGHT_ID}/waitlist", None, "Add to waitlist"),
    ("DELETE", f"/v1/waitlist/{FLIGHT_ID}", None, "Leave waitlist"),
    ("POST", f"/v1/waitlist/{FLIGHT_ID}/leave", None, "Leave waitlist alt"),
    
    # Position manipulation
    ("PATCH", f"/v1/waitlist/{FLIGHT_ID}", {"position": 0}, "Change position"),
    ("PATCH", f"/v1/waitlist/{FLIGHT_ID}/position", {"position": 0}, "Set position"),
    ("POST", f"/v1/waitlist/{FLIGHT_ID}/bump", None, "Bump up"),
    ("POST", f"/v1/waitlist/reorder", {"flightId": FLIGHT_ID, "position": 0}, "Reorder"),
    
    # Upgrade/boost
    ("POST", f"/v1/waitlist/{FLIGHT_ID}/upgrade", None, "Upgrade position"),
    ("POST", f"/v1/waitlist/upgrade/purchase", {"flightId": FLIGHT_ID}, "Purchase upgrade"),
    ("POST", f"/v1/waitlist/boost", {"flightId": FLIGHT_ID}, "Boost priority"),
    
    # Entrant management
    ("GET", f"/v1/flight/{FLIGHT_ID}/entrants", None, "Get entrants"),
    ("PATCH", f"/v1/flight/{FLIGHT_ID}/entrants/{USER_ID}", {"position": 0}, "Update entrant"),
    ("PATCH", f"/v1/entrant/{USER_ID}", {"flightId": FLIGHT_ID, "position": 0}, "Update via entrant"),
]

successful = []
manipulation_possible = []

print("\nTesting endpoints...\n")

for method, endpoint, data, description in waitlist_endpoints:
    url = f"{PROD_URL}{endpoint}"
    
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=data, timeout=10)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=10)
        
        status = r.status_code
        
        if status == 200:
            print(f"✅ {status} - {method} {endpoint}")
            print(f"   Description: {description}")
            
            try:
                resp_data = r.json()
                
                # Show preview
                if isinstance(resp_data, list):
                    print(f"   Response: List with {len(resp_data)} items")
                    if len(resp_data) > 0 and isinstance(resp_data[0], dict):
                        keys = list(resp_data[0].keys())[:5]
                        print(f"   Keys: {keys}")
                elif isinstance(resp_data, dict):
                    keys = list(resp_data.keys())[:8]
                    print(f"   Keys: {keys}")
                
                successful.append({
                    "endpoint": endpoint,
                    "method": method,
                    "description": description,
                    "data": resp_data
                })
                
                # Check if it's a manipulation endpoint
                if method in ["PATCH", "POST", "DELETE"] and "position" in str(data):
                    manipulation_possible.append(endpoint)
                
            except:
                print(f"   Response: {r.text[:100]}")
            
            print()
        
        elif status == 400:
            print(f"⚠️  {status} - {method} {endpoint}")
            try:
                error = r.json()
                print(f"   Error: {error}")
            except:
                print(f"   Error: {r.text[:100]}")
            print()
        
        elif status == 404:
            pass  # Skip 404s to reduce noise
        
        else:
            print(f"❌ {status} - {method} {endpoint}")
            print()
    
    except Exception as e:
        pass  # Skip errors

print("\n" + "="*80)
print("DETAILED ANALYSIS OF SUCCESSFUL ENDPOINTS")
print("="*80)

for item in successful:
    print(f"\n{'='*80}")
    print(f"{item['method']} {item['endpoint']}")
    print(f"Description: {item['description']}")
    print(f"{'='*80}")
    
    data = item['data']
    
    if isinstance(data, list) and len(data) > 0:
        print(f"\nTotal items: {len(data)}")
        print(f"\nFirst item:")
        print(json.dumps(data[0], indent=2)[:500])
    elif isinstance(data, dict):
        print(f"\nResponse:")
        print(json.dumps(data, indent=2)[:500])

print("\n" + "="*80)
print("SUMMARY")
print("="*80)

print(f"\n✅ Working endpoints: {len(successful)}")
for item in successful:
    print(f"   - {item['method']} {item['endpoint']}")

if manipulation_possible:
    print(f"\n🎯 Potential manipulation endpoints: {len(manipulation_possible)}")
    for ep in manipulation_possible:
        print(f"   - {ep}")
else:
    print(f"\n❌ No manipulation endpoints found")

print("\n" + "="*80)
