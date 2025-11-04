#!/usr/bin/env python3
"""
Test Duffel API integration for commercial flights and hotels
Check if bookings affect priority score
"""

import requests
import json

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

print("="*80)
print("TESTING DUFFEL INTEGRATION")
print("="*80)

# Test Duffel endpoints found in React Native bundle
duffel_endpoints = [
    ("GET", "/v1/app/duffel/airlines", None, "Get airlines list"),
    ("GET", "/v1/app/duffel/place-suggestions", {"query": "Miami"}, "Search places"),
    ("GET", "/v1/app/duffel/get-places-by-iata", {"iata": "MIA"}, "Get place by IATA"),
    ("POST", "/v1/app/duffel/create-hold-order", {}, "Create hold order"),
    ("GET", "/v1/duffel/stays/geocoding", {"query": "Miami"}, "Hotel geocoding"),
]

print("\n" + "="*80)
print("DUFFEL API ENDPOINTS")
print("="*80 + "\n")

active_endpoints = []

for method, endpoint, params, description in duffel_endpoints:
    url = f"{PROD_URL}{endpoint}"
    
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, params=params, timeout=10)
        else:
            r = requests.post(url, headers=headers, json=params, timeout=10)
        
        status = r.status_code
        
        if status == 200:
            print(f"✅ {status} - {endpoint}")
            print(f"   Description: {description}")
            
            try:
                data = r.json()
                
                if isinstance(data, list):
                    print(f"   Response: List with {len(data)} items")
                    if len(data) > 0:
                        print(f"   Sample: {json.dumps(data[0], indent=2)[:300]}")
                elif isinstance(data, dict):
                    print(f"   Response keys: {list(data.keys())}")
                    print(f"   Sample: {json.dumps(data, indent=2)[:400]}")
                
                active_endpoints.append({
                    "endpoint": endpoint,
                    "method": method,
                    "data": data
                })
            except:
                print(f"   Response: {r.text[:200]}")
            
            print()
        
        elif status == 400:
            print(f"⚠️  {status} - {endpoint}")
            print(f"   {description} - Exists but needs correct params")
            try:
                print(f"   Error: {r.json()}")
            except:
                print(f"   Error: {r.text[:200]}")
            print()
        
        elif status == 404:
            print(f"❌ {status} - {endpoint} - Not found")
        
        else:
            print(f"❌ {status} - {endpoint}")
            print(f"   Response: {r.text[:200]}")
            print()
    
    except Exception as e:
        print(f"❌ {endpoint} - Error: {e}")

# Test for booking history / activity
print("\n" + "="*80)
print("USER ACTIVITY & BOOKING HISTORY")
print("="*80 + "\n")

activity_endpoints = [
    "/v1/user/bookings",
    "/v1/user/activity",
    "/v1/user/travel-history",
    "/v1/user/purchases",
    "/v1/user/orders",
    "/v1/duffel/orders",
    "/v1/duffel/my-orders",
    "/v1/app/duffel/orders",
    "/v1/app/duffel/my-bookings",
]

for endpoint in activity_endpoints:
    try:
        r = requests.get(f"{PROD_URL}{endpoint}", headers=headers, timeout=10)
        
        if r.status_code == 200:
            print(f"✅ {endpoint}")
            try:
                data = r.json()
                print(f"   Data: {json.dumps(data, indent=2)[:500]}")
            except:
                print(f"   Response: {r.text[:200]}")
            print()
    except:
        pass

# Test for rewards/points system
print("\n" + "="*80)
print("REWARDS & PRIORITY SYSTEM")
print("="*80 + "\n")

rewards_endpoints = [
    "/v1/rewards",
    "/v1/points",
    "/v1/loyalty",
    "/v1/user/rewards",
    "/v1/user/points",
    "/v1/priority",
    "/v1/priority/history",
    "/v1/user/priority-history",
]

for endpoint in rewards_endpoints:
    try:
        r = requests.get(f"{PROD_URL}{endpoint}", headers=headers, timeout=10)
        
        if r.status_code == 200:
            print(f"✅ {endpoint}")
            try:
                data = r.json()
                print(f"   Data: {json.dumps(data, indent=2)[:500]}")
            except:
                print(f"   Response: {r.text[:200]}")
            print()
    except:
        pass

# Check flight history for any Duffel metadata
print("\n" + "="*80)
print("FLIGHT HISTORY (Check for Duffel metadata)")
print("="*80 + "\n")

try:
    r = requests.get(f"{PROD_URL}/v1/flight-history", headers=headers, timeout=10)
    
    if r.status_code == 200:
        flights = r.json()
        print(f"✅ Found {len(flights)} flights in history")
        
        # Check if any flights have Duffel-related fields
        if flights:
            print("\nChecking for Duffel-related fields...")
            sample = flights[0]
            keys = list(sample.keys())
            print(f"Flight keys: {keys}")
            
            duffel_fields = [k for k in keys if 'duffel' in k.lower() or 'commercial' in k.lower() or 'hotel' in k.lower()]
            if duffel_fields:
                print(f"\n✅ FOUND Duffel-related fields: {duffel_fields}")
            else:
                print(f"\n❌ No Duffel-related fields in flight history")
except Exception as e:
    print(f"Error: {e}")

print("\n" + "="*80)
print("SUMMARY")
print("="*80)

if active_endpoints:
    print(f"\n✅ Found {len(active_endpoints)} active Duffel endpoints:")
    for item in active_endpoints:
        print(f"   - {item['endpoint']}")
    
    print("\n🔍 This confirms:")
    print("   - Vaunt integrates with Duffel API for commercial flights/hotels")
    print("   - These endpoints ARE accessible via API")
    print("   - Users can book through the app")
else:
    print("\n❌ No active Duffel endpoints found")
    print("   - Endpoints may exist in code but not deployed")
    print("   - Or they require specific params/auth we don't have")

print("\n💡 Next Steps:")
print("   1. Search React Native bundle for priority score calculation")
print("   2. Check if Duffel order completion triggers score boost")
print("   3. Look for reward/points tracking system")

print("\n" + "="*80)
