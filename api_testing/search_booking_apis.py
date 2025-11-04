#!/usr/bin/env python3
"""
Search for commercial flight/hotel booking APIs that might affect priority score
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
print("SEARCHING FOR COMMERCIAL FLIGHT/HOTEL BOOKING APIS")
print("="*80)

# Potential booking-related endpoints
booking_endpoints = [
    # Commercial flight booking
    ("GET", "/v1/commercial/flights", "Commercial flights"),
    ("GET", "/v1/booking/commercial", "Commercial bookings"),
    ("GET", "/v1/flight/commercial", "Commercial flight search"),
    ("GET", "/v1/travel/flights", "Travel flights"),
    ("GET", "/v1/partner/flights", "Partner flights"),
    
    # Hotel booking
    ("GET", "/v1/hotels", "Hotels"),
    ("GET", "/v1/hotel/search", "Hotel search"),
    ("GET", "/v1/booking/hotels", "Hotel bookings"),
    ("GET", "/v1/accommodations", "Accommodations"),
    ("GET", "/v1/lodging", "Lodging"),
    
    # Partner/affiliate
    ("GET", "/v1/partner/services", "Partner services"),
    ("GET", "/v1/affiliate/offers", "Affiliate offers"),
    ("GET", "/v1/third-party/bookings", "Third party bookings"),
    ("GET", "/v1/external/travel", "External travel"),
    
    # Rewards/points
    ("GET", "/v1/rewards", "Rewards"),
    ("GET", "/v1/points", "Points"),
    ("GET", "/v1/loyalty", "Loyalty program"),
    ("GET", "/v1/earn", "Earn opportunities"),
    ("GET", "/v1/priority/earn", "Earn priority"),
    
    # User activity/history
    ("GET", "/v1/user/bookings", "User bookings"),
    ("GET", "/v1/user/travel-history", "Travel history"),
    ("GET", "/v1/user/activity", "User activity"),
    ("GET", "/v1/user/purchases", "User purchases"),
]

print("\nTesting endpoints...\n")

found_endpoints = []

for method, endpoint, description in booking_endpoints:
    url = f"{PROD_URL}{endpoint}"
    
    try:
        r = requests.get(url, headers=headers, timeout=10)
        
        if r.status_code == 200:
            print(f"✅ {endpoint} - {description}")
            
            try:
                data = r.json()
                
                if isinstance(data, list):
                    print(f"   Response: List with {len(data)} items")
                    if len(data) > 0:
                        print(f"   First item keys: {list(data[0].keys())[:8]}")
                elif isinstance(data, dict):
                    print(f"   Response keys: {list(data.keys())[:8]}")
                
                found_endpoints.append({
                    "endpoint": endpoint,
                    "description": description,
                    "data": data
                })
                
                print()
            except:
                print(f"   Response: {r.text[:100]}\n")
        
        elif r.status_code == 400:
            print(f"⚠️  {endpoint} - {description}")
            print(f"   Status: 400 - Might exist but needs params\n")
    
    except Exception as e:
        pass  # Skip errors

# Check app configuration
print("\n" + "="*80)
print("APP CONFIGURATION & FEATURES")
print("="*80)

config_endpoints = [
    "/v1/app/config",
    "/v1/app/features",
    "/v1/app/services",
    "/v1/app/partners",
    "/v1/app/integrations",
    "/v1/config",
    "/v1/features",
]

for endpoint in config_endpoints:
    try:
        r = requests.get(f"{PROD_URL}{endpoint}", headers=headers, timeout=10)
        
        if r.status_code == 200:
            print(f"\n✅ {endpoint}")
            try:
                data = r.json()
                print(json.dumps(data, indent=2)[:800])
            except:
                print(r.text[:400])
    except:
        pass

# Show detailed data for found endpoints
if found_endpoints:
    print("\n" + "="*80)
    print("DETAILED ENDPOINT DATA")
    print("="*80)
    
    for item in found_endpoints:
        print(f"\n{'='*80}")
        print(f"{item['endpoint']} - {item['description']}")
        print(f"{'='*80}")
        print(json.dumps(item['data'], indent=2)[:600])

print("\n" + "="*80)
print("SUMMARY")
print("="*80)

if found_endpoints:
    print(f"\n✅ Found {len(found_endpoints)} booking-related endpoints:")
    for item in found_endpoints:
        print(f"   - {item['endpoint']}")
else:
    print("\n❌ No commercial flight/hotel booking endpoints found")
    print("\nThis suggests:")
    print("  - No third-party booking integration via API")
    print("  - Commercial flights/hotels may be in-app only")
    print("  - Priority boost mechanism is server-side/hidden")
    print("  - Or feature doesn't exist / not exposed via API")

print("\n" + "="*80)
