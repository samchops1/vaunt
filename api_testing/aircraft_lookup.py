#!/usr/bin/env python3
"""
Look up aircraft types and carrier information
"""

import requests
import json

SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

BASE_URL = "https://vauntapi.flyvaunt.com"

def try_endpoint(endpoint):
    """Try to access an endpoint"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        print(f"{response.status_code} {endpoint}")

        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ SUCCESS!")
            print(json.dumps(data, indent=2)[:1000])
            return data
        elif response.status_code == 404:
            print(f"   ❌ Not Found")
        elif response.status_code == 401:
            print(f"   🔒 Unauthorized")
        elif response.status_code == 403:
            print(f"   🔒 Forbidden")
        else:
            print(f"   ⚠️  {response.text[:200]}")

        return None
    except Exception as e:
        print(f"   💥 Exception: {str(e)}")
        return None

print("=" * 80)
print("🔍 AIRCRAFT & CARRIER LOOKUP")
print("=" * 80)

# Aircraft IDs found: 114, 122, 89
# Type IDs: 15, 11
# Carrier IDs: 6, 4

print("\n📋 Testing Aircraft Endpoints...")
print("-" * 80)

endpoints = [
    "/v1/aircraft",
    "/v2/aircraft",
    "/v3/aircraft",
    "/v1/aircraft/114",
    "/v2/aircraft/114",
    "/v1/aircraft-type",
    "/v2/aircraft-type",
    "/v1/aircraft-type/11",
    "/v1/aircraft-type/15",
    "/v2/aircraft-type/11",
    "/v2/aircraft-type/15",
    "/v1/aircraft/types",
    "/v1/carrier",
    "/v2/carrier",
    "/v1/carrier/4",
    "/v1/carrier/6",
    "/v2/carrier/4",
    "/v2/carrier/6",
    "/v1/airline",
    "/v2/airline",
    "/v1/airline/4",
    "/v1/airline/6",
    "/v1/airline-carrier",
    "/v2/airline-carrier",
    "/v1/airline-carrier/4",
    "/v1/airline-carrier/6",
    "/v1/fleet",
    "/v2/fleet",
]

results = {}
for endpoint in endpoints:
    data = try_endpoint(endpoint)
    if data:
        results[endpoint] = data

print("\n" + "=" * 80)
print(f"📊 FOUND {len(results)} WORKING ENDPOINTS")
print("=" * 80)

for endpoint, data in results.items():
    print(f"\n✅ {endpoint}")
    print(json.dumps(data, indent=2)[:500])
    print("...")

# Save results
with open("/home/user/vaunt/api_testing/aircraft_lookup_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("\n💾 Results saved to aircraft_lookup_results.json")
