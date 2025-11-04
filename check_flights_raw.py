#!/usr/bin/env python3
"""
Check raw flight data from API
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
print("RAW FLIGHT DATA - PRODUCTION API")
print("="*80)

# Try different flight endpoints
endpoints = [
    "/v1/flight/current",
    "/v1/flights",
    "/v1/flight/all",
    "/v1/flight/available",
    "/v1/flight/list",
]

for endpoint in endpoints:
    print(f"\n{'='*80}")
    print(f"Endpoint: {endpoint}")
    print(f"{'='*80}")
    
    r = requests.get(f"{PROD_URL}{endpoint}", headers=headers)
    print(f"Status: {r.status_code}\n")
    
    if r.status_code == 200:
        try:
            data = r.json()
            
            if isinstance(data, list):
                print(f"Response: List with {len(data)} items\n")
                if len(data) > 0:
                    print("First flight (raw JSON):")
                    print(json.dumps(data[0], indent=2))
                    
                    if len(data) > 1:
                        print("\n\nSecond flight (raw JSON):")
                        print(json.dumps(data[1], indent=2))
            else:
                print("Response:")
                print(json.dumps(data, indent=2))
        except:
            print(f"Response (text): {r.text[:500]}")

# Also check if there's a detail endpoint
print(f"\n{'='*80}")
print("Trying individual flight details")
print(f"{'='*80}")

flight_id = 5779
r = requests.get(f"{PROD_URL}/v1/flight/{flight_id}", headers=headers)
print(f"\nGET /v1/flight/{flight_id}")
print(f"Status: {r.status_code}")

if r.status_code == 200:
    try:
        print("\nFull flight details:")
        print(json.dumps(r.json(), indent=2))
    except:
        print(r.text[:500])
