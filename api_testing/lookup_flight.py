#!/usr/bin/env python3
"""
Look up specific flight by ID
"""

import requests
import json
import sys

SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

BASE_URL = "https://vauntapi.flyvaunt.com"

def lookup_flight(flight_id):
    """Look up flight by ID"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    endpoints = [
        f"/v1/flight/{flight_id}",
        f"/v2/flight/{flight_id}",
        f"/v3/flight/{flight_id}",
        f"/v1/flight",
        f"/v2/flight",
        f"/v3/flight",
    ]

    print(f"=" * 80)
    print(f"🔍 LOOKING UP FLIGHT #{flight_id}")
    print(f"=" * 80)

    for endpoint in endpoints:
        url = f"{BASE_URL}{endpoint}"
        try:
            response = requests.get(url, headers=headers, timeout=10)
            print(f"\n📡 {response.status_code} {endpoint}")

            if response.status_code == 200:
                data = response.json()

                # Check if this is a list endpoint
                if endpoint in ["/v1/flight", "/v2/flight", "/v3/flight"]:
                    flights = data if isinstance(data, list) else data.get('data', [])
                    # Search for the specific flight ID
                    found = False
                    for flight in flights:
                        if isinstance(flight, dict) and flight.get('id') == int(flight_id):
                            print(f"   ✅ FOUND in list!")
                            print(json.dumps(flight, indent=2))
                            found = True
                            return flight
                    if not found:
                        print(f"   ⚠️  Flight {flight_id} not in list (showing {len(flights)} flights)")
                else:
                    # Direct endpoint
                    print(f"   ✅ SUCCESS!")
                    print(json.dumps(data, indent=2))
                    return data

            elif response.status_code == 404:
                print(f"   ❌ Not Found")
            elif response.status_code in [401, 403]:
                print(f"   🔒 Unauthorized/Forbidden")
            else:
                print(f"   ⚠️  {response.text[:200]}")

        except Exception as e:
            print(f"   💥 Exception: {str(e)}")

    print(f"\n❌ Flight #{flight_id} not found in any endpoint")
    return None

if __name__ == "__main__":
    flight_id = sys.argv[1] if len(sys.argv) > 1 else "88847"
    result = lookup_flight(flight_id)

    if result:
        print(f"\n" + "=" * 80)
        print(f"✅ FLIGHT #{flight_id} DETAILS")
        print(f"=" * 80)
        print(json.dumps(result, indent=2))
