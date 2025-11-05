#!/usr/bin/env python3
"""
V2/V3 Endpoint Enumeration

Systematically test for undiscovered endpoints
"""

import requests
import json
import time

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def test_endpoint(method, path, payload=None):
    """Test an endpoint and return status"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    url = f"{API_URL}{path}"

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=5)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=payload or {}, timeout=5)
        elif method == "PUT":
            r = requests.put(url, headers=headers, json=payload or {}, timeout=5)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=payload or {}, timeout=5)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=5)
        else:
            return None

        return {
            "status": r.status_code,
            "response": r.text[:200]
        }
    except Exception as e:
        return {"status": "ERROR", "response": str(e)}

def main():
    print("="*80)
    print("V2/V3 ENDPOINT ENUMERATION")
    print("="*80)
    print()

    discovered = []
    tested_count = 0

    # V2 Flight operations
    print("Testing V2 Flight Operations...")
    print("-" * 80)

    flight_ops = [
        "enter", "reset", "exit", "leave", "cancel",
        "confirm", "purchase", "claim", "accept", "reject",
        "upgrade", "downgrade", "modify", "update", "delete",
        "status", "details", "info", "current"
    ]

    flight_id = 8800

    for op in flight_ops:
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            path = f"/v2/flight/{flight_id}/{op}"
            result = test_endpoint(method, path)
            tested_count += 1

            if result and result['status'] not in [404, 405, "ERROR"]:
                print(f"✅ Found: {method} {path} - Status: {result['status']}")
                discovered.append({
                    "method": method,
                    "path": path,
                    "status": result['status'],
                    "response": result['response']
                })

            time.sleep(0.05)  # Rate limiting courtesy

    print()

    # V2 User operations
    print("Testing V2 User Operations...")
    print("-" * 80)

    user_ops = [
        "", "profile", "settings", "upgrade", "subscription",
        "flights", "history", "waitlist", "priority",
        "device", "notifications", "preferences"
    ]

    for op in user_ops:
        path = f"/v2/user/{op}".rstrip("/")
        for method in ["GET", "POST", "PATCH"]:
            result = test_endpoint(method, path)
            tested_count += 1

            if result and result['status'] not in [404, 405, "ERROR"]:
                print(f"✅ Found: {method} {path} - Status: {result['status']}")
                discovered.append({
                    "method": method,
                    "path": path,
                    "status": result['status'],
                    "response": result['response']
                })

            time.sleep(0.05)

    print()

    # V2 Subscription operations
    print("Testing V2 Subscription Operations...")
    print("-" * 80)

    subscription_ops = [
        "", "status", "upgrade", "cancel", "renew", "pk",
        "tiers", "plans", "pricing"
    ]

    for op in subscription_ops:
        path = f"/v2/subscription/{op}".rstrip("/")
        result = test_endpoint("GET", path)
        tested_count += 1

        if result and result['status'] not in [404, 405, "ERROR"]:
            print(f"✅ Found: GET {path} - Status: {result['status']}")
            discovered.append({
                "method": "GET",
                "path": path,
                "status": result['status'],
                "response": result['response']
            })

        time.sleep(0.05)

    print()

    # V3 endpoints
    print("Testing V3 Operations...")
    print("-" * 80)

    v3_paths = [
        "/v3/flight",
        f"/v3/flight/{flight_id}",
        "/v3/user",
        "/v3/user/profile",
        "/v3/subscription",
        "/v3/waitlist"
    ]

    for path in v3_paths:
        result = test_endpoint("GET", path)
        tested_count += 1

        if result and result['status'] not in [404, 405, "ERROR"]:
            print(f"✅ Found: GET {path} - Status: {result['status']}")
            discovered.append({
                "method": "GET",
                "path": path,
                "status": result['status'],
                "response": result['response']
            })

        time.sleep(0.05)

    print()

    # Summary
    print("="*80)
    print("ENUMERATION RESULTS")
    print("="*80)
    print()
    print(f"Total endpoints tested: {tested_count}")
    print(f"New endpoints discovered: {len(discovered)}")
    print()

    if discovered:
        print("Discovered Endpoints:")
        print("-" * 80)
        for ep in discovered:
            print(f"  {ep['method']:6} {ep['path']:40} Status: {ep['status']}")

        # Save to file
        output_file = "/home/user/vaunt/api_testing/discovered_endpoints_v2_v3.json"
        with open(output_file, 'w') as f:
            json.dump(discovered, f, indent=2)
        print()
        print(f"✅ Results saved to: {output_file}")
    else:
        print("No new endpoints discovered beyond the known ones:")
        print("  - POST /v2/flight/{id}/enter")
        print("  - POST /v2/flight/{id}/reset")
        print("  - GET /v2/flight/current")
        print("  - GET /v3/flight")

    print()
    print("="*80)

if __name__ == "__main__":
    main()
