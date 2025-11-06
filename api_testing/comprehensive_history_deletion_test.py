#!/usr/bin/env python3
"""
Comprehensive Flight History Deletion Test
Tests ALL possible endpoints for deleting flight history using Sameer's JWT token
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple

# Configuration
API_BASE = "https://vauntapi.flyvaunt.com"
SAMEER_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
USER_ID = 20254

# Test results storage
results = {
    "summary": {
        "total_tests": 0,
        "successful_deletions": 0,
        "not_found_404": 0,
        "unauthorized_401": 0,
        "forbidden_403": 0,
        "other_errors": 0,
        "unexpected_success": 0
    },
    "tests": []
}

def get_headers(extra_headers: Dict[str, str] = None) -> Dict[str, str]:
    """Get base headers with optional extras"""
    headers = {
        "Authorization": f"Bearer {SAMEER_JWT}",
        "Content-Type": "application/json",
        "x-app-platform": "iOS",
        "x-device-id": "test-device-123",
        "x-build-number": "1.0.0"
    }
    if extra_headers:
        headers.update(extra_headers)
    return headers

def get_flight_history() -> Tuple[int, List[Dict], str]:
    """Get current flight history to verify deletions"""
    try:
        response = requests.get(
            f"{API_BASE}/v1/flight-history",
            headers=get_headers(),
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                return len(data), data, "Success"
            else:
                return 0, [], f"Unexpected response format: {type(data)}"
        return 0, [], f"Status {response.status_code}: {response.text[:100]}"
    except Exception as e:
        return 0, [], f"Error: {str(e)}"

def test_endpoint(method: str, url: str, category: str, description: str,
                  extra_headers: Dict[str, str] = None, body: Dict = None) -> Dict:
    """Test a single endpoint and record results"""
    global results

    test_result = {
        "category": category,
        "description": description,
        "method": method,
        "url": url,
        "extra_headers": extra_headers or {},
        "body": body,
        "timestamp": datetime.now().isoformat(),
        "status_code": None,
        "response_preview": "",
        "success": False,
        "verified_deletion": False,
        "error": None
    }

    results["summary"]["total_tests"] += 1

    try:
        # Get history count before
        count_before, history_before, _ = get_flight_history()

        # Make the request
        headers = get_headers(extra_headers)

        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=body or {}, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, json=body or {}, timeout=10)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, json=body or {}, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=body or {}, timeout=10)
        else:
            test_result["error"] = f"Unknown method: {method}"
            results["tests"].append(test_result)
            return test_result

        test_result["status_code"] = response.status_code

        # Get response preview
        try:
            response_text = response.text[:200] if response.text else "(empty)"
            test_result["response_preview"] = response_text
        except:
            test_result["response_preview"] = "(binary or unreadable)"

        # Categorize response
        if response.status_code in [200, 204]:
            test_result["success"] = True
            results["summary"]["successful_deletions"] += 1

            # Wait a moment and verify deletion
            time.sleep(0.5)
            count_after, history_after, _ = get_flight_history()

            if count_after < count_before:
                test_result["verified_deletion"] = True
                test_result["deletion_details"] = f"History reduced from {count_before} to {count_after} entries"
            else:
                test_result["verified_deletion"] = False
                test_result["deletion_details"] = f"History unchanged: {count_before} entries before and after"

        elif response.status_code == 404:
            results["summary"]["not_found_404"] += 1
        elif response.status_code == 401:
            results["summary"]["unauthorized_401"] += 1
        elif response.status_code == 403:
            results["summary"]["forbidden_403"] += 1
        else:
            results["summary"]["other_errors"] += 1

        # Log unexpected successes
        if response.status_code in [200, 201, 202, 204] and method == "DELETE":
            results["summary"]["unexpected_success"] += 1
            print(f"⚠️  UNEXPECTED SUCCESS: {method} {url} returned {response.status_code}")

    except requests.exceptions.Timeout:
        test_result["error"] = "Request timeout"
        results["summary"]["other_errors"] += 1
    except Exception as e:
        test_result["error"] = str(e)
        results["summary"]["other_errors"] += 1

    results["tests"].append(test_result)
    return test_result

def run_all_tests():
    """Run all comprehensive deletion tests"""

    print("=" * 80)
    print("COMPREHENSIVE FLIGHT HISTORY DELETION TEST")
    print("=" * 80)
    print(f"User ID: {USER_ID}")
    print(f"API Base: {API_BASE}")
    print(f"Test Start: {datetime.now().isoformat()}")
    print()

    # Get initial flight history
    count_initial, history_initial, status_msg = get_flight_history()
    print(f"Initial flight history count: {count_initial} entries")
    print(f"Status: {status_msg}")
    print()

    # Extract flight history IDs for specific deletion tests
    history_ids = []
    if history_initial:
        for entry in history_initial[:5]:  # Get up to 5 IDs
            if isinstance(entry, dict):
                if 'id' in entry:
                    history_ids.append(entry['id'])
                elif 'historyId' in entry:
                    history_ids.append(entry['historyId'])
                elif '_id' in entry:
                    history_ids.append(entry['_id'])

    print(f"Extracted history IDs for testing: {history_ids[:3]}")
    print()

    # ========================================================================
    # CATEGORY 1: V2 API History Deletion
    # ========================================================================
    print("\n" + "=" * 80)
    print("TESTING V2 API ENDPOINTS")
    print("=" * 80)

    v2_endpoints = [
        ("DELETE", f"{API_BASE}/v2/flight-history", "Delete all flight history"),
        ("DELETE", f"{API_BASE}/v2/history", "Delete all history (alternate)"),
        ("DELETE", f"{API_BASE}/v2/user/history", "Delete user history"),
        ("DELETE", f"{API_BASE}/v2/user/flight-history", "Delete user flight history"),
        ("POST", f"{API_BASE}/v2/flight-history/clear", "Clear flight history via POST"),
        ("POST", f"{API_BASE}/v2/flight-history/delete", "Delete flight history via POST"),
        ("POST", f"{API_BASE}/v2/flight-history/remove", "Remove flight history via POST"),
        ("PATCH", f"{API_BASE}/v2/flight-history", "Patch flight history with delete action"),
    ]

    for method, url, desc in v2_endpoints:
        body = {"action": "delete"} if method == "PATCH" else None
        test_endpoint(method, url, "V2 API", desc, body=body)
        time.sleep(0.2)

    # Test V2 with specific IDs
    if history_ids:
        for hist_id in history_ids[:2]:
            test_endpoint("DELETE", f"{API_BASE}/v2/flight-history/{hist_id}",
                         "V2 API", f"Delete specific history entry {hist_id}")
            time.sleep(0.2)

    # ========================================================================
    # CATEGORY 2: V3 API History Deletion
    # ========================================================================
    print("\n" + "=" * 80)
    print("TESTING V3 API ENDPOINTS")
    print("=" * 80)

    v3_endpoints = [
        ("DELETE", f"{API_BASE}/v3/flight-history", "Delete all flight history"),
        ("DELETE", f"{API_BASE}/v3/history", "Delete all history (alternate)"),
        ("DELETE", f"{API_BASE}/v3/user/history", "Delete user history"),
        ("DELETE", f"{API_BASE}/v3/user/flight-history", "Delete user flight history"),
        ("POST", f"{API_BASE}/v3/flight-history/clear", "Clear flight history via POST"),
        ("POST", f"{API_BASE}/v3/flight-history/delete", "Delete flight history via POST"),
        ("POST", f"{API_BASE}/v3/flight-history/remove", "Remove flight history via POST"),
    ]

    for method, url, desc in v3_endpoints:
        test_endpoint(method, url, "V3 API", desc)
        time.sleep(0.2)

    # Test V3 with specific IDs
    if history_ids:
        for hist_id in history_ids[:2]:
            test_endpoint("DELETE", f"{API_BASE}/v3/flight-history/{hist_id}",
                         "V3 API", f"Delete specific history entry {hist_id}")
            time.sleep(0.2)

    # ========================================================================
    # CATEGORY 3: Admin/Elevated Endpoints
    # ========================================================================
    print("\n" + "=" * 80)
    print("TESTING ADMIN/ELEVATED ENDPOINTS")
    print("=" * 80)

    admin_headers_variants = [
        {"x-admin": "true"},
        {"x-role": "admin"},
        {"x-elevated": "true"},
        {"x-superuser": "true"},
        {"x-admin": "true", "x-role": "admin"},
        {"x-internal": "true"},
        {"x-staff": "true"},
    ]

    admin_endpoints = [
        ("DELETE", f"{API_BASE}/v1/admin/flight-history"),
        ("DELETE", f"{API_BASE}/v2/admin/flight-history"),
        ("DELETE", f"{API_BASE}/v3/admin/flight-history"),
        ("DELETE", f"{API_BASE}/v1/admin/user/{USER_ID}/flight-history"),
        ("DELETE", f"{API_BASE}/v2/admin/user/{USER_ID}/flight-history"),
    ]

    for method, url in admin_endpoints:
        for headers in admin_headers_variants:
            header_desc = ", ".join([f"{k}={v}" for k, v in headers.items()])
            test_endpoint(method, url, "Admin Endpoints",
                         f"Admin endpoint with headers: {header_desc}",
                         extra_headers=headers)
            time.sleep(0.2)

    # ========================================================================
    # CATEGORY 4: Specific Flight History Entry Deletion
    # ========================================================================
    print("\n" + "=" * 80)
    print("TESTING SPECIFIC ENTRY DELETION")
    print("=" * 80)

    if history_ids:
        for hist_id in history_ids[:3]:
            endpoints = [
                ("DELETE", f"{API_BASE}/v1/flight-history/{hist_id}"),
                ("DELETE", f"{API_BASE}/v2/flight-history/{hist_id}"),
                ("DELETE", f"{API_BASE}/v3/flight-history/{hist_id}"),
                ("DELETE", f"{API_BASE}/v1/user/{USER_ID}/flight-history/{hist_id}"),
                ("DELETE", f"{API_BASE}/v2/user/{USER_ID}/flight-history/{hist_id}"),
                ("POST", f"{API_BASE}/v1/flight-history/{hist_id}/delete"),
                ("POST", f"{API_BASE}/v2/flight-history/{hist_id}/delete"),
            ]

            for method, url in endpoints:
                test_endpoint(method, url, "Specific Entry Deletion",
                             f"Delete history entry {hist_id}")
                time.sleep(0.2)
    else:
        print("No history IDs available for specific deletion tests")

    # ========================================================================
    # CATEGORY 5: Batch/Clear Operations
    # ========================================================================
    print("\n" + "=" * 80)
    print("TESTING BATCH/CLEAR OPERATIONS")
    print("=" * 80)

    batch_endpoints = [
        ("POST", f"{API_BASE}/v1/flight-history/clear-all"),
        ("POST", f"{API_BASE}/v2/flight-history/clear-all"),
        ("POST", f"{API_BASE}/v3/flight-history/clear-all"),
        ("DELETE", f"{API_BASE}/v1/user/{USER_ID}/history"),
        ("DELETE", f"{API_BASE}/v2/user/{USER_ID}/history"),
        ("DELETE", f"{API_BASE}/v3/user/{USER_ID}/history"),
        ("POST", f"{API_BASE}/v1/flight-history/batch-delete"),
        ("POST", f"{API_BASE}/v2/flight-history/batch-delete"),
        ("DELETE", f"{API_BASE}/v1/users/{USER_ID}/flight-history"),
        ("DELETE", f"{API_BASE}/v2/users/{USER_ID}/flight-history"),
    ]

    for method, url in batch_endpoints:
        test_endpoint(method, url, "Batch/Clear Operations", "Batch deletion endpoint")
        time.sleep(0.2)

    # ========================================================================
    # CATEGORY 6: Undocumented/Hidden Endpoints
    # ========================================================================
    print("\n" + "=" * 80)
    print("TESTING UNDOCUMENTED/HIDDEN ENDPOINTS")
    print("=" * 80)

    hidden_endpoints = [
        ("DELETE", f"{API_BASE}/v1/me/flight-history"),
        ("DELETE", f"{API_BASE}/v2/me/flight-history"),
        ("DELETE", f"{API_BASE}/v3/me/flight-history"),
        ("POST", f"{API_BASE}/v1/me/flight-history/archive"),
        ("POST", f"{API_BASE}/v2/flight-history/archive"),
        ("POST", f"{API_BASE}/v3/flight-history/archive"),
        ("DELETE", f"{API_BASE}/v1/profile/flight-history"),
        ("DELETE", f"{API_BASE}/v2/profile/flight-history"),
        ("POST", f"{API_BASE}/v1/flight-history/purge"),
        ("POST", f"{API_BASE}/v2/flight-history/purge"),
        ("DELETE", f"{API_BASE}/v1/account/flight-history"),
        ("DELETE", f"{API_BASE}/v2/account/flight-history"),
    ]

    for method, url in hidden_endpoints:
        test_endpoint(method, url, "Undocumented/Hidden", "Hidden endpoint")
        time.sleep(0.2)

    # ========================================================================
    # CATEGORY 7: Parameter Variations
    # ========================================================================
    print("\n" + "=" * 80)
    print("TESTING PARAMETER VARIATIONS")
    print("=" * 80)

    param_endpoints = [
        ("DELETE", f"{API_BASE}/v1/flight-history?force=true"),
        ("DELETE", f"{API_BASE}/v2/flight-history?force=true"),
        ("DELETE", f"{API_BASE}/v2/flight-history?admin=true"),
        ("DELETE", f"{API_BASE}/v3/flight-history?admin=true"),
        ("POST", f"{API_BASE}/v1/flight-history?action=delete"),
        ("POST", f"{API_BASE}/v2/flight-history?action=delete"),
        ("POST", f"{API_BASE}/v2/flight-history?action=clear"),
        ("DELETE", f"{API_BASE}/v2/flight-history?all=true"),
        ("DELETE", f"{API_BASE}/v3/flight-history?all=true"),
        ("POST", f"{API_BASE}/v2/flight-history?method=delete"),
        ("DELETE", f"{API_BASE}/v2/flight-history?permanent=true"),
        ("DELETE", f"{API_BASE}/v2/flight-history?userId={USER_ID}"),
    ]

    for method, url in param_endpoints:
        test_endpoint(method, url, "Parameter Variations", "Endpoint with query parameters")
        time.sleep(0.2)

    # ========================================================================
    # CATEGORY 8: V1 API (Standard endpoints we know exist)
    # ========================================================================
    print("\n" + "=" * 80)
    print("TESTING V1 API ENDPOINTS (Baseline)")
    print("=" * 80)

    v1_endpoints = [
        ("DELETE", f"{API_BASE}/v1/flight-history"),
        ("DELETE", f"{API_BASE}/v1/history"),
        ("DELETE", f"{API_BASE}/v1/user/flight-history"),
        ("POST", f"{API_BASE}/v1/flight-history/clear"),
        ("POST", f"{API_BASE}/v1/flight-history/delete"),
    ]

    for method, url in v1_endpoints:
        test_endpoint(method, url, "V1 API Baseline", "V1 standard endpoint")
        time.sleep(0.2)

    # ========================================================================
    # FINAL VERIFICATION
    # ========================================================================
    print("\n" + "=" * 80)
    print("FINAL VERIFICATION")
    print("=" * 80)

    count_final, history_final, status_msg = get_flight_history()
    print(f"Final flight history count: {count_final} entries")
    print(f"Status: {status_msg}")
    print(f"Change: {count_initial} → {count_final} ({count_final - count_initial:+d})")
    print()

    # Save results to JSON
    results["initial_history_count"] = count_initial
    results["final_history_count"] = count_final
    results["history_deleted"] = count_initial - count_final

    return results

def generate_markdown_report(results: Dict) -> str:
    """Generate markdown report from test results"""

    report = []
    report.append("# Comprehensive Flight History Deletion Test Results\n")
    report.append(f"**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report.append(f"**User ID:** {USER_ID}\n")
    report.append(f"**API Base:** {API_BASE}\n")
    report.append("\n")

    # Summary
    report.append("## Summary\n")
    report.append(f"- **Total endpoints tested:** {results['summary']['total_tests']}\n")
    report.append(f"- **Successful deletions (200/204):** {results['summary']['successful_deletions']}\n")
    report.append(f"- **404 Not Found:** {results['summary']['not_found_404']}\n")
    report.append(f"- **401 Unauthorized:** {results['summary']['unauthorized_401']}\n")
    report.append(f"- **403 Forbidden:** {results['summary']['forbidden_403']}\n")
    report.append(f"- **Other errors:** {results['summary']['other_errors']}\n")
    report.append(f"- **Unexpected successes:** {results['summary']['unexpected_success']}\n")
    report.append("\n")

    # History change
    report.append("## Flight History Status\n")
    report.append(f"- **Initial count:** {results.get('initial_history_count', 'N/A')}\n")
    report.append(f"- **Final count:** {results.get('final_history_count', 'N/A')}\n")
    report.append(f"- **Entries deleted:** {results.get('history_deleted', 0)}\n")
    report.append("\n")

    # Group results by category
    categories = {}
    for test in results["tests"]:
        cat = test["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(test)

    # Detailed results by category
    report.append("## Detailed Results by Category\n")

    for category in sorted(categories.keys()):
        report.append(f"\n### {category}\n")
        report.append("\n")

        # Show successful deletions first
        successes = [t for t in categories[category] if t.get("success")]
        if successes:
            report.append("#### ✅ Successful Deletions\n")
            for test in successes:
                report.append(f"- **{test['method']} {test['url']}**\n")
                report.append(f"  - Status: {test['status_code']}\n")
                report.append(f"  - Description: {test['description']}\n")
                if test.get('verified_deletion'):
                    report.append(f"  - ✅ **VERIFIED DELETION:** {test.get('deletion_details', '')}\n")
                else:
                    report.append(f"  - ⚠️ Success response but no verified deletion\n")
                report.append(f"  - Response: {test['response_preview']}\n")
                report.append("\n")

        # Show failures
        failures = [t for t in categories[category] if not t.get("success")]
        if failures:
            # Group by status code
            by_status = {}
            for test in failures:
                status = test.get('status_code', 'Error')
                if status not in by_status:
                    by_status[status] = []
                by_status[status].append(test)

            for status_code in sorted(by_status.keys(), key=lambda x: str(x)):
                report.append(f"#### Status {status_code} ({len(by_status[status_code])} tests)\n")

                # Show first 3 examples
                for test in by_status[status_code][:3]:
                    report.append(f"- {test['method']} {test['url']}\n")

                if len(by_status[status_code]) > 3:
                    report.append(f"- *(and {len(by_status[status_code]) - 3} more)*\n")
                report.append("\n")

    # Conclusion
    report.append("## Conclusion\n")
    report.append("\n")

    verified_deletions = [t for t in results["tests"] if t.get("verified_deletion")]
    successful_responses = [t for t in results["tests"] if t.get("success")]

    if verified_deletions:
        report.append(f"### ⚠️ CRITICAL FINDING: YES, Sameer CAN delete flight history!\n")
        report.append("\n")
        report.append(f"**{len(verified_deletions)} endpoint(s) successfully deleted flight history:**\n")
        report.append("\n")
        for test in verified_deletions:
            report.append(f"- **{test['method']} {test['url']}**\n")
            report.append(f"  - {test.get('deletion_details', '')}\n")
        report.append("\n")
    elif successful_responses:
        report.append(f"### ⚠️ AMBIGUOUS: {len(successful_responses)} endpoint(s) returned success but deletion not verified\n")
        report.append("\n")
        report.append("These endpoints returned 200/204 but flight history count remained unchanged:\n")
        report.append("\n")
        for test in successful_responses[:5]:
            report.append(f"- {test['method']} {test['url']}\n")
        report.append("\n")
        report.append("**Verdict:** Likely these are not functional deletion endpoints.\n")
        report.append("\n")
    else:
        report.append(f"### ✅ SECURE: No, Sameer CANNOT delete flight history\n")
        report.append("\n")
        report.append("All tested endpoints returned errors (404/401/403/500).\n")
        report.append("Flight history deletion appears to be properly protected.\n")
        report.append("\n")

    # Working endpoints summary
    if verified_deletions or successful_responses:
        report.append("### Working Endpoints Summary\n")
        report.append("\n")
        report.append("| Method | Endpoint | Status | Verified Deletion |\n")
        report.append("|--------|----------|--------|-------------------|\n")
        for test in (verified_deletions + successful_responses):
            verified = "✅ Yes" if test.get("verified_deletion") else "❌ No"
            report.append(f"| {test['method']} | {test['url']} | {test['status_code']} | {verified} |\n")
        report.append("\n")

    return "".join(report)

if __name__ == "__main__":
    print("Starting comprehensive flight history deletion test...")
    print()

    # Run all tests
    test_results = run_all_tests()

    # Generate and save report
    report_content = generate_markdown_report(test_results)

    # Save JSON results
    json_filename = "/home/user/vaunt/api_testing/history_deletion_test_results.json"
    with open(json_filename, "w") as f:
        json.dump(test_results, f, indent=2)

    print(f"\n✅ JSON results saved to: {json_filename}")

    # Save markdown report
    md_filename = "/home/user/vaunt/api_testing/FLIGHT_HISTORY_DELETION_COMPREHENSIVE_TEST.md"
    with open(md_filename, "w") as f:
        f.write(report_content)

    print(f"✅ Markdown report saved to: {md_filename}")

    # Print summary
    print("\n" + "=" * 80)
    print("TEST COMPLETE - SUMMARY")
    print("=" * 80)
    print(f"Total tests: {test_results['summary']['total_tests']}")
    print(f"Successful deletions: {test_results['summary']['successful_deletions']}")
    print(f"404 Not Found: {test_results['summary']['not_found_404']}")
    print(f"401 Unauthorized: {test_results['summary']['unauthorized_401']}")
    print(f"403 Forbidden: {test_results['summary']['forbidden_403']}")
    print(f"Other errors: {test_results['summary']['other_errors']}")
    print()

    verified_deletions = [t for t in test_results["tests"] if t.get("verified_deletion")]
    if verified_deletions:
        print("⚠️  CRITICAL: VERIFIED DELETIONS FOUND!")
        print(f"   {len(verified_deletions)} endpoint(s) successfully deleted flight history")
        for test in verified_deletions:
            print(f"   - {test['method']} {test['url']}")
    else:
        print("✅ No verified deletions - flight history appears secure")

    print("\n" + "=" * 80)
