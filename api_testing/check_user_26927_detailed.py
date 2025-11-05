#!/usr/bin/env python3
"""
Detailed check for User ID 26927 and Entrant ID 34740
"""

import requests
import json
from datetime import datetime

PROD_URL = "https://vauntapi.flyvaunt.com"
QA_URL = "https://qa-vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

TARGET_USER_ID = 26927
TARGET_ENTRANT_ID = 34740

def make_request(base_url, endpoint, token, method="GET", data=None):
    """Make API request with detailed error handling"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    url = f"{base_url}{endpoint}"

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        else:
            return None

        print(f"   Status Code: {r.status_code}")
        print(f"   Response Length: {len(r.text)} bytes")

        if r.status_code == 200:
            if r.text:
                try:
                    return r.json()
                except:
                    print(f"   Raw Response: {r.text[:200]}")
                    return None
            else:
                print("   Empty response body")
                return None
        else:
            print(f"   Response: {r.text[:200]}")
            return None

    except Exception as e:
        print(f"   Exception: {str(e)}")
        return None

print("="*80)
print(f"DETAILED CHECK: USER ID {TARGET_USER_ID} - ENTRANT ID {TARGET_ENTRANT_ID}")
print("="*80)

# First, let's verify Sameer's token works
print("\n🔍 Step 1: Verify Sameer's token is still valid")
print("-"*80)
result = make_request(PROD_URL, "/v1/user", SAMEER_TOKEN)
if result:
    print(f"✅ Token valid - Logged in as: {result.get('firstName')} {result.get('lastName')} (ID: {result.get('id')})")
else:
    print("❌ Token appears invalid")
    exit(1)

# Try to find user 26927 through different methods
print(f"\n🔍 Step 2: Search for User ID {TARGET_USER_ID}")
print("-"*80)

# Method 1: Check if there's a specific user detail endpoint
print(f"\n📍 Method 1: GET /v1/user/detail/{TARGET_USER_ID}")
make_request(PROD_URL, f"/v1/user/detail/{TARGET_USER_ID}", SAMEER_TOKEN)

# Method 2: Check users endpoint (might list all users - IDOR test)
print(f"\n📍 Method 2: GET /v1/users/{TARGET_USER_ID}")
make_request(PROD_URL, f"/v1/users/{TARGET_USER_ID}", SAMEER_TOKEN)

# Method 3: Check profile endpoint
print(f"\n📍 Method 3: GET /v1/profile/{TARGET_USER_ID}")
make_request(PROD_URL, f"/v1/profile/{TARGET_USER_ID}", SAMEER_TOKEN)

# Try entrant-specific searches
print(f"\n🔍 Step 3: Search for Entrant ID {TARGET_ENTRANT_ID}")
print("-"*80)

# Check waitlist upgrades - this might show entrant info
print(f"\n📍 Method 4: GET /v1/user/waitlist-upgrade")
result = make_request(PROD_URL, "/v1/user/waitlist-upgrade", SAMEER_TOKEN)
if result:
    print(json.dumps(result, indent=2))

# Check all waitlist entries
print(f"\n📍 Method 5: GET /v1/waitlist")
result = make_request(PROD_URL, "/v1/waitlist", SAMEER_TOKEN)
if result:
    print(json.dumps(result, indent=2)[:500])

# Check if entrant is in flight details
print(f"\n📍 Method 6: GET /v1/flight/entrant-detail/{TARGET_ENTRANT_ID}")
result = make_request(PROD_URL, f"/v1/flight/entrant-detail/{TARGET_ENTRANT_ID}", SAMEER_TOKEN)
if result:
    print(json.dumps(result, indent=2))

# Try to get specific entrant info
print(f"\n📍 Method 7: POST /v1/waitlist/entrant (with ID in body)")
result = make_request(PROD_URL, "/v1/waitlist/entrant", SAMEER_TOKEN, "POST", {"entrantId": TARGET_ENTRANT_ID})
if result:
    print(json.dumps(result, indent=2))

print("\n" + "="*80)
print("NOTES:")
print("="*80)
print("If user 26927 is YOUR account, you may need to:")
print("1. Extract the JWT token for that user from the app")
print("2. Use that token instead of Sameer's token")
print("3. The API likely doesn't allow viewing other users (IDOR protection)")
print("\nTo get the token for user 26927:")
print("- Login to the app with that account")
print("- Extract the RKStorage database")
print("- Look for the JWT token in the database")
print("="*80)
