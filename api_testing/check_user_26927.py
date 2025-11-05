#!/usr/bin/env python3
"""
Check details for User ID 26927 and Entrant ID 34740
"""

import requests
import json
from datetime import datetime

PROD_URL = "https://vauntapi.flyvaunt.com"
QA_URL = "https://qa-vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

TARGET_USER_ID = 26927
TARGET_ENTRANT_ID = 34740

def timestamp_to_date(ts):
    if not ts:
        return "N/A"
    try:
        # Handle milliseconds
        if ts > 10000000000:
            ts = ts / 1000
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)

def test_endpoint(base_url, endpoint, token, method="GET", data=None):
    """Test an API endpoint"""
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

        return {
            "status": r.status_code,
            "data": r.json() if r.text else None,
            "text": r.text
        }
    except Exception as e:
        return {
            "status": None,
            "error": str(e)
        }

print("="*80)
print(f"CHECKING USER ID {TARGET_USER_ID} - ENTRANT ID {TARGET_ENTRANT_ID}")
print("="*80)

# Test different endpoints that might reveal user information
test_cases = [
    ("Production", PROD_URL),
    ("QA", QA_URL)
]

for env_name, base_url in test_cases:
    print(f"\n{'='*80}")
    print(f"📍 {env_name.upper()} ENVIRONMENT")
    print(f"{'='*80}")

    # Try direct user endpoint
    print(f"\n1️⃣ Testing: GET /v1/user/{TARGET_USER_ID}")
    result = test_endpoint(base_url, f"/v1/user/{TARGET_USER_ID}", SAMEER_TOKEN)

    if result.get("status") == 200:
        print("✅ SUCCESS! User data retrieved:")
        data = result.get("data", {})
        print(json.dumps(data, indent=2))

        # Parse key fields
        print(f"\n📊 KEY INFORMATION:")
        print(f"   User ID: {data.get('id')}")
        print(f"   Name: {data.get('firstName')} {data.get('lastName')}")
        print(f"   Email: {data.get('email')}")
        print(f"   Phone: {data.get('phoneNumber')}")
        print(f"   Subscription Status: {data.get('subscriptionStatus')}")
        print(f"   Priority Score: {data.get('priorityScore')}")

        if data.get('license'):
            lic = data['license']
            print(f"\n🎫 LICENSE:")
            print(f"   ID: {lic.get('id')}")
            print(f"   Tier: {lic.get('membershipTier', {}).get('name')}")
            print(f"   Expires: {timestamp_to_date(lic.get('expiresAt'))}")

        if data.get('stripeCustomerId'):
            print(f"\n💳 STRIPE:")
            print(f"   Customer: {data.get('stripeCustomerId')}")
            print(f"   Subscription: {data.get('stripeSubscriptionId')}")

    elif result.get("status") == 403:
        print("❌ 403 Forbidden - IDOR protection is working (good security!)")
    elif result.get("status") == 404:
        print("❌ 404 Not Found - Endpoint doesn't support user ID parameter")
    elif result.get("status") == 401:
        print("❌ 401 Unauthorized - Token invalid")
    else:
        print(f"❌ Status: {result.get('status')} - {result.get('error', 'Unknown error')}")

    # Try entrant endpoint
    print(f"\n2️⃣ Testing: GET /v1/entrant/{TARGET_ENTRANT_ID}")
    result = test_endpoint(base_url, f"/v1/entrant/{TARGET_ENTRANT_ID}", SAMEER_TOKEN)

    if result.get("status") == 200:
        print("✅ SUCCESS! Entrant data retrieved:")
        data = result.get("data", {})
        print(json.dumps(data, indent=2))
    elif result.get("status") == 404:
        print("❌ 404 Not Found")
    else:
        print(f"❌ Status: {result.get('status')}")

    # Try flight entrant endpoint
    print(f"\n3️⃣ Testing: GET /v1/flight/entrant/{TARGET_ENTRANT_ID}")
    result = test_endpoint(base_url, f"/v1/flight/entrant/{TARGET_ENTRANT_ID}", SAMEER_TOKEN)

    if result.get("status") == 200:
        print("✅ SUCCESS! Flight entrant data retrieved:")
        data = result.get("data", {})
        print(json.dumps(data, indent=2))
    elif result.get("status") == 404:
        print("❌ 404 Not Found")
    else:
        print(f"❌ Status: {result.get('status')}")

    # Try waitlist endpoint
    print(f"\n4️⃣ Testing: GET /v1/waitlist/entrant/{TARGET_ENTRANT_ID}")
    result = test_endpoint(base_url, f"/v1/waitlist/entrant/{TARGET_ENTRANT_ID}", SAMEER_TOKEN)

    if result.get("status") == 200:
        print("✅ SUCCESS! Waitlist entrant data retrieved:")
        data = result.get("data", {})
        print(json.dumps(data, indent=2))
    elif result.get("status") == 404:
        print("❌ 404 Not Found")
    else:
        print(f"❌ Status: {result.get('status')}")

print("\n" + "="*80)
print("TESTING COMPLETE")
print("="*80)
