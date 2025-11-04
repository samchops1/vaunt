#!/usr/bin/env python3
"""
Test 1: Trial membership activation
Test 2: Stripe webhook simulation
"""

import requests
import json
import time

PROD_URL = "https://vauntapi.flyvaunt.com"
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"

def make_request(method, endpoint, data=None, extra_headers=None):
    headers = {
        "Authorization": f"Bearer {ASHLEY_TOKEN}",
        "Content-Type": "application/json"
    }
    
    if extra_headers:
        headers.update(extra_headers)
    
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
        
        result = {"status": r.status_code, "data": None, "text": None}
        
        if r.text:
            result["text"] = r.text[:500]
            try:
                result["data"] = r.json()
            except:
                pass
        
        return result
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_membership():
    r = make_request("GET", "/v1/user")
    if r['status'] == 200 and r['data']:
        return {
            "subscriptionStatus": r['data'].get('subscriptionStatus'),
            "stripeSubscriptionId": r['data'].get('stripeSubscriptionId'),
            "license": r['data'].get('license')
        }
    return None

print("="*80)
print("PART 1: TRIAL MEMBERSHIP TESTING")
print("="*80)

baseline = check_membership()
print(f"\nBaseline: subscriptionStatus = {baseline['subscriptionStatus']}\n")

trial_endpoints = [
    # Trial activation
    ("POST", "/v1/trial/start", None),
    ("POST", "/v1/trial/activate", None),
    ("POST", "/v1/subscription/trial", {"tier": "cabin+"}),
    ("POST", "/v1/subscription/trial/start", {"tier": "cabin+"}),
    ("POST", "/v1/subscription/trial/claim", None),
    ("POST", "/v1/user/trial", {"membershipTier": "cabin+"}),
    
    # Promo/referral codes that might grant trial
    ("POST", "/v1/promo/apply", {"code": "TRIAL"}),
    ("POST", "/v1/promo/redeem", {"code": "FREETRIAL"}),
    ("POST", "/v1/referral/claim", {"code": "TRIAL2025"}),
    
    # Trial info endpoints
    ("GET", "/v1/trial/available", None),
    ("GET", "/v1/trial/status", None),
    ("GET", "/v1/user/trial-eligibility", None),
]

print("Testing trial endpoints...\n")

for method, endpoint, data in trial_endpoints:
    result = make_request(method, endpoint, data)
    
    if result['status'] == 200:
        print(f"✅ {result['status']} - {method} {endpoint}")
        
        # Check for changes
        new_status = check_membership()
        if new_status != baseline:
            print(f"   🚨 MEMBERSHIP CHANGED!")
            print(f"   Status: {baseline['subscriptionStatus']} → {new_status['subscriptionStatus']}")
            baseline = new_status
        else:
            if result['data']:
                print(f"   Response: {json.dumps(result['data'])[:100]}")
    
    elif result['status'] == 404:
        print(f"❌ 404 - {method} {endpoint}")
    elif result['status'] == 400:
        print(f"⚠️  400 - {method} {endpoint}")
        if result['data']:
            print(f"   Error: {result['data']}")
    else:
        print(f"❌ {result['status']} - {method} {endpoint}")

print("\n" + "="*80)
print("PART 2: STRIPE WEBHOOK SIMULATION")
print("="*80)

# Common Stripe webhook endpoints
webhook_endpoints = [
    "/webhook/stripe",
    "/webhooks/stripe",
    "/api/webhook/stripe",
    "/api/webhooks/stripe",
    "/v1/webhook/stripe",
    "/v1/webhooks/stripe",
    "/stripe/webhook",
    "/stripe/webhooks",
]

# Stripe webhook events we want to simulate
webhook_events = [
    {
        "name": "customer.subscription.created",
        "payload": {
            "id": "evt_test_123",
            "object": "event",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_test_ashley",
                    "customer": "cus_TMQ5kN5yjgYTLR",
                    "status": "active",
                    "metadata": {
                        "userId": "171208",
                        "tier": "cabin+"
                    }
                }
            }
        }
    },
    {
        "name": "checkout.session.completed",
        "payload": {
            "id": "evt_test_456",
            "object": "event",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_ashley",
                    "customer": "cus_TMQ5kN5yjgYTLR",
                    "subscription": "sub_test_ashley",
                    "payment_status": "paid",
                    "metadata": {
                        "userId": "171208"
                    }
                }
            }
        }
    }
]

print("\nTesting Stripe webhook endpoints...\n")

for endpoint in webhook_endpoints:
    print(f"\n{'='*60}")
    print(f"Testing: {endpoint}")
    print(f"{'='*60}")
    
    for event in webhook_events:
        # Try without signature (might be rejected)
        result = make_request("POST", endpoint, event['payload'])
        
        print(f"\n  Event: {event['name']}")
        print(f"  Status: {result['status']}")
        
        if result['status'] == 200:
            print(f"  ✅ Webhook accepted!")
            
            # Check if membership changed
            time.sleep(1)
            new_status = check_membership()
            if new_status != baseline:
                print(f"  🚨🚨🚨 MEMBERSHIP ACTIVATED!")
                print(f"  Status: {baseline['subscriptionStatus']} → {new_status['subscriptionStatus']}")
                print(f"  Subscription: {new_status['stripeSubscriptionId']}")
                baseline = new_status
            else:
                print(f"  Response: {result['text'][:100] if result['text'] else 'Empty'}")
        
        elif result['status'] == 400:
            print(f"  ⚠️  400 Bad Request")
            if result['data']:
                print(f"  Error: {result['data']}")
        
        elif result['status'] == 401:
            print(f"  ⚠️  401 Unauthorized (might need Stripe signature)")
        
        elif result['status'] == 404:
            print(f"  ❌ 404 Not Found")
            break  # Skip other events for this endpoint
        
        else:
            print(f"  ❌ {result['status']}")

print("\n" + "="*80)
print("FINAL RESULTS")
print("="*80)

final = check_membership()
print(f"\nSubscription Status: {final['subscriptionStatus']}")
print(f"Subscription ID: {final['stripeSubscriptionId']}")
print(f"License: {final['license']}")

if final['subscriptionStatus'] == 3:
    print("\n✅✅✅ SUCCESS! Ashley has Cabin+ membership!")
elif final['subscriptionStatus']:
    print(f"\n⚠️  Partial success - Status changed to {final['subscriptionStatus']}")
else:
    print("\n❌ No trial or webhook simulation worked")
