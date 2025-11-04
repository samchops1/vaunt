#!/usr/bin/env python3
"""
Check Ashley's current account status for Stripe IDs
"""

import requests
import json

PROD_URL = "https://vauntapi.flyvaunt.com"
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"

headers = {
    "Authorization": f"Bearer {ASHLEY_TOKEN}",
    "Content-Type": "application/json"
}

print("="*80)
print("ASHLEY'S CURRENT ACCOUNT STATUS - PRODUCTION API")
print("="*80)

r = requests.get(f"{PROD_URL}/v1/user", headers=headers)

if r.status_code == 200:
    data = r.json()
    
    print("\n📊 Full User Profile:")
    print(json.dumps(data, indent=2))
    
    print("\n" + "="*80)
    print("KEY FIELDS:")
    print("="*80)
    
    print(f"\n🆔 User ID: {data.get('id')}")
    print(f"👤 Name: {data.get('firstName')} {data.get('lastName')}")
    print(f"📧 Email: {data.get('email')}")
    
    print(f"\n💳 STRIPE INFORMATION:")
    stripe_customer = data.get('stripeCustomerId')
    stripe_sub = data.get('stripeSubscriptionId')
    
    print(f"   Customer ID: {stripe_customer}")
    print(f"   Subscription ID: {stripe_sub}")
    
    if stripe_customer:
        print(f"\n   ✅ Ashley HAS a Stripe Customer ID!")
    else:
        print(f"\n   ❌ No Stripe Customer ID")
    
    if stripe_sub:
        print(f"   ✅ Ashley HAS a Stripe Subscription ID!")
    else:
        print(f"   ❌ No Stripe Subscription ID")
    
    print(f"\n🎫 MEMBERSHIP STATUS:")
    print(f"   Subscription Status: {data.get('subscriptionStatus')}")
    print(f"   Membership Tier: {data.get('membershipTier')}")
    print(f"   Priority Score: {data.get('priorityScore')}")
    print(f"   License: {data.get('license')}")
    
    if stripe_customer and not data.get('subscriptionStatus'):
        print("\n" + "="*80)
        print("🔍 SITUATION ANALYSIS:")
        print("="*80)
        print("✅ Ashley has Stripe Customer ID (payment account exists)")
        print("❌ But subscriptionStatus is still null (no active subscription)")
        print("\nThis means:")
        print("- Payment account was created")
        print("- But subscription wasn't activated")
        print("- Need to link Stripe subscription to membership")
    
else:
    print(f"\n❌ Error: {r.status_code}")
    print(r.text)
