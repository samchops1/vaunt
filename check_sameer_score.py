#!/usr/bin/env python3
"""
Check Sameer's current priority score on production API
"""

import requests
import json
from datetime import datetime

PROD_URL = "https://vauntapi.flyvaunt.com"
QA_URL = "https://qa-vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def timestamp_to_date(ts):
    if not ts:
        return "N/A"
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)

def get_user_data(base_url):
    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}
    r = requests.get(f"{base_url}/v1/user", headers=headers)
    if r.status_code == 200:
        return r.json()
    return None

print("="*80)
print("SAMEER CHOPRA - PRIORITY SCORE CHECK")
print("="*80)

# Get data from both environments
prod_data = get_user_data(PROD_URL)
qa_data = get_user_data(QA_URL)

print("\n📍 PRODUCTION API (vauntapi.flyvaunt.com)")
print("="*80)
if prod_data:
    score = prod_data.get('priorityScore')
    print(f"Priority Score: {score}")
    print(f"Date Equivalent: {timestamp_to_date(score)}")
    print(f"Subscription Status: {prod_data.get('subscriptionStatus')}")
    print(f"Membership Tier: {prod_data.get('membershipTier')}")
    print(f"Stripe Customer: {prod_data.get('stripeCustomerId')}")
    print(f"Stripe Subscription: {prod_data.get('stripeSubscriptionId')}")
    
    if prod_data.get('license'):
        license_data = prod_data['license']
        print(f"\nLicense:")
        print(f"  ID: {license_data.get('id')}")
        print(f"  Expires: {timestamp_to_date(license_data.get('expiresAt', 0) / 1000)}")
        print(f"  Tier: {license_data.get('membershipTier', {}).get('name')}")
else:
    print("❌ Could not get data")

print("\n📍 QA API (qa-vauntapi.flyvaunt.com)")
print("="*80)
if qa_data:
    score = qa_data.get('priorityScore')
    print(f"Priority Score: {score}")
    print(f"Date Equivalent: {timestamp_to_date(score)}")
    print(f"Subscription Status: {qa_data.get('subscriptionStatus')}")
else:
    print("❌ Could not get data")

print("\n" + "="*80)
print("COMPARISON")
print("="*80)

if prod_data and qa_data:
    prod_score = prod_data.get('priorityScore')
    qa_score = qa_data.get('priorityScore')
    
    print(f"\nProduction: {prod_score} ({timestamp_to_date(prod_score)})")
    print(f"QA:         {qa_score} ({timestamp_to_date(qa_score)})")
    print(f"Difference: {prod_score - qa_score:,} seconds")
    print(f"            {(prod_score - qa_score) / 86400:.1f} days")
    print(f"            {(prod_score - qa_score) / 31536000:.2f} years")
    
    if prod_score == qa_score:
        print("\n✅ Scores are IDENTICAL")
    else:
        print(f"\n⚠️  Scores are DIFFERENT")
        print(f"Production is {'HIGHER' if prod_score > qa_score else 'LOWER'} than QA")

print("\n" + "="*80)
