#!/usr/bin/env python3
"""
Test Production API vs QA API
"""

import requests
import json
from datetime import datetime

# Production API
PROD_URL = "https://vauntapi.flyvaunt.com"
QA_URL = "https://qa-vauntapi.flyvaunt.com"

ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def test_endpoint(base_url, endpoint, token, method="GET", data=None):
    """Test an endpoint"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    url = f"{base_url}{endpoint}"
    
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=data, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        
        result = {
            "status": r.status_code,
            "data": None
        }
        
        if r.status_code == 200 and r.text:
            try:
                result["data"] = r.json()
            except:
                result["data"] = r.text[:200]
        
        return result
    except Exception as e:
        return {"status": "error", "error": str(e)}

print("="*80)
print("PRODUCTION API vs QA API COMPARISON")
print("="*80)

# Test key endpoints on both
test_cases = [
    ("GET", "/v1/user", None, "Get user profile"),
    ("GET", "/v1/flight/current", None, "Get current flights"),
    ("GET", "/v1/subscription/pk", None, "Get Stripe key"),
    ("GET", "/v1/app/upgrade-offer/list", None, "Get upgrade offers"),
    ("PATCH", "/v1/user", {"priorityScore": 2000000000}, "Try to modify priority score"),
]

print("\n" + "="*80)
print("TESTING WITH SAMEER'S TOKEN (Cabin+ Account)")
print("="*80)

for method, endpoint, data, description in test_cases:
    print(f"\n{'='*80}")
    print(f"🧪 {description}")
    print(f"   {method} {endpoint}")
    print(f"{'='*80}")
    
    # Test QA
    print("\n📍 QA API (qa-vauntapi.flyvaunt.com):")
    qa_result = test_endpoint(QA_URL, endpoint, SAMEER_TOKEN, method, data)
    print(f"   Status: {qa_result['status']}")
    
    if qa_result.get('data'):
        if endpoint == "/v1/user" and isinstance(qa_result['data'], dict):
            print(f"   Priority Score: {qa_result['data'].get('priorityScore')}")
            print(f"   Subscription Status: {qa_result['data'].get('subscriptionStatus')}")
        elif endpoint == "/v1/subscription/pk" and isinstance(qa_result['data'], dict):
            pk = qa_result['data'].get('pk', '')
            print(f"   Stripe Key: {pk[:20]}... ({'TEST' if 'test' in pk else 'LIVE'} mode)")
        elif isinstance(qa_result['data'], list):
            print(f"   Response: List with {len(qa_result['data'])} items")
    
    # Test Production
    print("\n📍 PRODUCTION API (vauntapi.flyvaunt.com):")
    prod_result = test_endpoint(PROD_URL, endpoint, SAMEER_TOKEN, method, data)
    print(f"   Status: {prod_result['status']}")
    
    if prod_result.get('data'):
        if endpoint == "/v1/user" and isinstance(prod_result['data'], dict):
            prod_score = prod_result['data'].get('priorityScore')
            qa_score = qa_result.get('data', {}).get('priorityScore')
            print(f"   Priority Score: {prod_score}")
            print(f"   Subscription Status: {prod_result['data'].get('subscriptionStatus')}")
            
            if prod_score != qa_score:
                print(f"\n   🚨 SCORES ARE DIFFERENT!")
                print(f"   QA:   {qa_score}")
                print(f"   PROD: {prod_score}")
                print(f"   Diff: {prod_score - qa_score if (prod_score and qa_score) else 'N/A'}")
        
        elif endpoint == "/v1/subscription/pk" and isinstance(prod_result['data'], dict):
            pk = prod_result['data'].get('pk', '')
            print(f"   Stripe Key: {pk[:20]}... ({'TEST' if 'test' in pk else 'LIVE'} mode)")
        elif isinstance(prod_result['data'], list):
            print(f"   Response: List with {len(prod_result['data'])} items")
    
    # Check if modification worked
    if method == "PATCH" and endpoint == "/v1/user":
        print("\n   🔍 Checking if modification persisted...")
        verify = test_endpoint(PROD_URL, "/v1/user", SAMEER_TOKEN, "GET")
        if verify.get('data'):
            new_score = verify['data'].get('priorityScore')
            print(f"   Score after PATCH: {new_score}")
            if new_score == 2000000000:
                print(f"   ✅ MODIFICATION WORKED ON PRODUCTION!")
            else:
                print(f"   ❌ Modification rejected (score unchanged)")

# Test Ashley's token on production
print("\n\n" + "="*80)
print("TESTING ASHLEY'S TOKEN ON PRODUCTION")
print("="*80)

ashley_qa = test_endpoint(QA_URL, "/v1/user", ASHLEY_TOKEN)
ashley_prod = test_endpoint(PROD_URL, "/v1/user", ASHLEY_TOKEN)

print(f"\nQA API:         Status {ashley_qa['status']}")
print(f"Production API: Status {ashley_prod['status']}")

if ashley_prod['status'] == 200:
    print("\n✅ Ashley's token works on PRODUCTION!")
    data = ashley_prod.get('data', {})
    print(f"   Priority Score: {data.get('priorityScore')}")
    print(f"   Subscription Status: {data.get('subscriptionStatus')}")

print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print("Both QA and Production APIs tested.")
print("Check above for any differences in priority scores or behavior!")
print("="*80)
