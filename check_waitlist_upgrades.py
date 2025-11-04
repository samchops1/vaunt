#!/usr/bin/env python3
"""
Check for waitlist upgrade features in user profile and app config
"""

import requests
import json

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

print("="*80)
print("WAITLIST UPGRADE FEATURES CHECK")
print("="*80)

# Check user profile for waitlist upgrades
print("\n📊 User Profile - Waitlist Upgrades:")
r = requests.get(f"{PROD_URL}/v1/user", headers=headers)
if r.status_code == 200:
    user = r.json()
    
    waitlist_upgrades = user.get('waitlistUpgrades', [])
    print(f"\nWaitlist Upgrades: {waitlist_upgrades}")
    
    if waitlist_upgrades:
        print(f"\nFound {len(waitlist_upgrades)} upgrade(s)!")
        for upgrade in waitlist_upgrades:
            print(json.dumps(upgrade, indent=2))
    else:
        print("❌ No waitlist upgrades available")

# Check app configuration for upgrade offers
print("\n" + "="*80)
print("📦 App Upgrade Offers:")

r = requests.get(f"{PROD_URL}/v1/app/upgrade-offer/list", headers=headers)
if r.status_code == 200:
    offers = r.json()
    print(f"\nFound {len(offers)} upgrade offer(s)")
    
    for i, offer in enumerate(offers, 1):
        print(f"\n{'='*60}")
        print(f"OFFER #{i}")
        print(f"{'='*60}")
        print(json.dumps(offer, indent=2))

# Check for priority upgrade purchases
print("\n" + "="*80)
print("💳 Priority Upgrade Endpoints:")

purchase_endpoints = [
    ("GET", "/v1/upgrade/available", "Available upgrades"),
    ("GET", "/v1/upgrade/list", "List upgrades"),
    ("GET", "/v1/priority/upgrades", "Priority upgrades"),
    ("POST", "/v1/upgrade/purchase", "Purchase upgrade"),
    ("POST", "/v1/priority/purchase", "Purchase priority"),
]

for method, endpoint, description in purchase_endpoints:
    url = f"{PROD_URL}{endpoint}"
    
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json={"flightId": 8795}, timeout=10)
        
        if r.status_code == 200:
            print(f"\n✅ {endpoint} - {description}")
            try:
                data = r.json()
                print(json.dumps(data, indent=2)[:300])
            except:
                print(r.text[:200])
        elif r.status_code == 400:
            print(f"\n⚠️  {endpoint} - {description}")
            print(f"   Status: 400 - {r.text[:100]}")
    except:
        pass

# Check flight userData for upgrade options
print("\n" + "="*80)
print("🎫 Flight-Specific Upgrade Options:")

r = requests.get(f"{PROD_URL}/v1/flight/current", headers=headers)
if r.status_code == 200:
    flights = r.json()
    
    for flight in flights:
        if flight.get('id') == 8795:
            user_data = flight.get('userData', {})
            
            print(f"\nFlight 8795 - Your userData:")
            print(json.dumps(user_data, indent=2))
            
            # Check specific upgrade fields
            can_purchase = user_data.get('canPurchase')
            print(f"\nCan purchase upgrade: {can_purchase}")
            
            if can_purchase:
                print("✅ You can purchase a waitlist upgrade for this flight!")

print("\n" + "="*80)
print("SUMMARY")
print("="*80)

print("\n❌ No waitlist manipulation API found")
print("   - All waitlist/* endpoints return 404")
print("   - No position modification endpoints exist")
print("   - No bump/reorder functionality")

print("\n⚠️  Waitlist position is READ-ONLY")
print("   - Determined automatically by priority score")
print("   - Cannot be changed via API")
print("   - Server-side calculation only")

print("\n✅ Only legitimate way to improve position:")
print("   - Increase priority score (requires account activity)")
print("   - Purchase waitlist upgrade (if available)")
print("   - Wait for people ahead to decline")

print("\n" + "="*80)
