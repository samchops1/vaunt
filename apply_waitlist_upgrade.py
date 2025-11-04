#!/usr/bin/env python3
"""
Try to apply waitlist upgrade to Flight 8795
"""

import requests
import json
import time

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

FLIGHT_ID = 8795

# Free upgrades to try
FREE_UPGRADES = [896, 5978]
PAID_UPGRADES = [456, 5484]

headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

def check_position():
    r = requests.get(f"{PROD_URL}/v1/flight/current", headers=headers)
    if r.status_code == 200:
        for flight in r.json():
            if flight.get('id') == FLIGHT_ID:
                entrants = flight.get('entrants', [])
                for ent in entrants:
                    if ent.get('id') == 20254:
                        return ent.get('queuePosition')
    return None

print("="*80)
print("APPLYING WAITLIST UPGRADE TO FLIGHT 8795")
print("="*80)

baseline_pos = check_position()
print(f"\n📊 Current position: #{baseline_pos}\n")

# Try different endpoints to apply upgrade
upgrade_endpoints = [
    ("POST", f"/v1/waitlist-upgrade/use", {"upgradeId": FREE_UPGRADES[0], "flightId": FLIGHT_ID}),
    ("POST", f"/v1/upgrade/apply", {"upgradeId": FREE_UPGRADES[0], "flightId": FLIGHT_ID}),
    ("POST", f"/v1/priority/apply", {"upgradeId": FREE_UPGRADES[0], "flightId": FLIGHT_ID}),
    ("POST", f"/v1/flight/{FLIGHT_ID}/apply-upgrade", {"upgradeId": FREE_UPGRADES[0]}),
    ("PATCH", f"/v1/user/waitlist-upgrades/{FREE_UPGRADES[0]}", {"usedOn": FLIGHT_ID}),
    ("POST", f"/v1/app/upgrade-offer/purchase", {"offerId": 2, "flightId": FLIGHT_ID}),
]

print("Testing upgrade application endpoints...\n")

for method, endpoint, data in upgrade_endpoints:
    url = f"{PROD_URL}{endpoint}"
    
    try:
        if method == "POST":
            r = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=data, timeout=10)
        
        print(f"{method} {endpoint}")
        print(f"Status: {r.status_code}")
        
        if r.status_code == 200:
            print("✅ Request accepted!")
            
            try:
                resp = r.json()
                print(f"Response: {json.dumps(resp, indent=2)[:300]}")
            except:
                print(f"Response: {r.text[:200]}")
            
            # Check if position changed
            time.sleep(1)
            new_pos = check_position()
            
            if new_pos != baseline_pos:
                print(f"\n🚨🚨🚨 POSITION CHANGED!")
                print(f"Before: #{baseline_pos}")
                print(f"After: #{new_pos}")
                print(f"✅ UPGRADE APPLIED SUCCESSFULLY!\n")
                baseline_pos = new_pos
                break
            else:
                print(f"❌ Position unchanged (still #{new_pos})\n")
        
        elif r.status_code == 400:
            print(f"⚠️  Bad Request")
            try:
                error = r.json()
                print(f"Error: {error}\n")
            except:
                print(f"Error: {r.text[:200]}\n")
        
        elif r.status_code == 404:
            print(f"❌ Not found\n")
        
        else:
            print(f"❌ Failed: {r.status_code}\n")
    
    except Exception as e:
        print(f"❌ Error: {str(e)[:100]}\n")

# Check final position
print("="*80)
print("FINAL STATUS")
print("="*80)

final_pos = check_position()
print(f"\nFinal position: #{final_pos}")

if final_pos < baseline_pos:
    print(f"✅✅✅ SUCCESS! Moved from #{baseline_pos} to #{final_pos}!")
elif final_pos == 0:
    print(f"✅✅✅ YOU ARE NOW #1 IN LINE!")
else:
    print(f"❌ No change - still at position #{final_pos}")

# Show remaining upgrades
print("\n" + "="*80)
print("REMAINING UPGRADES")
print("="*80)

r = requests.get(f"{PROD_URL}/v1/user", headers=headers)
if r.status_code == 200:
    user = r.json()
    upgrades = user.get('waitlistUpgrades', [])
    
    unused = [u for u in upgrades if u.get('usedOn') is None]
    
    print(f"\nUnused upgrades: {len(unused)}")
    for u in unused:
        cost = u.get('costToUse', 0) / 100
        name = u.get('priorityUpgradeTier', {}).get('name', 'Unknown')
        print(f"  - Upgrade #{u['id']}: {name} (${cost:.2f})")
