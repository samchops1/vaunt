#!/usr/bin/env python3
"""
Restore Sameer's profile to normal after SQL injection testing
"""

import requests

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

print("Restoring Sameer's profile data...")

# Check current state
r = requests.get(f"{API_URL}/v1/user", headers=headers)
current = r.json()

print(f"\nCurrent state:")
print(f"  firstName: {current.get('firstName')}")
print(f"  lastName: {current.get('lastName')}")
print(f"  email: {current.get('email')}")

# Restore to normal
restore_data = {
    "firstName": "Sameer",
    "lastName": "Chopra",
    "email": "sameer.s.chopra@gmail.com"
}

print(f"\nRestoring to:")
print(f"  firstName: {restore_data['firstName']}")
print(f"  lastName: {restore_data['lastName']}")
print(f"  email: {restore_data['email']}")

r = requests.patch(f"{API_URL}/v1/user", headers=headers, json=restore_data)

if r.status_code == 200:
    print("\n✅ Profile restored successfully!")

    # Verify
    r = requests.get(f"{API_URL}/v1/user", headers=headers)
    restored = r.json()

    print(f"\nVerified state:")
    print(f"  firstName: {restored.get('firstName')}")
    print(f"  lastName: {restored.get('lastName')}")
    print(f"  email: {restored.get('email')}")
    print(f"  priorityScore: {restored.get('priorityScore')}")
else:
    print(f"\n❌ Failed to restore: {r.status_code}")
    print(r.text)
