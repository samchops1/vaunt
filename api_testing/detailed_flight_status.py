#!/usr/bin/env python3
"""
Get detailed status of all current flights for Sameer
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
print("DETAILED FLIGHT STATUS - SAMEER CHOPRA")
print("="*80)

r = requests.get(f"{PROD_URL}/v1/flight/current", headers=headers)

if r.status_code == 200:
    flights = r.json()

    print(f"\n📊 Total Flights: {len(flights)}")

    waitlist_count = 0
    winner_count = 0
    closed_count = 0

    for i, flight in enumerate(flights, 1):
        print(f"\n{'='*80}")
        print(f"FLIGHT #{i} - ID: {flight.get('id')}")
        print(f"{'='*80}")

        print(f"Route: {flight.get('origin')} → {flight.get('destination')}")
        print(f"Date: {flight.get('departureDate')}")
        print(f"Status: {flight.get('status')}")
        print(f"Winner ID: {flight.get('winner')}")
        print(f"Winner Confirmed: {flight.get('isConfirmedByWinner', False)}")

        user_data = flight.get('userData', {})
        print(f"\n📋 Your Status:")
        print(f"   On Waitlist: {user_data.get('isOnWaitlist', False)}")
        print(f"   Is Winner: {user_data.get('isWinner', False)}")
        print(f"   Queue Position: {user_data.get('queuePosition', 'N/A')}")
        print(f"   Can Join Waitlist: {user_data.get('canJoinWaitlist', False)}")

        if user_data.get('isOnWaitlist'):
            waitlist_count += 1

        if user_data.get('isWinner'):
            winner_count += 1

        if flight.get('status') == 'CLOSED':
            closed_count += 1

        # Show entrants
        entrants = flight.get('entrants', [])
        print(f"\n👥 Entrants: {len(entrants)}")

        # Show first 5 entrants
        for j, entrant in enumerate(entrants[:5]):
            position = entrant.get('queuePosition', 'N/A')
            is_you = entrant.get('id') == 20254
            marker = " ← YOU" if is_you else ""
            print(f"   #{position}: User {entrant.get('id')}{marker}")

        if len(entrants) > 5:
            print(f"   ... and {len(entrants) - 5} more")

        # Check if you're in entrants
        your_entrant = None
        for entrant in entrants:
            if entrant.get('id') == 20254:
                your_entrant = entrant
                break

        if your_entrant:
            print(f"\n🔍 Your Entrant Details:")
            print(json.dumps(your_entrant, indent=2))

    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"Total Flights: {len(flights)}")
    print(f"On Waitlist: {waitlist_count}")
    print(f"Won Flights: {winner_count}")
    print(f"Closed Flights: {closed_count}")

    # Detailed waitlist analysis
    if waitlist_count == 0:
        print(f"\n⚠️  NOT ON ANY WAITLISTS")
        print(f"\nPossible reasons:")
        print(f"1. All flights you entered have already selected winners")
        print(f"2. All flights are closed")
        print(f"3. You won all the flights")

    # Check why can't join new flights
    can_join_any = False
    for flight in flights:
        if flight.get('userData', {}).get('canJoinWaitlist'):
            can_join_any = True
            break

    if not can_join_any:
        print(f"\n⚠️  CANNOT JOIN ANY NEW WAITLISTS")
        print(f"\nReasons per flight:")

        for flight in flights:
            fid = flight.get('id')
            status = flight.get('status')
            can_join = flight.get('userData', {}).get('canJoinWaitlist', False)
            is_on = flight.get('userData', {}).get('isOnWaitlist', False)

            print(f"\n   Flight {fid} ({flight.get('origin')} → {flight.get('destination')}):")
            print(f"   - Status: {status}")
            print(f"   - Already on: {is_on}")
            print(f"   - Can join: {can_join}")

            if status == 'CLOSED':
                print(f"   → Flight is CLOSED")
            elif is_on:
                print(f"   → Already on this flight")

else:
    print(f"❌ Error: {r.status_code}")
    print(r.text)

print("\n" + "="*80)
