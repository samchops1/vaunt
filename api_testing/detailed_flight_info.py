#!/usr/bin/env python3
"""
Get detailed flight history and upcoming flight info
"""

import requests
import json
from datetime import datetime

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

headers = {
    "Authorization": f"Bearer {SAMEER_TOKEN}",
    "Content-Type": "application/json"
}

def timestamp_to_date(ts):
    if not ts:
        return "N/A"
    try:
        if ts > 10000000000:
            ts = ts / 1000
        dt = datetime.fromtimestamp(ts)
        return dt.strftime('%b %d, %Y @ %I:%M %p')
    except:
        return str(ts)

print("="*80)
print("SAMEER'S COMPLETE FLIGHT INFORMATION")
print("="*80)

# Get flight history
print("\n📜 FLIGHT HISTORY:")
print("="*80)

r = requests.get(f"{PROD_URL}/v1/flight-history", headers=headers)
if r.status_code == 200:
    history = r.json()
    
    flights = history.get('data', [])
    total_count = history.get('totalCount', len(flights))
    
    print(f"\n✅ Total flights in history: {total_count}")
    print(f"   Flights returned: {len(flights)}\n")
    
    if flights:
        for i, flight in enumerate(flights, 1):
            print(f"{'='*80}")
            print(f"FLIGHT #{i} - ID: {flight.get('id')}")
            print(f"{'='*80}")
            
            # Route
            depart = flight.get('departAirport', {})
            arrive = flight.get('arriveAirport', {})
            print(f"Route: {depart.get('code')} → {arrive.get('code')}")
            print(f"       {depart.get('city', 'N/A')} → {arrive.get('city', 'N/A')}")
            
            # Time
            depart_time = flight.get('departDateTimeLocal')
            print(f"Departure: {depart_time}")
            
            # Status
            status_id = flight.get('status')
            status_map = {1: 'OPEN', 2: 'CLOSED', 3: 'CANCELLED'}
            status = status_map.get(status_id, f'UNKNOWN({status_id})')
            print(f"Status: {status}")
            
            # Entrants
            entrants = flight.get('numberOfEntrants', 0)
            print(f"Waitlist size: {entrants} people")
            
            # Your position
            user_data = flight.get('userData', {})
            queue_pos = user_data.get('queuePosition')
            if queue_pos is not None:
                print(f"Your position: #{queue_pos}")
                if queue_pos == 0:
                    print("   🏆 YOU WON THIS FLIGHT!")
            
            # Winner info
            winner = flight.get('winner')
            if winner:
                if isinstance(winner, dict):
                    winner_name = winner.get('firstName', 'Unknown')
                    print(f"Winner: {winner_name}")
                else:
                    print(f"Winner: User ID {winner}")
                    if winner == 20254:
                        print(f"   🏆 YOU WON THIS FLIGHT!")
            
            print()
    else:
        print("No flight history found")

# Get current/upcoming flights
print("\n" + "="*80)
print("📅 CURRENT/UPCOMING FLIGHTS:")
print("="*80)

r = requests.get(f"{PROD_URL}/v1/flight/current", headers=headers)
if r.status_code == 200:
    flights = r.json()
    
    # Separate by status
    open_flights = []
    pending_flights = []
    closed_flights = []
    
    for flight in flights:
        status = flight.get('status', {}).get('label', 'UNKNOWN')
        if status == 'OPEN':
            open_flights.append(flight)
        elif status == 'PENDING':
            pending_flights.append(flight)
        elif status == 'CLOSED':
            closed_flights.append(flight)
    
    print(f"\n📊 Summary:")
    print(f"   OPEN flights: {len(open_flights)}")
    print(f"   PENDING flights: {len(pending_flights)}")
    print(f"   CLOSED flights: {len(closed_flights)}")
    print(f"   Total: {len(flights)}")
    
    # Show OPEN flights
    if open_flights:
        print(f"\n🟢 OPEN FLIGHTS (Can join waitlist):")
        for flight in open_flights:
            print(f"\n   Flight {flight.get('id')}: {flight.get('departAirport', {}).get('code')} → {flight.get('arriveAirport', {}).get('code')}")
            print(f"   Departs: {flight.get('departDateTimeLocal')}")
            print(f"   Waitlist: {flight.get('waitlistCount', 0)} people")
    
    # Show PENDING flights
    if pending_flights:
        print(f"\n🟡 PENDING FLIGHTS (Winner selection in progress):")
        for flight in pending_flights:
            flight_id = flight.get('id')
            depart = flight.get('departAirport', {}).get('code')
            arrive = flight.get('arriveAirport', {}).get('code')
            
            print(f"\n   Flight {flight_id}: {depart} → {arrive}")
            print(f"   Departs: {flight.get('departDateTimeLocal')}")
            
            # Check your position
            entrants = flight.get('entrants', [])
            for entrant in entrants:
                if entrant.get('id') == 20254:
                    pos = entrant.get('queuePosition')
                    print(f"   🎯 Your waitlist position: #{pos}")
                    
                    if pos == 0:
                        print(f"   🏆 YOU ARE #1 IN LINE!")
                    elif pos == 1:
                        print(f"   🥈 You are #2 (standby)")
                    else:
                        print(f"   ⏳ You are #{pos + 1}")
            
            # Show winner if selected
            winner_id = flight.get('winner')
            if winner_id:
                if winner_id == 20254:
                    print(f"   ✅ YOU WON THIS FLIGHT!")
                else:
                    print(f"   ❌ Someone else won (User {winner_id})")

# Summary
print("\n" + "="*80)
print("SUMMARY")
print("="*80)

r_history = requests.get(f"{PROD_URL}/v1/flight-history", headers=headers)
if r_history.status_code == 200:
    history_data = r_history.json()
    total = history_data.get('totalCount', 0)
    print(f"\n📊 Total flights you've been involved with: {total}")

r_current = requests.get(f"{PROD_URL}/v1/flight/current", headers=headers)
if r_current.status_code == 200:
    current_flights = r_current.json()
    pending = [f for f in current_flights if f.get('status', {}).get('label') == 'PENDING']
    open_fl = [f for f in current_flights if f.get('status', {}).get('label') == 'OPEN']
    
    print(f"📅 Active waitlist entries: {len(pending)}")
    print(f"🆕 Available flights to join: {len(open_fl)}")

print("\n" + "="*80)
