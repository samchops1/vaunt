#!/usr/bin/env python3
"""
Check Sameer's flight history and upcoming flights
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
        return dt.strftime('%b %d, %Y %I:%M %p')
    except:
        return str(ts)

print("="*80)
print("SAMEER'S FLIGHT HISTORY & UPCOMING FLIGHTS")
print("="*80)

# Check user profile for flight count
print("\n📊 User Profile:")
r = requests.get(f"{PROD_URL}/v1/user", headers=headers)
if r.status_code == 200:
    user = r.json()
    print(f"Last Flight Purchase: {user.get('lastFlightPurchase')}")
    print(f"Successful Referrals: {user.get('successfulReferralCount')}")
    
# Get current flights (history)
print("\n" + "="*80)
print("FLIGHT HISTORY (Past Flights)")
print("="*80)

r = requests.get(f"{PROD_URL}/v1/flight/current", headers=headers)
if r.status_code == 200:
    flights = r.json()
    print(f"\nTotal flights in history: {len(flights)}")
    
    completed_flights = []
    for flight in flights:
        status = flight.get('status', {}).get('label', 'UNKNOWN')
        if status == 'CLOSED':
            # Check if Sameer was on this flight
            passengers = flight.get('passengers', [])
            sameer_flew = any(p.get('user') == 20254 for p in passengers)
            
            if sameer_flew:
                completed_flights.append({
                    'id': flight.get('id'),
                    'depart': flight.get('departAirport', {}).get('code'),
                    'arrive': flight.get('arriveAirport', {}).get('code'),
                    'date': flight.get('departDateTimeLocal'),
                    'winner': flight.get('winner') == 20254
                })
    
    print(f"Flights Sameer actually flew on: {len(completed_flights)}")
    
    print("\nFlight Details:")
    for i, f in enumerate(completed_flights, 1):
        winner_icon = "🏆" if f['winner'] else "  "
        print(f"{i}. {winner_icon} Flight {f['id']}: {f['depart']} → {f['arrive']} on {f['date']}")

# Check for upcoming flights
print("\n" + "="*80)
print("UPCOMING FLIGHTS")
print("="*80)

endpoints_to_check = [
    ("/v1/flight/upcoming", "Upcoming flights"),
    ("/v1/flight/future", "Future flights"),
    ("/v1/user/bookings", "User bookings"),
    ("/v1/flight/scheduled", "Scheduled flights"),
    ("/v1/waitlist/active", "Active waitlist entries"),
]

found_upcoming = False

for endpoint, description in endpoints_to_check:
    r = requests.get(f"{PROD_URL}{endpoint}", headers=headers)
    
    if r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list) and len(data) > 0:
                print(f"\n✅ {description} ({endpoint})")
                print(f"   Found {len(data)} item(s)")
                
                # Show first item
                print(f"\n   First item:")
                print(json.dumps(data[0], indent=4)[:500])
                found_upcoming = True
            elif isinstance(data, list):
                print(f"❌ {description} - No data (empty list)")
        except:
            pass
    elif r.status_code == 404:
        print(f"❌ {description} - Endpoint not found")

# Check flight history endpoint
print("\n" + "="*80)
print("FLIGHT STATISTICS")
print("="*80)

history_endpoints = [
    "/v1/flight-history",
    "/v1/user/flight-history",
    "/v1/user/flights/history",
    "/v1/user/stats",
    "/v1/user/flight-stats",
]

for endpoint in history_endpoints:
    r = requests.get(f"{PROD_URL}{endpoint}", headers=headers)
    
    if r.status_code == 200:
        try:
            data = r.json()
            print(f"\n✅ {endpoint}")
            print(json.dumps(data, indent=2)[:500])
        except:
            print(f"\n✅ {endpoint} - {r.text[:200]}")

# Check waitlist status for current flights
print("\n" + "="*80)
print("CURRENT WAITLIST POSITIONS")
print("="*80)

r = requests.get(f"{PROD_URL}/v1/flight/current", headers=headers)
if r.status_code == 200:
    flights = r.json()
    
    open_flights = [f for f in flights if f.get('status', {}).get('label') != 'CLOSED']
    
    if open_flights:
        print(f"\nFound {len(open_flights)} OPEN flights!")
        for flight in open_flights:
            print(f"\nFlight {flight.get('id')}: {flight.get('departAirport', {}).get('code')} → {flight.get('arriveAirport', {}).get('code')}")
            print(f"Departure: {flight.get('departDateTimeLocal')}")
            print(f"Status: {flight.get('status', {}).get('label')}")
            
            entrants = flight.get('entrants', [])
            for entrant in entrants:
                if entrant.get('id') == 20254:
                    print(f"Your position: #{entrant.get('queuePosition')}")
    else:
        print("\n❌ No open flights - all are CLOSED")

print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"\nFlights completed: {len(completed_flights)}")
print(f"Upcoming flights: {'Found some!' if found_upcoming else 'None found'}")
print("="*80)
