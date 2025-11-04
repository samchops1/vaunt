#!/usr/bin/env python3
"""
Check available flights and their times
"""

import requests
import json
from datetime import datetime

PROD_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"

def timestamp_to_date(ts):
    """Convert timestamp to readable date"""
    if not ts:
        return "N/A"
    try:
        # Handle both seconds and milliseconds
        if ts > 10000000000:
            ts = ts / 1000
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)

def get_flights(token, account_name):
    """Get flights for an account"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print(f"\n{'='*80}")
    print(f"FLIGHTS FOR: {account_name}")
    print(f"{'='*80}\n")
    
    # Get current flights
    r = requests.get(f"{PROD_URL}/v1/flight/current", headers=headers)
    
    if r.status_code != 200:
        print(f"❌ Error: {r.status_code}")
        return
    
    flights = r.json()
    print(f"Found {len(flights)} flights\n")
    
    for i, flight in enumerate(flights, 1):
        print(f"{'='*80}")
        print(f"FLIGHT #{i}")
        print(f"{'='*80}")
        
        # Flight ID and route
        print(f"Flight ID: {flight.get('id')}")
        print(f"Route: {flight.get('departureAirport')} → {flight.get('arrivalAirport')}")
        
        # Times
        departure = timestamp_to_date(flight.get('departureTime'))
        arrival = timestamp_to_date(flight.get('arrivalTime'))
        print(f"Departure: {departure}")
        print(f"Arrival: {arrival}")
        
        # Aircraft and capacity
        print(f"\nAircraft: {flight.get('aircraft', {}).get('type', 'N/A')}")
        print(f"Registration: {flight.get('aircraft', {}).get('registration', 'N/A')}")
        print(f"Capacity: {flight.get('capacity')} passengers")
        
        # Booking status
        booked = flight.get('passengerCount', 0)
        available = flight.get('capacity', 0) - booked
        print(f"\nBooked: {booked}/{flight.get('capacity')}")
        print(f"Available Seats: {available}")
        
        # Waitlist
        waitlist_count = flight.get('waitlistCount', 0)
        print(f"Waitlist: {waitlist_count} people")
        
        # Price
        price = flight.get('price', {})
        if price:
            print(f"\nPrice:")
            print(f"  Basic: ${price.get('basic', 0)}")
            print(f"  Cabin+: ${price.get('cabinPlus', 0)}")
        
        # Status
        status = flight.get('status', 'N/A')
        print(f"\nStatus: {status}")
        
        # Booking window
        booking_opens = timestamp_to_date(flight.get('bookingOpensAt'))
        booking_closes = timestamp_to_date(flight.get('bookingClosesAt'))
        print(f"Booking Opens: {booking_opens}")
        print(f"Booking Closes: {booking_closes}")
        
        # Additional info
        if flight.get('notes'):
            print(f"\nNotes: {flight.get('notes')}")
        
        print()

# Get flights for both accounts
print("="*80)
print("PRODUCTION API - AVAILABLE FLIGHTS")
print("="*80)

get_flights(SAMEER_TOKEN, "Sameer Chopra (Cabin+)")
get_flights(ASHLEY_TOKEN, "Ashley Rager (Basic)")

print("="*80)
print("SUMMARY")
print("="*80)
print("Above are all available flights in the system.")
print("Sameer (Cabin+) sees 10 flights, Ashley (Basic) may see fewer.")
print("="*80)
