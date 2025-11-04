#!/usr/bin/env python3
"""
Find endpoints that show AVAILABLE flights (not history)
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

print("="*80)
print("SEARCHING FOR AVAILABLE/UPCOMING FLIGHTS ENDPOINTS")
print("="*80)

# Test various endpoint patterns
endpoints = [
    # Current/Active
    "/v1/flight/current",
    "/v1/flight/active",
    "/v1/flight/open",
    "/v1/flight/available",
    
    # Upcoming/Future
    "/v1/flight/upcoming",
    "/v1/flight/future",
    "/v1/flight/scheduled",
    "/v1/flight/pending",
    
    # Browse/Search
    "/v1/flights",
    "/v1/flight/browse",
    "/v1/flight/search",
    "/v1/flight/list",
    
    # Booking related
    "/v1/flight/bookable",
    "/v1/booking/available",
    "/v1/waitlist/available",
    
    # History (for comparison)
    "/v1/flight/history",
    "/v1/flight/past",
    "/v1/flight/completed",
    "/v1/flight/closed",
    
    # User specific
    "/v1/user/flights",
    "/v1/user/flights/upcoming",
    "/v1/user/bookings",
    
    # General
    "/v1/app/flights",
    "/v1/app/available-flights",
]

successful = []

for endpoint in endpoints:
    r = requests.get(f"{PROD_URL}{endpoint}", headers=headers, timeout=10)
    
    status_icon = "✅" if r.status_code == 200 else "❌"
    print(f"{status_icon} {r.status_code} - {endpoint}")
    
    if r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list):
                count = len(data)
                successful.append({
                    "endpoint": endpoint,
                    "count": count,
                    "data": data
                })
                print(f"   → Returns {count} items")
            else:
                successful.append({
                    "endpoint": endpoint,
                    "data": data
                })
                print(f"   → Returns object")
        except:
            pass

print("\n" + "="*80)
print("DETAILED RESULTS FOR SUCCESSFUL ENDPOINTS")
print("="*80)

for result in successful:
    print(f"\n{'='*80}")
    print(f"Endpoint: {result['endpoint']}")
    print(f"{'='*80}")
    
    data = result['data']
    
    if isinstance(data, list) and len(data) > 0:
        print(f"Total items: {len(data)}\n")
        
        # Check if any flights are OPEN (not closed)
        open_flights = []
        closed_flights = []
        
        for flight in data:
            status = flight.get('status', {})
            status_label = status.get('label', 'UNKNOWN')
            
            if status_label == 'OPEN':
                open_flights.append(flight)
            else:
                closed_flights.append(flight)
        
        print(f"OPEN flights: {len(open_flights)}")
        print(f"CLOSED flights: {len(closed_flights)}")
        
        if open_flights:
            print("\n🎯 FOUND OPEN/AVAILABLE FLIGHTS!")
            for i, flight in enumerate(open_flights[:3], 1):
                print(f"\nFlight {i}:")
                print(f"  ID: {flight.get('id')}")
                print(f"  Route: {flight.get('departAirport', {}).get('code')} → {flight.get('arriveAirport', {}).get('code')}")
                print(f"  Depart: {flight.get('departDateTimeLocal')}")
                print(f"  Status: {flight.get('status', {}).get('label')}")
                print(f"  Tier: {flight.get('tierClassification')}")
        else:
            print("\n❌ All flights are CLOSED")
            print("\nFirst flight sample:")
            print(f"  Status: {data[0].get('status', {}).get('label')}")
            print(f"  Depart: {data[0].get('departDateTimeLocal')}")
    
    elif isinstance(data, dict):
        print("Response (first 5 keys):")
        for key in list(data.keys())[:5]:
            print(f"  {key}: {data[key]}")

print("\n" + "="*80)
print("SUMMARY")
print("="*80)

if any('OPEN' in str(r.get('data', [])) for r in successful):
    print("✅ Found endpoints with OPEN/available flights!")
else:
    print("❌ No OPEN flights found - all are CLOSED/past flights")
    print("\nPossible reasons:")
    print("1. No upcoming flights scheduled in the system")
    print("2. Different endpoint needed (not discovered yet)")
    print("3. Flights only appear when booking window opens")
    print("4. Need different parameters/filters")
