#!/usr/bin/env python3
"""
Scan for all flights going to SJC (San Jose) and extract aircraft information
"""

import requests
import json
from datetime import datetime

# Sameer's JWT token
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

BASE_URL = "https://vauntapi.flyvaunt.com"

def make_request(endpoint, params=None):
    """Make authenticated request to Vaunt API"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }

    url = f"{BASE_URL}{endpoint}"
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        print(f"📡 {response.status_code} {endpoint}")

        if response.status_code == 200:
            return response.json()
        else:
            print(f"   ⚠️  Error: {response.text[:200]}")
            return None
    except Exception as e:
        print(f"   ❌ Exception: {str(e)}")
        return None

def scan_v3_flights():
    """Scan V3 API for all flights"""
    print("\n🔍 Scanning V3 API for all flights...")
    print("=" * 80)

    # Try different parameter combinations to get all flights
    test_params = [
        {"includeExpired": "false", "nearMe": "false"},
        {"includeExpired": "false", "nearMe": "false", "showAll": "true"},
        {"includeExpired": "true", "nearMe": "false"},
        {"includeExpired": "true", "nearMe": "false", "showAll": "true"},
        {},  # No params
    ]

    all_flights_map = {}

    for params in test_params:
        param_str = "&".join([f"{k}={v}" for k, v in params.items()]) if params else "no params"
        print(f"\n📊 Testing with: {param_str}")

        data = make_request("/v3/flight", params)

        if data:
            flights = data if isinstance(data, list) else data.get('data', [])
            print(f"   ✅ Found {len(flights)} flights")

            # Add to map (deduplicate by flight ID)
            for flight in flights:
                if isinstance(flight, dict) and 'id' in flight:
                    all_flights_map[flight['id']] = flight

    return list(all_flights_map.values())

def scan_v2_flights():
    """Scan V2 API for available flights"""
    print("\n🔍 Scanning V2 API for available flights...")
    print("=" * 80)

    data = make_request("/v2/flight")

    if data:
        flights = data if isinstance(data, list) else data.get('data', [])
        print(f"   ✅ Found {len(flights)} flights")
        return flights

    return []

def extract_aircraft_info(flight):
    """Extract aircraft and jet provider information from flight"""
    info = {
        'flight_id': flight.get('id'),
        'route': f"{flight.get('departAirport', {}).get('code', '???')} → {flight.get('arriveAirport', {}).get('code', '???')}",
        'depart_airport': flight.get('departAirport', {}),
        'arrive_airport': flight.get('arriveAirport', {}),
        'depart_time': flight.get('departDateTimeLocal', 'Unknown'),
        'arrive_time': flight.get('arriveDateTimeLocal', 'Unknown'),
        'status': flight.get('status', {}).get('label') if isinstance(flight.get('status'), dict) else flight.get('status', 'Unknown'),
        'aircraft': flight.get('aircraft', {}),
        'aircraft_type': flight.get('aircraftType'),
        'tail_number': flight.get('tailNumber'),
        'operator': flight.get('operator'),
        'provider': flight.get('provider'),
        'jet_provider': flight.get('jetProvider'),
        'charter_provider': flight.get('charterProvider'),
        'seats': flight.get('seats'),
        'available_seats': flight.get('availableSeats'),
        'entrants': flight.get('entrants', []),
        'raw_flight': flight  # Keep full data for inspection
    }

    return info

def display_flight_info(flight_info, show_full=False):
    """Display formatted flight information"""
    print("\n" + "=" * 100)
    print(f"🛫 FLIGHT #{flight_info['flight_id']}: {flight_info['route']}")
    print("=" * 100)

    # Route details
    depart = flight_info['depart_airport']
    arrive = flight_info['arrive_airport']

    print(f"\n📍 ROUTE:")
    print(f"   Depart: {depart.get('code', '???')} - {depart.get('name', 'Unknown')} ({depart.get('city', 'Unknown')})")
    print(f"   Arrive: {arrive.get('code', '???')} - {arrive.get('name', 'Unknown')} ({arrive.get('city', 'Unknown')})")
    print(f"   Depart Time: {flight_info['depart_time']}")
    print(f"   Arrive Time: {flight_info['arrive_time']}")
    print(f"   Status: {flight_info['status']}")

    # Aircraft information
    print(f"\n✈️  AIRCRAFT INFORMATION:")

    aircraft = flight_info['aircraft']
    if aircraft and isinstance(aircraft, dict):
        print(f"   Aircraft Object: {json.dumps(aircraft, indent=6)}")
    else:
        print(f"   Aircraft: {aircraft if aircraft else 'Not specified'}")

    if flight_info['aircraft_type']:
        print(f"   Aircraft Type: {flight_info['aircraft_type']}")

    if flight_info['tail_number']:
        print(f"   Tail Number: {flight_info['tail_number']}")

    # Provider information
    print(f"\n🏢 PROVIDER INFORMATION:")

    if flight_info['operator']:
        print(f"   Operator: {flight_info['operator']}")

    if flight_info['provider']:
        print(f"   Provider: {flight_info['provider']}")

    if flight_info['jet_provider']:
        print(f"   Jet Provider: {flight_info['jet_provider']}")

    if flight_info['charter_provider']:
        print(f"   Charter Provider: {flight_info['charter_provider']}")

    # Capacity
    print(f"\n👥 CAPACITY:")
    print(f"   Total Seats: {flight_info['seats'] if flight_info['seats'] else 'Unknown'}")
    print(f"   Available Seats: {flight_info['available_seats'] if flight_info['available_seats'] is not None else 'Unknown'}")
    print(f"   Entrants: {len(flight_info['entrants'])}")

    # Show entrants if present
    if flight_info['entrants'] and len(flight_info['entrants']) > 0:
        print(f"\n   📋 Passenger Manifest:")
        for i, entrant in enumerate(flight_info['entrants'][:5], 1):
            if isinstance(entrant, dict):
                name = f"{entrant.get('firstName', '')} {entrant.get('lastName', '')}".strip() or f"User {entrant.get('id', '???')}"
                position = entrant.get('queuePosition', '?')
                print(f"      {i}. Pos {position}: {name}")
        if len(flight_info['entrants']) > 5:
            print(f"      ... and {len(flight_info['entrants']) - 5} more")

    if show_full:
        print(f"\n🔍 RAW FLIGHT DATA:")
        print(json.dumps(flight_info['raw_flight'], indent=2))

def main():
    print("=" * 100)
    print("🛩️  VAUNT FLIGHT SCANNER - SJC (San Jose) Destination Analysis")
    print("=" * 100)

    # Scan all flights from both V3 and V2 APIs
    all_flights = []

    v3_flights = scan_v3_flights()
    all_flights.extend(v3_flights)

    v2_flights = scan_v2_flights()
    # Add V2 flights that aren't already in the list
    v3_ids = {f.get('id') for f in v3_flights if isinstance(f, dict)}
    for flight in v2_flights:
        if isinstance(flight, dict) and flight.get('id') not in v3_ids:
            all_flights.append(flight)

    print(f"\n📊 TOTAL UNIQUE FLIGHTS FOUND: {len(all_flights)}")

    # Filter for SJC destination
    sjc_flights = []
    for flight in all_flights:
        if isinstance(flight, dict):
            arrive_code = flight.get('arriveAirport', {}).get('code', '') if isinstance(flight.get('arriveAirport'), dict) else ''
            if arrive_code and 'SJC' in arrive_code.upper():
                sjc_flights.append(flight)

    print(f"\n🎯 FLIGHTS TO SJC: {len(sjc_flights)}")
    print("=" * 100)

    if len(sjc_flights) == 0:
        print("\n⚠️  No flights to SJC found. Showing ALL flights for aircraft info analysis...\n")
        flights_to_show = all_flights[:10]  # Show first 10 for analysis
    else:
        flights_to_show = sjc_flights

    # Extract and display aircraft info for each flight
    for flight in flights_to_show:
        info = extract_aircraft_info(flight)
        display_flight_info(info, show_full=False)

    # Summary of jet providers
    print("\n" + "=" * 100)
    print("📊 JET PROVIDER SUMMARY")
    print("=" * 100)

    providers = {}
    aircraft_types = {}
    operators = {}

    for flight in all_flights:
        if isinstance(flight, dict):
            # Track providers
            provider = flight.get('provider') or flight.get('jetProvider') or flight.get('charterProvider') or flight.get('operator')
            if provider:
                providers[provider] = providers.get(provider, 0) + 1

            # Track aircraft types
            aircraft_type = flight.get('aircraftType')
            if aircraft_type:
                aircraft_types[aircraft_type] = aircraft_types.get(aircraft_type, 0) + 1

            # Track operators
            operator = flight.get('operator')
            if operator:
                operators[operator] = operators.get(operator, 0) + 1

    if providers:
        print(f"\n🏢 Providers ({len(providers)} unique):")
        for provider, count in sorted(providers.items(), key=lambda x: x[1], reverse=True):
            print(f"   {provider}: {count} flight(s)")
    else:
        print("\n⚠️  No provider information found in flight data")

    if aircraft_types:
        print(f"\n✈️  Aircraft Types ({len(aircraft_types)} unique):")
        for aircraft, count in sorted(aircraft_types.items(), key=lambda x: x[1], reverse=True):
            print(f"   {aircraft}: {count} flight(s)")
    else:
        print("\n⚠️  No aircraft type information found in flight data")

    if operators:
        print(f"\n🎯 Operators ({len(operators)} unique):")
        for operator, count in sorted(operators.items(), key=lambda x: x[1], reverse=True):
            print(f"   {operator}: {count} flight(s)")
    else:
        print("\n⚠️  No operator information found in flight data")

    # Save detailed results to JSON
    output_file = "/home/user/vaunt/api_testing/sjc_flights_analysis.json"
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "total_flights": len(all_flights),
        "sjc_flights": len(sjc_flights),
        "sjc_flight_details": [extract_aircraft_info(f) for f in sjc_flights],
        "all_flights": [extract_aircraft_info(f) for f in all_flights],
        "providers": providers,
        "aircraft_types": aircraft_types,
        "operators": operators
    }

    # Remove raw_flight from JSON to keep file size manageable
    for category in ['sjc_flight_details', 'all_flights']:
        for flight in output_data[category]:
            flight.pop('raw_flight', None)

    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"\n💾 Detailed results saved to: {output_file}")

if __name__ == "__main__":
    main()
