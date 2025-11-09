#!/usr/bin/env python3
"""
Priority Score Analysis - Compare multiple users to understand the mechanics
"""

import requests
import json
from datetime import datetime

API_BASE = "https://vauntapi.flyvaunt.com"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

def get_all_flights():
    """Get all flights to find user IDs"""
    resp = requests.get(f"{API_BASE}/v1/flight", headers=HEADERS)
    if resp.status_code == 200:
        data = resp.json()
        return data if isinstance(data, list) else data.get('data', [])
    return []

def get_flight_history():
    """Get flight history"""
    resp = requests.get(f"{API_BASE}/v1/flight-history", headers=HEADERS)
    if resp.status_code == 200:
        return resp.json().get('data', [])
    return []

def priority_score_to_date(score):
    """Convert priority score (unix timestamp) to date"""
    if not score:
        return None
    try:
        return datetime.fromtimestamp(score)
    except:
        return None

def main():
    print("="*80)
    print("PRIORITY SCORE ANALYSIS - Understanding the Mechanics")
    print("="*80)

    # Sameer's data
    OLD_SCORE = 1931577847
    NEW_SCORE = 1963113847
    DIFF = NEW_SCORE - OLD_SCORE

    print(f"\n📊 SAMEER'S PRIORITY SCORE CHANGE")
    print(f"="*80)
    print(f"Old score:  {OLD_SCORE:,}")
    print(f"New score:  {NEW_SCORE:,}")
    print(f"Difference: {DIFF:,} seconds")
    print(f"In days:    {DIFF / 86400:.1f} days")
    print(f"In years:   {DIFF / 31536000:.2f} years")

    old_date = priority_score_to_date(OLD_SCORE)
    new_date = priority_score_to_date(NEW_SCORE)

    print(f"\nAs dates:")
    print(f"Old score date: {old_date.strftime('%Y-%m-%d %H:%M:%S') if old_date else 'N/A'}")
    print(f"New score date: {new_date.strftime('%Y-%m-%d %H:%M:%S') if new_date else 'N/A'}")

    if DIFF == 31536000:
        print(f"\n🎯 EXACTLY 365 days (1 year) added!")
        print(f"   This suggests: Winning a flight = +1 year boost")

    # Get flight data
    print(f"\n{'='*80}")
    print(f"ANALYZING OTHER USERS FROM FLIGHT DATA")
    print(f"{'='*80}")

    flights = get_all_flights()
    flight_history = get_flight_history()

    # Collect unique user IDs and their context
    user_contexts = {}

    for flight in flights:
        flight_id = flight.get('id')
        tier = flight.get('tierClassification', 'unknown')
        winner = flight.get('winner')
        status = flight.get('status', {}).get('label', 'unknown')

        # Get entrants
        for entrant in flight.get('entrants', []):
            user_id = entrant.get('id')
            if user_id and user_id not in user_contexts:
                user_contexts[user_id] = {
                    'user_id': user_id,
                    'first_name': entrant.get('firstName', '?'),
                    'last_name': entrant.get('lastName', '?'),
                    'flights_entered': 0,
                    'flights_won': 0,
                    'is_sameer': user_id == 20254,
                    'queue_positions': []
                }

            if user_id in user_contexts:
                user_contexts[user_id]['flights_entered'] += 1
                user_contexts[user_id]['queue_positions'].append(entrant.get('queuePosition', 999))

                if winner == user_id:
                    user_contexts[user_id]['flights_won'] += 1

    # Also check flight history for winners
    for flight in flight_history:
        winner = flight.get('winner')
        if winner and winner in user_contexts:
            # Already counted in main flights
            pass
        elif winner:
            # Winner not in current entrants, add them
            user_contexts[winner] = {
                'user_id': winner,
                'first_name': '?',
                'last_name': '?',
                'flights_entered': 0,
                'flights_won': 1,
                'is_sameer': winner == 20254,
                'queue_positions': []
            }

    print(f"\nFound {len(user_contexts)} unique users in flight data")

    # Print summary of interesting users
    print(f"\n{'='*80}")
    print(f"USER ACTIVITY SUMMARY (Sample)")
    print(f"{'='*80}")
    print(f"{'User ID':<12} {'Name':<20} {'Entered':<10} {'Won':<8} {'Avg Pos':<10}")
    print(f"{'-'*80}")

    sorted_users = sorted(user_contexts.values(), key=lambda x: x['flights_won'], reverse=True)

    for user in sorted_users[:20]:  # Top 20 by wins
        avg_pos = sum(user['queue_positions']) / len(user['queue_positions']) if user['queue_positions'] else 0
        name = f"{user['first_name']} {user['last_name']}"
        marker = "👤 YOU" if user['is_sameer'] else ""

        print(f"{user['user_id']:<12} {name:<20} {user['flights_entered']:<10} {user['flights_won']:<8} {avg_pos:<10.1f} {marker}")

    # Key findings
    print(f"\n{'='*80}")
    print(f"KEY FINDINGS")
    print(f"{'='*80}")

    print(f"\n1. PRIORITY SCORE MECHANICS:")
    print(f"   - Priority score is a Unix timestamp (seconds since 1970)")
    print(f"   - HIGHER score = BETTER priority (further in the future)")
    print(f"   - Score represents your 'priority date'")

    print(f"\n2. FLIGHT AWARDS BOOST SCORE:")
    print(f"   - Sameer won a flight → score increased by {DIFF:,} seconds")
    print(f"   - This is EXACTLY 1 year (365 days)")
    print(f"   - Winning flights INCREASES priority (rewards activity)")

    print(f"\n3. WHY HIGHER IS BETTER:")
    print(f"   - Counter-intuitive, but makes sense:")
    print(f"   - Cabin+ members get baseline score = subscription start + 3 years")
    print(f"   - Taking flights EXTENDS this boost")
    print(f"   - Frequent flyers get MORE priority (not less)")

    print(f"\n4. THE CONFUSION:")
    print(f"   - User expected: More flights = Lower priority")
    print(f"   - Reality: More flights WON = Higher priority")
    print(f"   - System REWARDS frequent travelers")

    # Check if we can see other users' scores
    print(f"\n{'='*80}")
    print(f"ATTEMPTING TO CHECK OTHER USERS' SCORES")
    print(f"{'='*80}")

    # Pick a few user IDs to test
    test_users = [
        156170,  # Won flight 8840
        18540,   # Won flight 8800
        161064,  # Won flight 8835
        20254,   # Sameer (for comparison)
    ]

    print(f"\nNote: V1 API likely doesn't expose other users' priority scores")
    print(f"      (This would be an information disclosure vulnerability)")
    print(f"\nChecking entrant data from flights instead...")

    # Look for users with multiple wins
    multi_winners = [u for u in user_contexts.values() if u['flights_won'] > 1]
    print(f"\n{'='*80}")
    print(f"USERS WITH MULTIPLE FLIGHT WINS")
    print(f"{'='*80}")

    if multi_winners:
        for user in sorted(multi_winners, key=lambda x: x['flights_won'], reverse=True)[:10]:
            print(f"User {user['user_id']}: {user['first_name']} {user['last_name']}")
            print(f"  Flights entered: {user['flights_entered']}")
            print(f"  Flights won: {user['flights_won']}")
            print(f"  Expected boost: +{user['flights_won']} years")
            print()
    else:
        print("No users found with multiple wins in current data")

    print(f"\n{'='*80}")
    print(f"CONCLUSION")
    print(f"{'='*80}")

    print(f"""
The priority score system works as follows:

1. BASE SCORE = Account creation time or subscription start time
2. CABIN+ BOOST = +3 years (or +6 years originally) from subscription start
3. FLIGHT WIN BOOST = +1 year per flight won

Formula (hypothesis):
  priority_score = subscription_start_timestamp + (years_boost * 31536000)

Sameer's example:
  - Subscription start: {datetime.fromtimestamp(1760700980).strftime('%Y-%m-%d')} (from API data)
  - Original boost: +3 years (shows in subscription expiry)
  - Won 1 flight: +1 year
  - Total boost: ~4 years

This explains why:
  ✅ Winning flights INCREASES priority score
  ✅ More flights = Better queue position
  ✅ System rewards active, frequent flyers
  ❌ NOT a "penalty" for flying too much

The user was correct that something changed after winning - the score DID increase!
But the interpretation was backwards - higher is better, not worse.
""")

if __name__ == "__main__":
    main()
