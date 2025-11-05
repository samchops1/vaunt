#!/usr/bin/env python3
"""
Rate Limiting Test - V2 API

Tests how many rapid join/reset cycles can be performed before rate limiting kicks in.
"""

import requests
import json
import time
from datetime import datetime

API_URL = "https://vauntapi.flyvaunt.com"
SAMEER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"

def join_flight_v2(flight_id):
    """Join flight using v2 API"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(
            f"{API_URL}/v2/flight/{flight_id}/enter",
            headers=headers,
            json={},
            timeout=10
        )
        return r.status_code, r.text[:200]
    except Exception as e:
        return None, str(e)

def reset_flight_v2(flight_id):
    """Leave flight using v2 API"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(
            f"{API_URL}/v2/flight/{flight_id}/reset",
            headers=headers,
            json={},
            timeout=10
        )
        return r.status_code, r.text[:200]
    except Exception as e:
        return None, str(e)

def get_available_flights_v3():
    """Get available flights from v3 API"""
    headers = {"Authorization": f"Bearer {SAMEER_TOKEN}"}
    try:
        r = requests.get(
            f"{API_URL}/v3/flight?includeExpired=false&nearMe=false",
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            response = r.json()
            if isinstance(response, dict) and 'data' in response:
                return response['data']
            return response
    except Exception as e:
        print(f"Error: {e}")
    return []

def main():
    print("="*80)
    print("RATE LIMITING TEST - V2 API")
    print("="*80)
    print()

    # Get test flight
    print("Step 1: Getting test flight...")
    flights = get_available_flights_v3()

    if not flights:
        print("❌ No available flights")
        return

    flight_id = flights[0].get('id')
    print(f"✅ Using Flight {flight_id}")
    print()

    # Test rapid join/reset cycles
    print("="*80)
    print("TEST: Rapid Join/Reset Cycles")
    print("="*80)
    print()
    print("Performing up to 50 join/reset cycles...")
    print("Will stop if rate limited (429) or other error occurs")
    print()

    start_time = time.time()
    results = []
    rate_limited = False
    rate_limit_at = 0

    for i in range(50):
        cycle_start = time.time()

        # Join
        join_status, join_response = join_flight_v2(flight_id)

        if join_status == 429:
            print(f"🛑 Rate limited at cycle {i + 1} (JOIN)")
            print(f"   Response: {join_response}")
            rate_limited = True
            rate_limit_at = i + 1
            break

        if join_status != 200:
            print(f"⚠️  Join failed at cycle {i + 1}: Status {join_status}")
            print(f"   Response: {join_response}")
            # Don't break, could be temporary issue
            time.sleep(1)
            continue

        # Reset
        reset_status, reset_response = reset_flight_v2(flight_id)

        if reset_status == 429:
            print(f"🛑 Rate limited at cycle {i + 1} (RESET)")
            print(f"   Response: {reset_response}")
            rate_limited = True
            rate_limit_at = i + 1
            break

        if reset_status != 200:
            print(f"⚠️  Reset failed at cycle {i + 1}: Status {reset_status}")
            print(f"   Response: {reset_response}")
            time.sleep(1)
            continue

        cycle_time = time.time() - cycle_start

        results.append({
            "cycle": i + 1,
            "join_status": join_status,
            "reset_status": reset_status,
            "cycle_time": cycle_time
        })

        # Progress indicator
        if (i + 1) % 5 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"   Cycle {i + 1}: ✅ ({rate:.2f} cycles/sec)")

        # Small delay to avoid overwhelming
        time.sleep(0.05)

    elapsed = time.time() - start_time
    successful_cycles = len(results)

    print()
    print("="*80)
    print("RATE LIMITING TEST RESULTS")
    print("="*80)
    print()

    print(f"Total Duration: {elapsed:.2f} seconds")
    print(f"Successful Cycles: {successful_cycles}")
    print(f"Average Rate: {successful_cycles / elapsed:.2f} cycles/second")
    print()

    if rate_limited:
        print("✅ Rate Limiting: IMPLEMENTED")
        print(f"   Limited after {rate_limit_at} cycles")
        print(f"   Limit hit at {rate_limit_at * 2} total requests (join + reset)")
        print()
        print("Security Assessment: GOOD")
        print("  - Rate limiting protects against abuse")
        print("  - Prevents rapid join/reset spam")
        print("  - Mitigates DoS attacks")
    else:
        print("⚠️  Rate Limiting: NOT DETECTED")
        print(f"   Completed {successful_cycles} cycles without limiting")
        print(f"   Total requests: {successful_cycles * 2} (join + reset)")
        print()
        print("Security Assessment: CONCERNING")
        print("  - No rate limiting observed")
        print("  - Vulnerable to rapid join/reset abuse")
        print("  - Could enable DoS attacks")
        print("  - Email/notification spam possible")

    print()

    # Timing analysis
    if results:
        print("="*80)
        print("TIMING ANALYSIS")
        print("="*80)
        print()

        cycle_times = [r['cycle_time'] for r in results]
        avg_time = sum(cycle_times) / len(cycle_times)
        min_time = min(cycle_times)
        max_time = max(cycle_times)

        print(f"Average cycle time: {avg_time:.3f}s")
        print(f"Fastest cycle: {min_time:.3f}s")
        print(f"Slowest cycle: {max_time:.3f}s")
        print()

        # Check for timing changes (could indicate rate limiting starting)
        first_10 = cycle_times[:10] if len(cycle_times) >= 10 else cycle_times
        last_10 = cycle_times[-10:] if len(cycle_times) >= 10 else []

        if last_10:
            avg_first = sum(first_10) / len(first_10)
            avg_last = sum(last_10) / len(last_10)

            print(f"First 10 cycles avg: {avg_first:.3f}s")
            print(f"Last 10 cycles avg: {avg_last:.3f}s")

            if avg_last > avg_first * 1.5:
                print()
                print("⚠️  Response times increased significantly")
                print("   This could indicate soft rate limiting (throttling)")
            elif avg_last > avg_first * 1.2:
                print()
                print("ℹ️  Response times increased slightly")
                print("   Minor throttling or network variation")
            else:
                print()
                print("✅ Response times remained consistent")

    print()

    # Compare with V1
    print("="*80)
    print("COMPARISON WITH V1 API")
    print("="*80)
    print()

    print("Testing v1/enter and v1/cancel for comparison...")
    v1_start = time.time()
    v1_cycles = 0

    for i in range(10):  # Just test 10 cycles for v1
        # V1 join
        status_v1_join, _ = join_flight_v1(flight_id)
        if status_v1_join != 200:
            break

        # V1 cancel (note: only works for CLOSED flights, but we can try)
        status_v1_cancel, _ = cancel_flight_v1(flight_id)

        v1_cycles += 1
        time.sleep(0.05)

    v1_elapsed = time.time() - v1_start
    v1_rate = v1_cycles / v1_elapsed if v1_elapsed > 0 else 0

    print(f"V1 API: {v1_cycles} cycles in {v1_elapsed:.2f}s ({v1_rate:.2f} cycles/sec)")
    print(f"V2 API: {successful_cycles} cycles in {elapsed:.2f}s ({successful_cycles / elapsed:.2f} cycles/sec)")
    print()

    if successful_cycles > 0:
        v2_rate = successful_cycles / elapsed
        if abs(v1_rate - v2_rate) < 0.5:
            print("✅ V1 and V2 have similar rate limits")
        else:
            print("⚠️  V1 and V2 have different rate limits")

    print()
    print("="*80)
    print("TEST COMPLETE")
    print("="*80)

def join_flight_v1(flight_id):
    """Join flight using v1 API (for comparison)"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(
            f"{API_URL}/v1/flight/{flight_id}/enter",
            headers=headers,
            json={},
            timeout=10
        )
        return r.status_code, r.text[:200]
    except:
        return None, ""

def cancel_flight_v1(flight_id):
    """Cancel flight using v1 API (for comparison)"""
    headers = {
        "Authorization": f"Bearer {SAMEER_TOKEN}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(
            f"{API_URL}/v1/flight/{flight_id}/cancel",
            headers=headers,
            json={},
            timeout=10
        )
        return r.status_code, r.text[:200]
    except:
        return None, ""

if __name__ == "__main__":
    main()
