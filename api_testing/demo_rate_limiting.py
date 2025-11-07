#!/usr/bin/env python3
"""
Rate Limiting Vulnerability Demonstration
==========================================
This script demonstrates the lack of rate limiting on Vaunt API endpoints.

AUTHORIZED TESTING ONLY - User ID 20254
"""

import requests
import time
from datetime import datetime
import statistics

# Configuration
BASE_URL = "https://vauntapi.flyvaunt.com"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q"
HEADERS = {
    "Authorization": f"Bearer {JWT_TOKEN}",
    "Content-Type": "application/json"
}

def test_rate_limiting(endpoint, num_requests=50, delay=0):
    """
    Test rate limiting on an endpoint by sending rapid requests.

    Args:
        endpoint: API endpoint to test (e.g., "/v1/user")
        num_requests: Number of requests to send
        delay: Delay between requests in seconds
    """
    print(f"\n{'='*80}")
    print(f"Testing Rate Limiting: {endpoint}")
    print(f"{'='*80}")
    print(f"Requests to send: {num_requests}")
    print(f"Delay between requests: {delay}s")
    print()

    url = f"{BASE_URL}{endpoint}"
    results = {
        "success": 0,
        "rate_limited": 0,
        "errors": 0,
        "response_times": []
    }

    start_time = time.time()

    for i in range(1, num_requests + 1):
        request_start = time.time()

        try:
            response = requests.get(url, headers=HEADERS, timeout=10)
            request_time = time.time() - request_start
            results["response_times"].append(request_time)

            if response.status_code == 200:
                results["success"] += 1
                status_icon = "✓"
            elif response.status_code == 429:  # Too Many Requests
                results["rate_limited"] += 1
                status_icon = "⏸"
                print(f"\n{'='*80}")
                print(f"RATE LIMITED after {i} requests!")
                print(f"{'='*80}")
                if 'Retry-After' in response.headers:
                    print(f"Retry-After: {response.headers['Retry-After']} seconds")
                break
            else:
                results["errors"] += 1
                status_icon = "✗"

            # Progress indicator
            if i % 10 == 0:
                print(f"[{i:3d}/{num_requests}] {status_icon} Status: {response.status_code} | "
                      f"Time: {request_time:.3f}s | Success: {results['success']}")

        except Exception as e:
            results["errors"] += 1
            print(f"[{i:3d}/{num_requests}] ✗ Error: {str(e)[:50]}")

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - start_time

    # Print summary
    print(f"\n{'='*80}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*80}")
    print(f"Endpoint:           {endpoint}")
    print(f"Total Requests:     {num_requests}")
    print(f"Successful (200):   {results['success']}")
    print(f"Rate Limited (429): {results['rate_limited']}")
    print(f"Errors:             {results['errors']}")
    print(f"Time Elapsed:       {elapsed:.2f}s")
    print(f"Requests/Second:    {num_requests / elapsed:.2f}")

    if results["response_times"]:
        print(f"\nResponse Time Statistics:")
        print(f"  Average:  {statistics.mean(results['response_times']):.3f}s")
        print(f"  Median:   {statistics.median(results['response_times']):.3f}s")
        print(f"  Min:      {min(results['response_times']):.3f}s")
        print(f"  Max:      {max(results['response_times']):.3f}s")

    # Vulnerability assessment
    print(f"\n{'='*80}")
    if results["rate_limited"] > 0:
        print("✅ SECURE: Rate limiting is ACTIVE")
        print(f"   Rate limit triggered after {results['success']} requests")
    else:
        print("🔴 VULNERABLE: NO rate limiting detected!")
        print(f"   All {results['success']} requests succeeded without throttling")
        print("\n⚠️  IMPACT:")
        print("   - Denial of Service (DoS) attacks possible")
        print("   - Resource exhaustion possible")
        print("   - No protection against automated abuse")
        print("   - API scraping possible")
    print(f"{'='*80}")

    return results

def demonstrate_dos_potential():
    """
    Demonstrate the potential for DoS by showing how many requests
    can be made in a short time period.
    """
    print(f"\n{'='*80}")
    print(f"DENIAL OF SERVICE POTENTIAL DEMONSTRATION")
    print(f"{'='*80}")
    print("This demonstrates how an attacker could overwhelm the API")
    print("by sending rapid requests without rate limiting protection.")
    print()

    endpoint = "/v1/user"
    burst_size = 20
    num_bursts = 3

    print(f"Simulating attack: {num_bursts} bursts of {burst_size} requests each")
    print(f"Total requests: {num_bursts * burst_size}")
    print()

    total_success = 0
    total_time = 0

    for burst in range(1, num_bursts + 1):
        print(f"\nBurst #{burst}:")
        burst_start = time.time()

        for i in range(burst_size):
            try:
                response = requests.get(f"{BASE_URL}{endpoint}",
                                       headers=HEADERS,
                                       timeout=5)
                if response.status_code == 200:
                    total_success += 1
                elif response.status_code == 429:
                    print(f"  Rate limited at request {i+1}")
                    break
            except Exception as e:
                print(f"  Error: {str(e)[:50]}")

        burst_time = time.time() - burst_start
        total_time += burst_time
        print(f"  Burst completed in {burst_time:.2f}s")
        print(f"  Requests/second: {burst_size / burst_time:.2f}")

        # Small delay between bursts
        if burst < num_bursts:
            time.sleep(1)

    print(f"\n{'='*80}")
    print(f"ATTACK SIMULATION RESULTS")
    print(f"{'='*80}")
    print(f"Total successful requests: {total_success}")
    print(f"Total time: {total_time:.2f}s")
    print(f"Average rate: {total_success / total_time:.2f} requests/second")

    if total_success >= (num_bursts * burst_size) * 0.9:
        print(f"\n🔴 VULNERABILITY CONFIRMED")
        print(f"   {total_success}/{num_bursts * burst_size} requests succeeded")
        print(f"   An attacker could sustain this rate to overwhelm the API")
    print(f"{'='*80}")

def show_rate_limit_recommendations():
    """
    Show recommended rate limiting configuration.
    """
    print(f"\n{'='*80}")
    print(f"RECOMMENDED RATE LIMITING CONFIGURATION")
    print(f"{'='*80}")

    recommendations = """
1. IMPLEMENT TIERED RATE LIMITS:

   Per User (Authenticated):
   - 100 requests per minute
   - 1,000 requests per hour
   - 10,000 requests per day

   Per IP (Unauthenticated):
   - 20 requests per minute
   - 200 requests per hour

2. ENDPOINT-SPECIFIC LIMITS (for expensive operations):

   /v3/flight/search:
   - 20 requests per minute
   - 200 requests per hour

   /v3/flight/join:
   - 10 requests per minute
   - 100 requests per hour

   /v1/user (updates):
   - 30 updates per hour

3. IMPLEMENT PROPER HTTP 429 RESPONSES:

   HTTP/1.1 429 Too Many Requests
   Retry-After: 60
   X-RateLimit-Limit: 100
   X-RateLimit-Remaining: 0
   X-RateLimit-Reset: 1699360800

   {
     "error": "Rate limit exceeded",
     "message": "Too many requests. Please try again later.",
     "retryAfter": 60
   }

4. USE SLIDING WINDOW OR TOKEN BUCKET ALGORITHM:

   Recommended: Redis-based distributed rate limiting
   - Atomic increment operations
   - TTL for automatic cleanup
   - Works across multiple API servers

5. EXAMPLE IMPLEMENTATION (Node.js/Express):

   const rateLimit = require('express-rate-limit');
   const RedisStore = require('rate-limit-redis');

   const limiter = rateLimit({
     store: new RedisStore({
       client: redisClient,
       prefix: 'rate_limit:',
     }),
     windowMs: 60 * 1000, // 1 minute
     max: 100, // 100 requests per window
     message: {
       error: 'Rate limit exceeded',
       retryAfter: 60
     },
     standardHeaders: true, // Return RateLimit-* headers
     legacyHeaders: false,
   });

   app.use('/v1/user', limiter);
   app.use('/v3/flight/search', stricter_limiter);

6. MONITOR AND ALERT:

   - Track rate limit hits per user/IP
   - Alert on sustained high request rates
   - Log all 429 responses for analysis
   - Identify and block abusive users/IPs

7. CONSIDER ADAPTIVE RATE LIMITING:

   - Increase limits for verified users
   - Decrease limits for suspicious behavior
   - Implement CAPTCHA for excessive requests
   - Temporary IP bans for severe abuse
"""

    print(recommendations)
    print(f"{'='*80}")

def main():
    """
    Main execution function.
    """
    print(f"\n{'='*80}")
    print(f"RATE LIMITING VULNERABILITY DEMONSTRATION")
    print(f"{'='*80}")
    print(f"Target: {BASE_URL}")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Authorized Testing: User ID 20254")
    print(f"{'='*80}")

    # Test 1: Rapid requests on /v1/user
    print("\nTest 1: Testing /v1/user with 50 rapid requests")
    test_rate_limiting("/v1/user", num_requests=50, delay=0)

    # Test 2: DoS potential demonstration
    print("\n" + "="*80)
    input("Press Enter to run DoS potential demonstration...")
    demonstrate_dos_potential()

    # Show recommendations
    print("\n" + "="*80)
    input("Press Enter to see rate limiting recommendations...")
    show_rate_limit_recommendations()

    print(f"\n{'='*80}")
    print(f"TESTING COMPLETE")
    print(f"{'='*80}")
    print("For full penetration test results, see:")
    print("  /home/user/vaunt/PENETRATION_TEST_RESULTS.md")
    print("  /home/user/vaunt/api_testing/pentest_results.json")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    main()
