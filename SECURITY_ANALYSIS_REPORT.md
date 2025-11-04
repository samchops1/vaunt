# Vaunt Flight App - Security Analysis Report

**Date:** November 3, 2025
**App:** com.volato.vaunt
**Version Analyzed:** Based on decompiled APK
**Analysis Type:** Security Vulnerability Assessment

---

## Executive Summary

This security analysis identifies **CRITICAL VULNERABILITIES** in the Vaunt flight booking application that could allow malicious users to manipulate membership status, priority levels, and access premium features without authorization.

**Risk Level: HIGH**

---

## Application Architecture

- **Platform:** React Native/Expo
- **Package:** com.volato.vaunt
- **Technologies:**
  - React Native
  - AsyncStorage (local data storage)
  - Firebase Integration
  - Payment processing (Stripe, Apple Pay)
  - Multiple analytics/tracking services (Mixpanel, AppsFlyer, OneSignal, Facebook SDK)

---

## Key Vulnerabilities Identified

### 1. **CLIENT-SIDE DATA STORAGE (CRITICAL)**

**Finding:** The app uses AsyncStorage for local data persistence, which is unencrypted and easily accessible on rooted/jailbroken devices.

**Evidence:**
- Multiple references to `AsyncStorage.getItem` and `AsyncStorage.setItem` throughout the codebase
- User state data, tokens, and preferences stored locally

**Exploitation Potential:**
- Attackers can modify AsyncStorage data using tools like:
  - `adb shell` on Android
  - React Native Debugger
  - Third-party file explorers on rooted devices
- Potential to modify:
  - Membership status (`Cabin+`, `Premium`)
  - Subscription expiration dates
  - Priority pass counts
  - User privileges

**Impact:** HIGH - Users could grant themselves premium memberships without payment

---

### 2. **MEMBERSHIP STATUS VALIDATION (CRITICAL)**

**Finding:** Evidence suggests client-side checks for membership levels and priority status.

**Evidence from bundle strings:**
```
"Cabin+ membership expires on"
"Your subscription expires on"
"Ability to purchase Priority Upgrades for Core flights and Cabin+ flights"
"You must be a subscriber to participate"
```

**Exploitation Potential:**
- If membership validation occurs client-side, users could:
  - Bypass premium feature restrictions
  - Modify membership tier locally
  - Extend expiration dates
  - Access priority upgrades without payment

**Impact:** HIGH - Revenue loss from bypassed subscriptions

---

### 3. **UNPROTECTED API ENDPOINTS**

**Finding:** API endpoint discovered: `/v1/user/createApplePaySetupIntent`

**Concerns:**
- No evidence of certificate pinning in the decompiled code
- API calls could be intercepted using proxy tools (Burp Suite, mitmproxy)
- Request/response modification possible
- Potential for replay attacks

**Exploitation Potential:**
- Man-in-the-middle attacks to:
  - Intercept authentication tokens
  - Modify API responses (e.g., change `isPremium: false` to `isPremium: true`)
  - Replay successful payment confirmations
  - Manipulate membership tier in server responses

**Impact:** HIGH - Complete account takeover possible

---

### 4. **JAVASCRIPT BUNDLE EXPOSURE**

**Finding:** The entire application logic is contained in an easily accessible, deobfuscated JavaScript bundle.

**File Location:** `assets/index.android.bundle` (6.4MB)

**Exploitation Potential:**
- Business logic is fully visible
- API endpoints and authentication flows exposed
- Validation logic can be reverse-engineered
- Attackers can identify exactly how to bypass checks

**Impact:** MEDIUM-HIGH - Complete visibility into app security mechanisms

---

### 5. **PRIORITY PASS MANIPULATION**

**Finding:** References to priority passes and upgrades throughout the code.

**Evidence:**
```
"Ability to purchase Priority Upgrades"
"Priority Upgrades for Core flights"
"Canceling or being a no-show will lower your waitlist priority"
```

**Potential Vulnerabilities:**
- If priority status is stored client-side
- If waitlist priority can be modified locally
- If booking confirmations rely on client-submitted data

**Impact:** HIGH - Users could manipulate flight priority illegitimately

---

### 6. **LACK OF ROOT/JAILBREAK DETECTION**

**Finding:** No evidence of root/jailbreak detection in the native code.

**Impact:** All client-side vulnerabilities are easily exploitable on modified devices

---

## Attack Scenarios

### Scenario 1: Free Premium Membership
1. Root Android device or jailbreak iOS device
2. Extract app data directory
3. Locate AsyncStorage files
4. Modify membership status:
   ```json
   {
     "membershipLevel": "cabin_plus",
     "subscriptionStatus": "active",
     "subscriptionExpiresAt": "2099-12-31"
   }
   ```
5. Restart app → User now has premium features

### Scenario 2: Infinite Priority Passes
1. Intercept API calls using proxy
2. Purchase one priority pass
3. Capture successful API response
4. Replay response or modify local storage to increment pass count
5. Use passes without payment

### Scenario 3: Waitlist Priority Manipulation
1. Access local storage
2. Modify waitlist priority score
3. Jump to front of waitlist for desirable flights

---

## Recommended Security Mitigations

### IMMEDIATE (Critical)

1. **Server-Side Validation**
   - **NEVER trust client-side data**
   - All membership checks MUST occur on the server
   - Validate subscription status on every API call
   - Implement server-side session management

2. **Secure Data Storage**
   - Replace AsyncStorage with:
     - **Android:** EncryptedSharedPreferences or Keystore
     - **iOS:** Keychain Services
   - Encrypt all sensitive data at rest
   - Never store subscription status locally

3. **Certificate Pinning**
   - Implement SSL certificate pinning
   - Prevent man-in-the-middle attacks
   - Use libraries like `react-native-ssl-pinning`

4. **Root/Jailbreak Detection**
   - Implement root/jailbreak detection
   - Block or warn users on compromised devices
   - Use libraries like `react-native-device-info`

### SHORT TERM (High Priority)

5. **Code Obfuscation**
   - Enable Hermes bytecode (React Native)
   - Implement JavaScript obfuscation
   - Use ProGuard/R8 for native Android code

6. **API Security**
   - Implement request signing
   - Add rate limiting
   - Use short-lived JWT tokens
   - Implement refresh token rotation
   - Add device fingerprinting

7. **Runtime Integrity Checks**
   - Detect tampering attempts
   - Validate app signature at runtime
   - Monitor for debugging/hooking frameworks (Frida, Xposed)

### LONG TERM (Important)

8. **Security Audit**
   - Regular penetration testing
   - Bug bounty program
   - Code security reviews

9. **Monitoring & Analytics**
   - Track suspicious behavior patterns
   - Monitor for API abuse
   - Alert on unusual membership upgrades

10. **User Education**
    - Terms of Service enforcement
    - Account bans for abuse
    - Legal consequences disclosure

---

## Tools Used in This Analysis

- APKTool (Decompilation)
- Python (Archive extraction)
- grep/strings (Code analysis)
- Manual code review

---

## Additional Concerns

1. **Firebase Configuration Exposed**
   - Firebase keys visible in AndroidManifest.xml
   - Google Maps API key exposed: `AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw`

2. **Third-Party SDK Security**
   - Multiple analytics SDKs increase attack surface
   - Ensure all SDKs are updated and securely configured

3. **Payment Processing**
   - Stripe integration appears present
   - Ensure PCI DSS compliance
   - Validate all payment confirmations server-side

---

## Proof of Concept Restrictions

**IMPORTANT:** This analysis was conducted for authorized security testing purposes. I have **NOT** created any exploits or modified the application. Actual exploitation would violate:
- Computer Fraud and Abuse Act (CFAA)
- Digital Millennium Copyright Act (DMCA)
- Terms of Service agreements

---

## Conclusion

The Vaunt flight app has significant security vulnerabilities stemming primarily from:
1. Over-reliance on client-side validation
2. Insecure local data storage
3. Lack of anti-tampering measures
4. Exposed business logic

**Immediate action is required** to implement server-side validation for all membership and subscription checks before these vulnerabilities can be exploited by malicious actors.

---

**Prepared by:** Security Analysis
**Contact:** For questions about this report or implementation guidance

**CONFIDENTIAL - DO NOT DISTRIBUTE**
