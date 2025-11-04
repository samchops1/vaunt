# Vaunt Flight App - LDPlayer Local File Access Guide

**Platform:** LDPlayer on Windows (No ADB Required!)
**Date Created:** November 4, 2025
**Target App:** com.volato.vaunt (Vaunt Flight App)
**Method:** Direct file access via Windows Explorer

---

## Table of Contents

1. [Why LDPlayer with Local Access?](#why-ldplayer-with-local-access)
2. [LDPlayer Setup](#ldplayer-setup)
3. [Accessing Android Files from Windows](#accessing-android-files-from-windows)
4. [Installing Required Windows Tools](#installing-required-windows-tools)
5. [Test Scenarios (No ADB)](#test-scenarios-no-adb)
6. [Troubleshooting](#troubleshooting)
7. [Quick Reference](#quick-reference)

---

## Why LDPlayer with Local Access?

### Advantages Over ADB Method

✅ **No ADB Installation Required** - No command-line tools needed
✅ **Direct Windows Access** - Browse Android files like any Windows folder
✅ **Drag & Drop Files** - Easy file management with Windows Explorer
✅ **Visual Editing** - Use familiar Windows tools (DB Browser, Notepad++)
✅ **Faster Workflow** - No push/pull commands needed
✅ **Beginner Friendly** - Point-and-click instead of command-line
✅ **Built-in Root Access** - LDPlayer comes with root enabled

### What You Can Do

- Access app databases directly from Windows
- Edit AsyncStorage files with DB Browser for SQLite
- Modify XML configuration files
- View and edit shared preferences
- Copy files in/out without commands
- Take screenshots easily

---

## LDPlayer Setup

### Step 1: Install LDPlayer

1. **Download LDPlayer:**
   - Visit: https://www.ldplayer.net/
   - Download the latest version (LDPlayer 9 recommended)
   - Run installer (default settings are fine)

2. **Launch LDPlayer:**
   - Start Menu → LDPlayer
   - Wait for Android to fully load
   - Initial boot takes 2-3 minutes

3. **Configure Settings:**
   - Click the **Menu icon** (three lines) in top-right
   - Go to **Settings**

**Recommended Settings:**
```
Performance:
- CPU: 4 cores
- RAM: 4096 MB (4GB)
- Resolution: 1080x1920 (Portrait - Phone)
- DPI: 240

Other:
- Root permission: ON (Enable)
- Graphics rendering: OpenGL
```

4. **Enable Root Access:**
   - Settings → **Other settings** tab
   - Toggle **Root permission** to **ON**
   - Click **Save**
   - **Restart LDPlayer** (Important!)

5. **Verify Root:**
   - Download "Root Checker" from Play Store (optional)
   - Or install any app and check if it can request root

---

### Step 2: Enable Shared Folder Access

**This is the KEY feature that eliminates the need for ADB!**

1. **Open LDPlayer Folder Settings:**
   - In LDPlayer menu → **Settings**
   - Go to **Other** tab
   - Look for **Shared folder** option

2. **Find LDPlayer's Data Directory:**

   **Default Locations:**
   ```
   C:\Users\YourUsername\AppData\Roaming\LDPlayer9\vms\leidian0\data
   ```

   Or find it this way:
   - Right-click LDPlayer desktop shortcut → **Open file location**
   - Navigate to: `vms\leidian0\`

3. **Access Android Filesystem:**

   LDPlayer stores Android filesystem in:
   ```
   C:\LDPlayer\LDPlayer9\vms\leidian0\
   ```

---

### Step 3: Access Method - Two Options

#### Option A: LDPlayer's Built-in File Manager (Easiest)

1. **Open File Manager in LDPlayer:**
   - Click the folder icon in the right toolbar
   - Or install "File Manager" from Play Store

2. **Navigate to app data:**
   ```
   /data/data/com.volato.vaunt/
   ```

3. **Grant Root Access:**
   - File manager will request superuser permissions
   - Tap **Grant**

4. **Export Files:**
   - Long-press on file → **Share**
   - Choose **Shared folder** or **Documents**
   - Files appear in Windows:
     ```
     C:\Users\YourUsername\Documents\ldplayer\
     ```

#### Option B: Direct Windows Access (Advanced)

1. **Enable Developer Mode in LDPlayer Settings**

2. **Access via LDPlayer's Shared Folder:**
   - Open Windows Explorer
   - Navigate to:
     ```
     \\wsl$\LDPlayer\data\data\com.volato.vaunt\
     ```

   Or use the direct path:
   ```
   C:\Users\YourUsername\AppData\Roaming\LDPlayer9\vms\leidian0\data\
   ```

---

## Accessing Android Files from Windows

### Method 1: Using LDPlayer's File Explorer Tool

LDPlayer has a built-in tool for this!

1. **Open LDPlayer while it's running**

2. **Access the Built-in File Browser:**
   - Look for **"LD File Manager"** in the system apps
   - Or download "ES File Explorer" from Play Store

3. **Navigate to App Data:**
   ```
   Root Directory (/)
   → data
   → data
   → com.volato.vaunt
   ```

4. **Copy Files to Shared Folder:**
   - Long-press file → **Copy**
   - Navigate to: `/storage/emulated/0/Documents/`
   - Paste here
   - Files now accessible from Windows:
     ```
     C:\Users\YourUsername\Documents\ldplayer\
     ```

---

### Method 2: Using Windows File Explorer with Root Access

**Requirements:**
- LDPlayer must be running
- Root must be enabled
- Use this method for advanced users

**Steps:**

1. **Install Root-enabled File Manager in LDPlayer:**
   - Download: **X-plore File Manager** (has root support)
   - Or: **Root Explorer** from Play Store

2. **Grant Root Permissions:**
   - Open file manager
   - Allow superuser when prompted

3. **Navigate to App Directory:**
   ```
   /data/data/com.volato.vaunt/databases/
   /data/data/com.volato.vaunt/shared_prefs/
   /data/data/com.volato.vaunt/files/
   ```

4. **Copy to Accessible Location:**
   - Copy files to: `/sdcard/Download/` or `/sdcard/Documents/`
   - These folders are accessible from Windows

5. **Access from Windows:**
   - Open Windows Explorer
   - Go to LDPlayer shared folder:
     ```
     C:\Users\YourUsername\Documents\ldplayer\
     ```
   - Your files are here!

---

### Method 3: LDPlayer Screenshot/File Export Feature

1. **Find File in LDPlayer**

2. **Use Export Function:**
   - Select file → Share → **Export to PC**
   - Files go to:
     ```
     C:\Users\YourUsername\Pictures\LDPlayer\
     ```

---

## Installing Required Windows Tools

### Tool 1: DB Browser for SQLite (Essential)

**Download & Install:**

1. **Download:**
   - Visit: https://sqlitebrowser.org/dl/
   - Download Windows installer (Standard installer)

2. **Install:**
   - Run installer
   - Default options are fine
   - Installation path: `C:\Program Files\DB Browser for SQLite\`

3. **Verify Installation:**
   - Start Menu → DB Browser for SQLite
   - Should open successfully

---

### Tool 2: Notepad++ (For Text Files)

**Download & Install:**

1. **Download:**
   - Visit: https://notepad-plus-plus.org/downloads/
   - Download latest version

2. **Install:**
   - Run installer
   - Default options are fine

3. **Use Cases:**
   - Viewing XML files (AndroidManifest, shared preferences)
   - Editing configuration files
   - Viewing log files

---

### Tool 3: X-plore File Manager (Inside LDPlayer)

**Install in LDPlayer:**

1. **Open Play Store in LDPlayer**

2. **Search for:** "X-plore File Manager"

3. **Install** (Free app)

4. **Open and Grant Root:**
   - Launch X-plore
   - Settings → Root access → **Enable**
   - Grant superuser permission

---

### Tool 4: Burp Suite (For Network Testing - Optional)

Same as MSI guide:
- Visit: https://portswigger.net/burp/communitydownload
- Download and install
- Configure proxy as needed

---

## Test Scenarios (No ADB)

### TEST 1: AsyncStorage Inspection (Easy Method)

**Objective:** Access and view app's local storage data.

**Difficulty:** ⭐ (Very Easy with LDPlayer)

---

#### STEP 1: Install and Run the Vaunt App

1. **Get the APK to LDPlayer:**

   **Method A - Drag & Drop:**
   - Locate your APK: `Vaunt.xapk` or `com.volato.vaunt.apk`
   - **Drag the APK file** directly onto LDPlayer window
   - LDPlayer auto-installs it
   - Wait for "Installation complete"

   **Method B - Shared Folder:**
   - Copy APK to: `C:\Users\YourUsername\Documents\ldplayer\`
   - In LDPlayer, open **File Manager**
   - Navigate to Documents folder
   - Tap APK to install

2. **Launch the Vaunt App:**
   - Find app icon on LDPlayer home screen
   - Tap to open
   - Complete login/registration with test account

3. **Use the app for a few minutes:**
   - View your profile
   - Check membership status (likely "Core")
   - Note your subscription details
   - Close the app (important - close it completely)

---

#### STEP 2: Locate App Data Using File Manager

1. **Open X-plore File Manager** in LDPlayer

2. **Enable Root Mode:**
   - Tap menu (☰) → **Settings**
   - Scroll to **Root access**
   - Enable it
   - Grant superuser when prompted

3. **Navigate to App Data:**
   - Tap **Root** in the main menu (looks like `/`)
   - Navigate: **data** → **data** → **com.volato.vaunt**
   - You'll see folders:
     ```
     databases/
     shared_prefs/
     files/
     cache/
     ```

4. **Enter the databases folder:**
   - Tap **databases/**
   - Look for files like:
     - `RKStorage` (React Native AsyncStorage)
     - `AsyncStorage.db`
     - `ReactNativeAsyncStorage`

---

#### STEP 3: Copy Database to Windows

1. **In X-plore, while viewing the databases folder:**
   - **Long-press** on `RKStorage` file
   - Tap **Copy**

2. **Navigate to shared location:**
   - Tap **Home** icon
   - Go to **sdcard** → **Documents** (or **Download**)
   - Tap **Paste**

3. **Access from Windows:**
   - Open Windows Explorer on your PC
   - Navigate to:
     ```
     C:\Users\YourUsername\Documents\ldplayer\
     ```
   - You should see `RKStorage` file here!

4. **Create working folder:**
   ```
   C:\VauntTesting\
   ```
   - Copy `RKStorage` here for editing

---

#### STEP 4: Open and Inspect with DB Browser

1. **Launch DB Browser for SQLite:**
   - Start Menu → DB Browser for SQLite

2. **Open the database:**
   - Click **Open Database** button
   - Navigate to: `C:\VauntTesting\RKStorage`
   - Click **Open**

3. **View the data:**
   - Click **Browse Data** tab
   - Table dropdown → Select **catalystLocalStorage**
   - You'll see two columns: `key` and `value`

4. **Look for sensitive keys:**

   Search (Ctrl+F) for keys containing:
   - `user`
   - `auth`
   - `token`
   - `membership`
   - `subscription`
   - `cabin`
   - `priority`

   **Example data you might find:**
   ```
   Key: @UserProfile:user12345
   Value: {"id":"12345","email":"test@test.com","name":"Test User"}

   Key: @MembershipData
   Value: {"tier":"core","status":"inactive","expiresAt":null}

   Key: @AuthToken
   Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   ```

5. **Take screenshots for documentation!**

---

#### STEP 5: Modify the Data (TEST ONLY)

**⚠️ WARNING: Only for authorized testing!**

1. **In DB Browser, find membership row:**
   - Look for key like `@MembershipData`, `@UserData`, or similar

2. **Double-click the `value` cell to edit**

3. **Modify the JSON:**

   **BEFORE:**
   ```json
   {"membershipLevel":"core","subscriptionStatus":"inactive","priorityPasses":0,"expiresAt":null}
   ```

   **AFTER:**
   ```json
   {"membershipLevel":"cabin_plus","subscriptionStatus":"active","priorityPasses":999,"expiresAt":"2099-12-31T23:59:59Z"}
   ```

4. **Save changes:**
   - Click **Write Changes** button (disk icon)
   - Click **Yes** to confirm
   - Close DB Browser

---

#### STEP 6: Copy Modified File Back to LDPlayer

**Important: Close the Vaunt app first!**

1. **In LDPlayer:**
   - Force close Vaunt app
   - Settings → Apps → Vaunt → **Force Stop**

2. **Copy modified file back:**
   - Copy modified `RKStorage` from `C:\VauntTesting\`
   - Paste to: `C:\Users\YourUsername\Documents\ldplayer\`

3. **In LDPlayer's X-plore:**
   - Navigate to **sdcard** → **Documents**
   - Find your modified `RKStorage`
   - **Long-press** → **Copy**
   - Navigate back to: **Root** → **data** → **data** → **com.volato.vaunt** → **databases**
   - **Long-press in empty space** → **Paste**
   - Confirm overwrite: **Yes**
   - Grant root permission if asked

---

#### STEP 7: Test the Exploit

1. **Restart Vaunt app**

2. **Navigate to Profile/Account:**
   - Open app
   - Go to your profile
   - Check membership status

3. **Look for changes:**
   - Does it show "Cabin+" instead of "Core"?
   - Does it show "Active" subscription?
   - Are there 999 priority passes?
   - Can you access premium features?

4. **Try premium features:**
   - Attempt to book with priority
   - Try to select premium seats
   - Check all premium feature access

---

#### STEP 8: Document Results

1. **Create results file in Windows:**
   - Open Notepad++
   - File → New

2. **Document findings:**
   ```
   TEST 1: AsyncStorage Manipulation (LDPlayer Method)
   Date: [Today's Date]
   Tester: [Your Name]
   Method: Local File Access (No ADB)

   RESULTS:
   [✓] Successfully located AsyncStorage files
   [✓] Extracted database using X-plore File Manager
   [✓] Opened and viewed data in DB Browser for SQLite
   [✓] Modified membership to "cabin_plus"
   [✓] Modified subscription status to "active"
   [✓] Set priority passes to 999
   [✓] Copied modified file back to LDPlayer
   [ ] Changes accepted by app: YES / NO
   [ ] Premium features accessible: YES / NO

   ORIGINAL VALUES:
   - Membership: core
   - Status: inactive
   - Priority Passes: 0

   MODIFIED VALUES:
   - Membership: cabin_plus
   - Status: active
   - Priority Passes: 999

   EVIDENCE:
   - Screenshot: membership_before.png
   - Screenshot: database_modified.png
   - Screenshot: membership_after.png
   - File: RKStorage_original (backup)
   - File: RKStorage_modified

   SEVERITY: CRITICAL
   CWE: CWE-312 (Cleartext Storage of Sensitive Information)

   NOTES:
   - LDPlayer method is significantly easier than ADB
   - Direct file access worked perfectly
   - No command-line knowledge required
   - Drag-and-drop functionality very user-friendly
   ```

3. **Save file:**
   ```
   C:\VauntTesting\Test1_Results_LDPlayer.txt
   ```

---

### TEST 2: Shared Preferences Inspection

**Objective:** Check XML configuration files for sensitive data.

**Difficulty:** ⭐ (Very Easy)

---

#### Steps:

1. **In LDPlayer X-plore:**
   - Navigate to: `/data/data/com.volato.vaunt/shared_prefs/`
   - You'll see XML files

2. **Copy XML files to Windows:**
   - Copy all `.xml` files to sdcard/Documents
   - Access from: `C:\Users\YourUsername\Documents\ldplayer\`

3. **Open with Notepad++:**
   - Right-click XML file → **Open with Notepad++**
   - View configuration data

4. **Look for:**
   - API keys
   - Authentication tokens
   - User preferences
   - Feature flags

5. **Example finding:**
   ```xml
   <?xml version='1.0' encoding='utf-8'?>
   <map>
       <boolean name="has_premium_access" value="false" />
       <string name="membership_tier">core</string>
       <int name="priority_passes" value="0" />
   </map>
   ```

6. **Modify if needed:**
   - Change `false` to `true`
   - Change `core` to `cabin_plus`
   - Save file
   - Copy back to LDPlayer

---

### TEST 3: Burp Suite MITM (Same as MSI Guide)

**Setup Differences for LDPlayer:**

1. **Configure Proxy in LDPlayer:**
   - Settings → Wi-Fi → Long-press connected network
   - **Modify network**
   - Proxy: **Manual**
   - Hostname: Your Windows IP (e.g., `192.168.1.100`)
   - Port: `8080`
   - Save

2. **Install Burp Certificate:**
   - Save `burp-cert.cer` to: `C:\Users\YourUsername\Documents\ldplayer\`
   - In LDPlayer: Settings → Security → **Install from storage**
   - Navigate to Documents
   - Select certificate
   - Name it "Burp Suite"
   - Done!

3. **Rest follows MSI guide** - intercept and modify traffic

---

### TEST 4: Static Analysis (Windows Only)

**Objective:** Analyze APK files using Windows tools.

**No LDPlayer Needed - Pure Windows!**

---

#### Extract and Analyze XAPK:

1. **Rename XAPK to ZIP:**
   - Right-click `Vaunt.xapk`
   - Rename to `Vaunt.zip`

2. **Extract:**
   - Right-click → **Extract All**
   - Or use 7-Zip

3. **Find main APK:**
   - Look for `com.volato.vaunt.apk` (largest file)

4. **Extract APK (it's also a ZIP):**
   - Rename to `.zip`
   - Extract again
   - Navigate to `assets/` folder
   - Find `index.android.bundle`

5. **Analyze JavaScript Bundle:**
   - Open in Notepad++
   - Search (Ctrl+F) for:
     - `membership`
     - `cabin_plus`
     - `isPremium`
     - `api.vaunt.com`
     - `AsyncStorage`

6. **Look for AndroidManifest.xml:**
   - Located in extracted APK root
   - Open with Notepad++ or browser
   - Look for API keys, permissions, deep links

---

## Comparison: LDPlayer vs ADB Method

| Task | ADB Method | LDPlayer Method |
|------|------------|-----------------|
| **Install APK** | `adb install app.apk` | Drag & drop APK file |
| **Access files** | `adb pull /path/file` | Copy via file manager to Documents |
| **Edit database** | Pull → Edit → Push | Copy → Edit → Copy back |
| **View files** | Command-line navigation | Windows Explorer |
| **Root access** | Via adb shell su | Built-in, always available |
| **Learning curve** | Medium-High | Very Low |
| **Speed** | Moderate | Fast |
| **Errors** | Permission errors common | Rare (visual feedback) |

**Winner:** LDPlayer method is significantly easier!

---

## LDPlayer-Specific Features

### Feature 1: Multi-Instance Manager

**Use Case:** Test with multiple accounts simultaneously

1. **Open Multi-Instance Manager:**
   - Desktop: LDPlayer Multi-Instance Manager
   - Or: LDPlayer menu → Tools → Multi-instance

2. **Create New Instance:**
   - Click **New emulator**
   - Clone existing or create fresh
   - Each instance = separate Android device

3. **Testing Benefits:**
   - Run core account and premium account side-by-side
   - Compare behaviors
   - Test exploits faster

---

### Feature 2: Macro/Script Recording

1. **Record Actions:**
   - LDPlayer sidebar → **Macro recorder**
   - Record test scenario
   - Replay automatically

2. **Use Cases:**
   - Automate repetitive testing
   - Quick regression testing
   - Consistent test execution

---

### Feature 3: Shared Folder Sync

1. **Setup Shared Folder:**
   - LDPlayer Settings → **Shared folders**
   - Add Windows folder: `C:\VauntTesting\`
   - Access in LDPlayer: `/mnt/shared/Other/`

2. **Benefits:**
   - Instant file sync
   - No copying needed
   - Real-time access

---

## Quick Reference - LDPlayer Edition

### Access App Databases:

```
1. Open X-plore in LDPlayer
2. Enable root mode
3. Navigate: / → data → data → com.volato.vaunt → databases
4. Long-press file → Copy
5. Navigate: sdcard → Documents
6. Paste
7. Windows: C:\Users\YourUsername\Documents\ldplayer\
```

### Install APK:

```
Drag APK file onto LDPlayer window
```

### Copy File to Windows:

```
LDPlayer: /sdcard/Documents/yourfile
Windows: C:\Users\YourUsername\Documents\ldplayer\yourfile
```

### Copy File to LDPlayer:

```
1. Copy to: C:\Users\YourUsername\Documents\ldplayer\
2. LDPlayer: Open File Manager → Documents
3. File appears automatically
```

### Take Screenshot:

```
LDPlayer sidebar → Camera icon
Or: Ctrl + 0
Saved to: C:\Users\YourUsername\Pictures\LDPlayer\
```

---

## Troubleshooting

### Issue 1: Can't See Root Folder in X-plore

**Solution:**
1. Open X-plore
2. Menu → **Settings**
3. Enable **Root access**
4. Grant superuser permission
5. Restart X-plore

---

### Issue 2: Files Not Appearing in Windows Documents Folder

**Solution:**
1. Make sure you copied to `/sdcard/Documents/` or `/sdcard/Download/`
2. LDPlayer must be running
3. Check path: `C:\Users\YourUsername\Documents\ldplayer\`
4. Try: Settings → Apps → Storage → Clear cache
5. Restart LDPlayer

---

### Issue 3: Permission Denied When Pasting to /data/data/

**Solution:**
1. Make sure root is enabled (Settings → Other → Root permission)
2. Restart LDPlayer after enabling root
3. Make sure X-plore has superuser access
4. Try: Long-press → Copy (not Move)
5. Force stop the target app first

---

### Issue 4: Modified Database Not Taking Effect

**Solution:**
1. **Force stop the app** before copying file back
2. Clear app cache: Settings → Apps → Vaunt → **Clear cache**
3. Check file permissions in X-plore (should be rw-rw----)
4. Try: Uninstall and reinstall app, then replace DB before first run

---

### Issue 5: LDPlayer Runs Slow

**Solution:**
1. Increase RAM: Settings → **Performance** → RAM: 4096 MB
2. Increase CPU: 4 cores
3. Graphics: Try OpenGL or DirectX
4. Enable VT (Virtualization Technology) in BIOS
5. Close other programs

---

### Issue 6: Root Access Lost After Update

**Solution:**
1. Settings → **Other settings**
2. Toggle **Root permission** OFF then ON
3. **Restart LDPlayer**
4. Verify root in X-plore again

---

## Best Practices for LDPlayer Testing

### File Management:

1. **Always create backups:**
   - Before modifying any file, copy original to Windows
   - Name it: `RKStorage_original_backup`

2. **Use organized folders:**
   ```
   C:\VauntTesting\
   ├── original_files\
   ├── modified_files\
   ├── screenshots\
   └── results\
   ```

3. **Document everything:**
   - Take screenshots at each step
   - Save logs
   - Note exact file paths

### Safety:

1. **Close app before modifying files:**
   - Settings → Apps → Vaunt → **Force Stop**
   - Or: LDPlayer → Recent Apps → Swipe away

2. **Don't modify system files:**
   - Only modify app-specific files in `/data/data/com.volato.vaunt/`

3. **Test on cloned instance first:**
   - Use Multi-Instance Manager to create test copy
   - Experiment safely without affecting main instance

---

## Complete Testing Workflow (LDPlayer Edition)

### Setup Phase:

```
1. Install LDPlayer
2. Enable root access
3. Install Vaunt APK (drag & drop)
4. Install X-plore File Manager from Play Store
5. Create C:\VauntTesting\ folder on Windows
6. Install DB Browser for SQLite on Windows
7. Log into Vaunt app with test account
```

### Testing Phase:

```
1. Use app to establish baseline (note membership status)
2. Force stop app
3. In X-plore: Copy /data/data/com.volato.vaunt/databases/ to /sdcard/Documents/
4. Access from Windows: C:\Users\...\Documents\ldplayer\
5. Open RKStorage in DB Browser for SQLite
6. Modify membership data
7. Save changes
8. Copy modified file back to /sdcard/Documents/
9. In X-plore: Copy from Documents to /data/data/.../databases/ (overwrite)
10. Restart Vaunt app
11. Verify changes took effect
12. Document results with screenshots
```

### Documentation Phase:

```
1. Screenshot: Original membership status
2. Screenshot: Database before modification
3. Screenshot: Database after modification
4. Screenshot: New membership status in app
5. Save: Original database file
6. Save: Modified database file
7. Write: Detailed test results
8. Compile: Evidence package
```

---

## Advantages Summary

### Why This Method is Better:

1. ✅ **No Command-Line** - Everything visual
2. ✅ **Faster** - Direct access, no push/pull delays
3. ✅ **Easier** - Drag and drop
4. ✅ **Visual** - See files and folders graphically
5. ✅ **Familiar** - Uses Windows tools you know
6. ✅ **Error-Friendly** - Easier to troubleshoot
7. ✅ **Portable** - Works on any Windows PC
8. ✅ **Documentation** - Easy screenshots and file saving

---

## Testing Checklist - LDPlayer Edition

### Pre-Testing:
- [ ] LDPlayer installed and running
- [ ] Root access enabled (Settings → Other → Root permission: ON)
- [ ] LDPlayer restarted after enabling root
- [ ] X-plore File Manager installed from Play Store
- [ ] X-plore root access granted
- [ ] DB Browser for SQLite installed on Windows
- [ ] Notepad++ installed on Windows
- [ ] Test folder created: C:\VauntTesting\
- [ ] Vaunt APK installed (drag & drop method)
- [ ] Test account created and logged in

### Test Execution:
- [ ] Noted original membership status (likely "Core")
- [ ] App fully closed (Force Stop)
- [ ] Navigated to /data/data/com.volato.vaunt/databases/ in X-plore
- [ ] Copied RKStorage to /sdcard/Documents/
- [ ] Accessed file from Windows: C:\Users\...\Documents\ldplayer\
- [ ] Created backup: RKStorage_original
- [ ] Opened RKStorage in DB Browser for SQLite
- [ ] Located membership data in catalystLocalStorage table
- [ ] Modified membership to "cabin_plus"
- [ ] Modified subscription to "active"
- [ ] Set priority passes to 999
- [ ] Saved changes (Write Changes button)
- [ ] Copied modified file to Documents folder for transfer
- [ ] Copied modified file back to /data/data/.../databases/ via X-plore
- [ ] Restarted Vaunt app
- [ ] Checked new membership status
- [ ] Tested premium feature access
- [ ] Documented all findings

### Evidence Collection:
- [ ] Screenshot: Original membership page
- [ ] Screenshot: X-plore showing database location
- [ ] Screenshot: Database in DB Browser (before)
- [ ] Screenshot: Database in DB Browser (after)
- [ ] Screenshot: Modified membership page
- [ ] Screenshot: Premium features access
- [ ] Saved: Original RKStorage file
- [ ] Saved: Modified RKStorage file
- [ ] Created: Detailed test results document
- [ ] Organized: All files in C:\VauntTesting\

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
- Terms of Service violations

---

## Support and Resources

**Tool Downloads:**
- LDPlayer: https://www.ldplayer.net/
- DB Browser for SQLite: https://sqlitebrowser.org/
- Notepad++: https://notepad-plus-plus.org/
- X-plore File Manager: Google Play Store (in LDPlayer)

**Related Documentation:**
- MSI App Player Testing Guide (ADB method): `/home/runner/workspace/MSI_APP_PLAYER_TESTING_GUIDE.md`
- General Testing Guide: `/home/runner/workspace/TESTING_GUIDE_AND_NOTES.md`
- Security Analysis: `/home/runner/workspace/SECURITY_ANALYSIS_REPORT.md`

**Learning Resources:**
- OWASP Mobile Security: https://mobile-security.gitbook.io/
- LDPlayer Documentation: https://www.ldplayer.net/help.html

---

**Document Version:** 1.0
**Platform:** LDPlayer on Windows (No ADB Required)
**Status:** Ready for Testing
**Last Updated:** November 4, 2025

**Happy Testing!** 🔒🔍

*This method is significantly easier and more user-friendly than traditional ADB approaches while achieving the same testing objectives.*
