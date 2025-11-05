# Mobile App Network Interception Guide
## Capturing the "Leave Waitlist" API Call from Vaunt App

**Date:** November 5, 2025
**Objective:** Intercept mobile app traffic to discover the exact endpoint used to remove from PENDING flights

---

## Overview

Since we cannot find the removal endpoint through API testing, we'll intercept the actual network traffic from the Vaunt mobile app to see the exact HTTP request it makes.

---

## Option 1: Charles Proxy (Recommended - Easiest)

**Time Required:** 15-20 minutes
**Difficulty:** Easy
**Works On:** iPhone or Android

### Prerequisites
- Windows/Mac computer
- Vaunt app on your phone
- Phone and computer on same WiFi network

### Step 1: Install Charles Proxy

1. Download Charles Proxy:
   - Website: https://www.charlesproxy.com/download/
   - Free trial available (30 days)
   - Works on Windows, Mac, Linux

2. Install and launch Charles Proxy

3. Note the proxy port (default: 8888)

### Step 2: Get Your Computer's IP Address

**On Windows:**
```bash
ipconfig
```
Look for "IPv4 Address" under your WiFi adapter (usually 192.168.x.x)

**On Mac:**
```bash
ifconfig | grep "inet " | grep -v 127.0.0.1
```

**Example:** Your IP might be `192.168.1.100`

### Step 3: Configure Charles for SSL Proxying

1. In Charles: **Proxy → SSL Proxying Settings**
2. Check "Enable SSL Proxying"
3. Click "Add" under "Include"
4. Enter:
   - Host: `*.flyvaunt.com`
   - Port: `443`
5. Click "OK"

### Step 4: Install Charles Certificate on Your Phone

**Get the certificate:**
1. Charles → **Help → SSL Proxying → Install Charles Root Certificate on a Mobile Device**
2. Charles will show instructions with URL like `chls.pro/ssl`

**On iPhone:**
1. Settings → Wi-Fi → Tap your network's (i) button
2. Scroll to "HTTP Proxy" → Select "Manual"
3. Server: `192.168.1.100` (your computer's IP)
4. Port: `8888`
5. Leave Authentication OFF
6. Open Safari and go to `chls.pro/ssl`
7. Download the profile
8. Settings → Profile Downloaded → Install
9. Settings → General → About → Certificate Trust Settings
10. Enable full trust for Charles Proxy

**On Android:**
1. Settings → Wi-Fi → Long press your network → Modify
2. Advanced options → Proxy: Manual
3. Hostname: `192.168.1.100` (your computer's IP)
4. Port: `8888`
5. Save
6. Open Chrome and go to `chls.pro/ssl`
7. Download certificate
8. Settings → Security → Install from storage
9. Find downloaded certificate and install
10. Name it "Charles Proxy"

### Step 5: Capture the "Leave Waitlist" API Call

1. **Clear Charles history:**
   - Charles → **Edit → Clear** (or Cmd/Ctrl+K)

2. **Open Vaunt app on your phone**

3. **Join a PENDING flight:**
   - Browse flights
   - Find any future flight
   - Join the waitlist
   - ✅ You should see API calls in Charles

4. **Now LEAVE the waitlist:**
   - In the app, find the flight you just joined
   - Tap to leave/cancel/remove from waitlist
   - ⚠️ **THIS IS THE CRITICAL CALL WE NEED**

5. **In Charles, look for the API call that just happened:**
   - Look for requests to `flyvaunt.com` or `vauntapi.flyvaunt.com`
   - It will be a POST, DELETE, PUT, or PATCH request
   - Click on it

6. **Document the request:**
   - **Method:** (POST/DELETE/PUT/PATCH)
   - **URL:** Full endpoint path
   - **Headers:** Any special headers
   - **Body:** Request payload (if any)

### Step 6: Send Me the Details

Take a screenshot or write down:
```
Method: [POST/DELETE/PUT/PATCH]
URL: https://vauntapi.flyvaunt.com[ENDPOINT]
Headers:
  Authorization: Bearer [token]
  Content-Type: application/json
  [any other headers]
Body:
  {any JSON data here}
```

---

## Option 2: mitmproxy (Advanced - More Powerful)

**Time Required:** 30 minutes
**Difficulty:** Moderate
**Best For:** Technical users comfortable with command line

### Step 1: Install mitmproxy

**On Windows:**
```bash
# Download from https://mitmproxy.org/
# Or use pip:
pip install mitmproxy
```

**On Mac:**
```bash
brew install mitmproxy
```

**On Linux:**
```bash
sudo apt install mitmproxy
```

### Step 2: Start mitmproxy

```bash
mitmproxy --listen-port 8888
```

Or for web interface:
```bash
mitmweb --listen-port 8888 --web-port 8081
```

### Step 3: Configure Phone (Same as Charles Step 4)

- Get your computer's IP
- Set phone proxy to your computer IP:8888
- Install mitmproxy certificate from `mitm.it`

### Step 4: Filter for Vaunt API Calls

**In mitmproxy:**
1. Press `f` to set filter
2. Enter: `~d flyvaunt.com`
3. Press Enter

**In mitmweb:**
- Open browser: `http://localhost:8081`
- Set filter: `~d flyvaunt.com`

### Step 5: Capture Leave Waitlist Call

1. Join a flight in the app
2. Leave the flight
3. In mitmproxy, find the request that just happened
4. Press Enter to view details
5. Note down the method, URL, headers, and body

### Step 6: Export Request Details

**In mitmweb:**
- Click on the request
- Click "Export" → Copy as curl

Send me the curl command!

---

## Option 3: Android Developer Tools (Android Only)

**Time Required:** 10 minutes
**Difficulty:** Easy
**Best For:** Android devices with USB debugging

### Requirements
- Android device
- USB cable
- Chrome browser on computer

### Steps

1. **Enable USB Debugging:**
   - Settings → About Phone → Tap "Build Number" 7 times
   - Settings → Developer Options → Enable USB Debugging

2. **Connect to Computer:**
   - Connect phone via USB
   - Allow USB debugging popup

3. **Open Chrome DevTools:**
   - Open Chrome browser on computer
   - Go to: `chrome://inspect/#devices`
   - You should see your phone listed

4. **Inspect Vaunt App:**
   - Click "Inspect" next to com.volato.vaunt
   - Go to "Network" tab

5. **Capture Traffic:**
   - In app: Join then leave a flight
   - In DevTools: Find the leave request
   - Right-click → Copy → Copy as cURL

---

## What to Look For

When you capture the "leave waitlist" call, it might look like:

**Possibility 1: Simple POST**
```
POST /v1/flight/8800/leave
```

**Possibility 2: With Body**
```
POST /v1/flight/8800/cancel
Body: {"reason": "user_requested"}
```

**Possibility 3: Different Path**
```
DELETE /v1/user/flights/8800
```

**Possibility 4: Internal Endpoint**
```
POST /internal/v1/flight/8800/remove
```

**Possibility 5: Different Base URL**
```
POST https://internal-api.flyvaunt.com/v1/flight/8800/cancel
```

---

## Common Issues & Solutions

### Issue: "SSL Certificate Invalid" in app

**Solution:** Make sure you:
1. Installed the certificate
2. Trusted the certificate (iPhone: Certificate Trust Settings)
3. Restarted the app after installing certificate

### Issue: "No traffic showing in Charles"

**Solution:**
1. Check phone proxy settings are correct
2. Make sure phone and computer on same network
3. Disable VPN on phone if enabled
4. Try airplane mode on/off to reset connection

### Issue: "Certificate won't install"

**For iPhone:**
- Make sure you opened `chls.pro/ssl` in Safari (not Chrome)
- Go to Settings → Profile Downloaded to install
- Must enable trust in Certificate Trust Settings

**For Android:**
- Try downloading certificate file directly
- Use Settings → Security → Install from storage
- May need to set screen lock PIN first

### Issue: "App says no internet connection"

**Solution:**
- Charles might be blocking requests
- Try: Charles → Proxy → Stop Recording
- Or: Charles → Proxy → SSL Proxying Settings → Clear the include list
- Then re-add only `*.flyvaunt.com`

---

## Quick Test: Verify It's Working

Before capturing the leave call, verify interception is working:

1. Open Vaunt app on phone
2. Let it load the flight list
3. Check Charles - you should see:
   ```
   GET https://vauntapi.flyvaunt.com/v1/flight
   GET https://vauntapi.flyvaunt.com/v1/user
   ```

If you see these, interception is working! ✅

---

## After Capturing the Call

Once you have the details, send me:

1. **The exact HTTP method** (POST/DELETE/PUT/PATCH)
2. **The complete URL** including endpoint
3. **Any special headers** (besides Authorization and Content-Type)
4. **The request body** (if any)

I'll then:
1. Test the endpoint with our Python scripts
2. Update the web dashboard to use the correct endpoint
3. Verify it works for PENDING flights
4. Document the solution

---

## Alternative: Ask Me to Do a Simpler Test

If network interception seems too complex, we can try:

**Simple Test Plan:**
1. Join Flight 8800 (or any PENDING flight) in your app
2. Try to leave it
3. Tell me: **Did it work? What button did you click?**
4. Take a screenshot of the button/screen

This will at least confirm whether the mobile app can actually leave PENDING flights, or if it also has the same limitation.

---

## Expected Timeline

- **Setup:** 15-20 minutes
- **Capture:** 2-3 minutes
- **Documentation:** 5 minutes
- **Total:** ~30 minutes

---

## Need Help?

If you get stuck at any step:
1. Take a screenshot of where you're stuck
2. Tell me what step you're on
3. I'll provide more detailed guidance

---

**Ready to proceed?** Start with Charles Proxy (Option 1) - it's the easiest and most reliable method.

---

*This guide will help us discover the missing endpoint and finally solve the PENDING flight removal puzzle!*
