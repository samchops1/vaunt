# Quick Interception Steps - Vaunt App

**Goal:** Capture the "leave waitlist" API call in 5 minutes

---

## Fastest Method: Charles Proxy

### Setup (Do Once)
1. Download Charles: https://www.charlesproxy.com/download/
2. Install and start Charles
3. Get your computer's IP: `ipconfig` (Windows) or `ifconfig` (Mac)
   - Example: `192.168.1.100`

### Configure Phone
**iPhone:**
- Settings → Wi-Fi → (i) button → HTTP Proxy → Manual
- Server: `192.168.1.100` (your computer IP)
- Port: `8888`
- Safari → Open `chls.pro/ssl` → Install certificate
- Settings → General → About → Certificate Trust → Enable Charles

**Android:**
- Settings → Wi-Fi → Long press network → Modify → Proxy Manual
- Hostname: `192.168.1.100`
- Port: `8888`
- Chrome → Open `chls.pro/ssl` → Download & install certificate

### Capture the Call
1. **Charles → Edit → Clear** (clear history)
2. Open Vaunt app
3. Join any PENDING (future) flight
4. **Immediately leave/cancel that flight** ⚠️
5. In Charles: Look for the newest POST/DELETE/PUT request
6. Click on it → Note:
   - Method: ____________________
   - URL: ____________________
   - Body: ____________________

---

## What I Need From You

```
Method: [POST/DELETE/PUT/PATCH/etc]
Full URL: https://vauntapi.flyvaunt.com/v1/[ENDPOINT]
Request Body (if any): {...}
Response Status: [200/201/204/etc]
```

---

## Visual Checklist

```
☐ Downloaded Charles Proxy
☐ Got computer IP address
☐ Configured phone proxy settings
☐ Installed certificate on phone
☐ Cleared Charles history
☐ Opened Vaunt app (should see traffic)
☐ Joined a PENDING flight in app
☐ Left/cancelled that flight in app
☐ Found the request in Charles
☐ Documented: Method, URL, Body
```

---

## Common Issues

**App says "No Internet"?**
- Restart the app after setting proxy
- Make sure computer and phone on same WiFi

**No traffic in Charles?**
- Phone proxy pointing to correct IP?
- Port is 8888?
- Certificate installed AND trusted?

**SSL errors in app?**
- Go to Certificate Trust Settings (iPhone)
- Enable full trust for Charles certificate

---

## Screenshot These in Charles

When you find the "leave waitlist" call:

1. **Overview tab** - Shows method and URL
2. **Request tab** - Shows headers and body
3. **Response tab** - Shows status code

Send me all 3 screenshots!

---

## Alternative: Just Try in App First

If setup seems complex, first just try this:

1. Open Vaunt app
2. Join a PENDING flight (any future flight)
3. Try to leave/cancel it
4. **Did it work? YES / NO**
5. What button did you press?
6. Screenshot the button

This tells us if the app even CAN leave PENDING flights.

---

**Once you have the info, paste it here or create a file called `CAPTURED_ENDPOINT.txt`**
