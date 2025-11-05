# Vaunt API Security Research Dashboard

A React-based security research dashboard demonstrating API vulnerabilities and security testing for the Vaunt flight booking service.

![Security Research](https://img.shields.io/badge/Type-Security%20Research-red)
![Status](https://img.shields.io/badge/Status-Active-green)

---

## 🎯 Project Overview

This dashboard is a **proof-of-concept security research tool** built to:
- Demonstrate API security testing methodologies
- Document Vaunt API capabilities and limitations
- Test for IDOR (Insecure Direct Object Reference) vulnerabilities
- Analyze authentication and authorization controls
- Display flight information and waitlist data

**⚠️ Disclaimer:** This is for security research and educational purposes only.

---

## 🚀 Quick Start

1. **Access the Dashboard**
   - Click "Run" to start the development server
   - Dashboard will open automatically in the webview

2. **Select Account**
   - Choose between Sameer Chopra (Cabin+) or Ashley Rager (Free)
   - Each account has different tier privileges

3. **Pull Live Data**
   - Click "Pull Live Data" to fetch current flight information
   - View waitlist entries and flight details

4. **View User Details**
   - Click on any name in waitlist tables to see available user information
   - Limited to public entrant data (no full PII access)

---

## 📚 Documentation

### Security Reports

| Document | Description | Status |
|----------|-------------|--------|
| **[SQL_SMS_SECURITY_REPORT.md](SQL_SMS_SECURITY_REPORT.md)** | 🔴 **SQL injection & SMS security vulnerabilities** | **Nov 5, 2025** |
| [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md) | ✅ Comprehensive API security testing results | Nov 5, 2025 |
| [SECURITY_ANALYSIS_REPORT.md](SECURITY_ANALYSIS_REPORT.md) | Mobile app decompilation & vulnerability analysis | Nov 3, 2025 |
| [API_EXPLOITATION_GUIDE.md](API_EXPLOITATION_GUIDE.md) | API endpoint documentation & usage patterns | Oct 2024 |
| [DUFFEL_BOOKING_ANALYSIS.md](DUFFEL_BOOKING_ANALYSIS.md) | Duffel booking integration analysis | Oct 2024 |

### Key Findings

**🔴 SMS Authentication: CRITICAL VULNERABILITIES** ⚠️ **NEW**
- NO rate limiting on SMS requests (SMS bombing possible)
- NO rate limiting on code verification (account takeover via brute force)
- User enumeration possible (registered vs unregistered numbers)
- See [SQL_SMS_SECURITY_REPORT.md](SQL_SMS_SECURITY_REPORT.md) for details

**🟡 SQL Injection: LOW-MEDIUM RISK** ⚠️ **NEW**
- Most endpoints properly protected
- Requires investigation: 500 errors in `completeSignIn` phoneNumber field (generic error, no SQL details leaked)
- No data exfiltration possible
- Assessment: Likely input validation issue, not confirmed SQL injection

**✅ API Authorization: GOOD**
- No IDOR vulnerabilities found
- Authorization controls working correctly
- Users can only access own data

**🟡 Privacy Concern: MINOR**
- Flight waitlist data exposes user names and positions
- No email/phone/address exposure via API

**❌ Mobile App: HIGH RISK**
- Client-side data manipulation possible
- See SECURITY_ANALYSIS_REPORT.md for details

---

## 🧪 Security Testing Performed

### 1. Authentication Testing ⚠️
- ✅ JWT token payload injection attempts blocked (userId, admin flags)
- ✅ SQL injection in most authentication fields blocked
- 🔴 SMS rate limiting: **CRITICAL VULNERABILITY** - No rate limiting found
- 🔴 Code verification rate limiting: **CRITICAL VULNERABILITY** - No lockout after 50+ attempts
- 🟡 User enumeration via SMS responses possible

**Result:** JWT payload security strong, but SMS authentication has critical vulnerabilities.

### 2. IDOR Testing ✅
- ✅ User PII access attempts (`/v1/user/:userId`)
- ✅ Entrant data access (`/v1/entrant/:entrantId`)
- ✅ Cross-user data queries
- ✅ Unauthorized profile access

**Result:** No IDOR vulnerabilities found. All blocked with 404.

### 3. Waitlist Manipulation ✅
- ✅ Join waitlist endpoints (all return 404)
- ✅ Remove from waitlist (all return 404)
- ✅ Cross-user waitlist manipulation

**Result:** All manipulation endpoints disabled or non-existent.

### 4. SQL Injection Testing ⚠️ **NEW**
- 🧪 26 different SQL injection payloads tested
- ✅ Authentication endpoints properly protected (400 errors)
- ✅ Flight endpoints properly protected
- ⚠️ One endpoint (completeSignIn phoneNumber) returns 500 errors
  - No SQL error details leaked (generic "Internal Server Error")
  - Likely input validation issue, not confirmed SQL injection
  - Requires further investigation

**Result:** Most endpoints protected. One potential input validation issue identified.

### 5. SMS Authentication Security Testing 🔴 **NEW - CRITICAL**
- 🧪 **Extended testing with 50+ attempts per vulnerability**
- 🔴 SMS Rate Limiting: **50/50 requests succeeded** - NO rate limiting
- 🔴 Code Verification: **50/50 attempts processed** - NO rate limiting
- 🟡 User Enumeration: Confirmed (200 vs 500 status codes)

**Methodology:** Extended testing approach used to ensure definitive conclusions:
- SMS initiation: 50 consecutive requests to confirm no rate limiting
- Code verification: 50 consecutive attempts to confirm no lockout mechanism
- Error analysis: Detailed examination of response bodies and headers

**Result:** Critical vulnerabilities confirmed in SMS authentication system.

---

## 🔍 What the Dashboard Shows

### ✅ Data Accessible
- Your own complete user profile (email, phone, subscription)
- All flights with departure/arrival details
- Waitlist entrant data for all flights:
  - First name, last name
  - Queue position
  - Carbon offset enrollment
  - Referral count

### ❌ Data NOT Accessible
- Other users' email addresses
- Other users' phone numbers
- Other users' addresses
- Other users' payment information
- Ability to join/leave waitlists (API endpoints disabled)

---

## 🛠️ Technical Stack

- **Frontend:** React + Vite
- **Styling:** Tailwind CSS
- **HTTP Client:** Fetch API
- **Authentication:** Hardcoded JWT tokens (for research only)
- **API:** Vaunt API (https://vauntapi.flyvaunt.com)

### Project Structure
```
├── src/
│   └── components/
│       └── Dashboard.jsx          # Main dashboard component
├── api_testing/                   # Python security test scripts
│   ├── check_user_26927.py       # IDOR vulnerability tests
│   └── check_user_26927_detailed.py
├── SECURITY_TEST_RESULTS.md      # Comprehensive security report
├── SECURITY_ANALYSIS_REPORT.md   # Mobile app analysis
├── API_EXPLOITATION_GUIDE.md     # API documentation
└── DUFFEL_BOOKING_ANALYSIS.md    # Booking integration
```

---

## 🔐 Test Accounts

**Sameer Chopra** (Cabin+ Tier)
- User ID: 20254
- Tier: Cabin+
- Features: Premium access, priority upgrades

**Ashley Rager** (Free Tier)
- User ID: 171208
- Tier: Free
- Features: Basic access

**Target User** (for IDOR testing)
- User ID: 26927
- Entrant ID: 34740

---

## 📊 API Endpoints Tested

### ✅ Working Endpoints
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/v1/auth/initiateSignIn` | POST | No | Trigger SMS code |
| `/v1/auth/completeSignIn` | POST | No | Get JWT token |
| `/v1/user` | GET | Yes | Get own profile |
| `/v1/flight` | GET | Yes | List all flights |
| `/v1/flight/:id` | GET | Yes | Get flight details |

### ❌ Non-Existent Endpoints (404)
- `/v1/user/:userId` - Direct user access
- `/v1/entrant/:entrantId` - Direct entrant access
- `/v1/waitlist/join` - Join waitlist
- `/v1/waitlist/remove` - Remove from waitlist
- All other IDOR-vulnerable endpoints

See [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md) for complete endpoint inventory.

---

## 🎓 Educational Value

This project demonstrates:

1. **Security Testing Methodology**
   - How to test for IDOR vulnerabilities
   - Authentication bypass techniques
   - Input validation testing
   - Authorization control verification

2. **API Security Best Practices**
   - Proper JWT token scoping
   - Input validation importance
   - Authorization vs authentication
   - Secure API design patterns

3. **Ethical Security Research**
   - Responsible disclosure
   - Testing boundaries
   - Documentation practices

---

## ⚠️ Ethical Considerations

This research was conducted:
- ✅ Without causing harm or disruption
- ✅ Using legitimate test accounts
- ✅ With educational intent
- ✅ Following responsible disclosure principles
- ✅ Without attempting to access production data maliciously

**Important:** The findings demonstrate that Vaunt's API has strong authorization controls (IDOR protection, proper JWT scoping), but **critical vulnerabilities exist in SMS authentication** (no rate limiting on SMS requests or code verification). Mixed security posture overall.

---

## 📝 License & Disclaimer

**For Educational and Security Research Purposes Only**

This dashboard and associated documentation are provided for:
- Security research and education
- Demonstrating security testing techniques
- Understanding API security best practices

**Not intended for:**
- Unauthorized access to systems
- Malicious exploitation
- Production use
- Commercial purposes

---

## 🤝 Contributing

This is a security research project. Findings and improvements welcome through:
1. Review of security testing methodology
2. Additional test cases
3. Documentation improvements
4. Responsible disclosure of findings

---

## 📧 Contact

For security concerns or responsible disclosure, please contact the appropriate parties through official channels.

---

*Last Updated: November 5, 2025*  
*Research Dashboard v1.0*
