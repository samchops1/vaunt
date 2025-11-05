# Vaunt API Security Research Dashboard

## Overview
A React-based security research dashboard for testing and demonstrating Vaunt API security. The dashboard allows researchers to explore flight data, analyze waitlist information, and test for common API vulnerabilities like IDOR (Insecure Direct Object Reference), authentication bypass, and unauthorized data access.

## Tech Stack
- **Frontend**: React + Vite, Tailwind CSS
- **Authentication**: Hardcoded JWT tokens (research purposes)
- **API**: Vaunt API (https://vauntapi.flyvaunt.com)
- **Deployment**: Port 5000 (frontend only)

## Project Structure
```
/
├── src/
│   └── components/
│       └── Dashboard.jsx          # Main security research dashboard
├── api_testing/                   # Python security test scripts
│   ├── check_user_26927.py       # IDOR vulnerability tests
│   └── check_user_26927_detailed.py
├── SECURITY_TEST_RESULTS.md      # Comprehensive security testing report (Nov 5, 2025)
├── SECURITY_ANALYSIS_REPORT.md   # Mobile app decompilation analysis (Nov 3, 2025)
├── API_EXPLOITATION_GUIDE.md     # API endpoint documentation
├── DUFFEL_BOOKING_ANALYSIS.md    # Booking integration analysis
├── README.md                      # Project documentation & navigation
└── package.json                   # Node dependencies
```

## Recent Changes
- **2025-11-05**: ✅ Completed comprehensive API security testing
  - Tested authentication payload injection (SMS/JWT)
  - Tested IDOR vulnerabilities (user data, waitlist manipulation)
  - Confirmed API has strong security controls
  - Created SECURITY_TEST_RESULTS.md with full findings
  - Updated all documentation with cross-references
  - Created README.md as master index

- **2025-11-04**: Fixed user details modal to show entrant data instead of 404 errors
- **2025-11-04**: Updated carbon offset display and waitlist functionality
- **2025-11-04**: Fixed Replit webview accessibility (vite.config.js allowedHosts)
- **2025-11-03**: Initial security research dashboard setup

## Features

### Dashboard Capabilities
- Switch between test accounts (Sameer - Cabin+, Ashley - Free)
- Pull live flight data from Vaunt API
- View waitlist entries with user details
- Display flight information (routes, times, available seats)
- Click user names to view entrant details
- Filter flights by city/airport
- View Duffel booking integration data
- Action log for API request tracking

### Security Testing Features
- IDOR vulnerability testing
- Authentication bypass attempts
- Payload injection testing
- User data access verification
- Waitlist manipulation testing
- JWT token analysis

## Architecture
- Frontend-only React app running on port 5000
- Direct API calls to https://vauntapi.flyvaunt.com
- Uses hardcoded JWT tokens for two test accounts
- All security testing via Python scripts in api_testing/

## Security Research Findings

### ✅ API Security: GOOD
- **Authentication**: SMS-based JWT properly implemented, no bypass possible
- **Authorization**: User data access properly restricted (no IDOR)
- **Input Validation**: SQL injection and payload injection blocked
- **Data Access**: Users can only access their own PII

### 🟡 Privacy Concern: MINOR
- Flight waitlist data exposes user names and queue positions
- No email/phone/address exposed via API

### Test Accounts
- **Sameer Chopra** (User 20254) - Cabin+ tier
- **Ashley Rager** (User 171208) - Free tier
- **Target User** (User 26927, Entrant 34740) - For IDOR testing

## User Preferences
- Focus on security research and vulnerability testing
- Document all findings comprehensively
- Test both working and non-existent endpoints
- Maintain ethical research practices

## Documentation
All security findings are documented in:
1. **SECURITY_TEST_RESULTS.md** - Latest comprehensive API security testing (Nov 5, 2025)
2. **SECURITY_ANALYSIS_REPORT.md** - Mobile app vulnerability analysis (Nov 3, 2025)
3. **README.md** - Master index and project overview
