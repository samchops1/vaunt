# 📊 Vaunt API Dashboard - User Guide

Welcome to the comprehensive Vaunt API Testing Dashboard! This tool allows you to explore the Vaunt private jet booking API, view flight data, check waitlist positions, and access all security research documentation.

---

## 🚀 Quick Start

### Dashboard Tab

1. **Select Account**
   - Choose between Sameer Chopra (Cabin+) or Ashley Rager (Free) accounts
   - Each has different membership tiers and access levels

2. **Click "Check All APIs"**
   - Fetches all API data in parallel
   - Shows user info, flights, waitlist, upgrades, and Duffel bookings
   - Real-time data from Production API

3. **View Results**
   - **User Information**: Name, email, priority score, membership tier
   - **Available Flights**: All open flights with schedules and aircraft details
   - **Your Waitlist**: Current waitlist positions and rankings
   - **Priority Upgrades**: Available upgrades (free and paid)
   - **Duffel Bookings**: Commercial flights and hotel bookings

### Documents Tab

Browse the complete knowledge base of security research:

- **Main Documentation** - Project overview and findings
- **Duffel Integration** - Commercial flight/hotel booking analysis
- **Security Analysis** - Vulnerability assessments
- **API Guide** - Complete API exploitation documentation
- **Testing Results** - All API testing outcomes
- **And 10+ more documents**

---

## 📋 What You Can Check

### Priority Score System
- View current priority scores
- See timestamp-based calculations
- Understand membership boost (3-6 years for Cabin+)
- Track score changes over time

### Flight Information
- All available flights with:
  - Departure/arrival airports and times
  - Aircraft type and seat availability
  - Flight status (OPEN/CLOSED)
  - Flight IDs for tracking

### Waitlist Status
- Current position on waitlists
- Flight details for waitlisted trips
- Priority-based ranking
- Scheduled departure times

### Priority Upgrades
- Available upgrades (free and paid)
- Upgrade IDs and types
- Cost breakdown
- Used vs. available status

### Duffel Integration
- Commercial flight bookings through Duffel API
- Hotel reservation tracking
- Order history and details
- Integration with Vaunt app

---

## 🔍 Key Findings Summary

### ✅ Confirmed Features

1. **Duffel Integration**
   - Active API endpoints for commercial flights and hotels
   - Full booking flow implemented
   - Accessible via `/v1/app/duffel/*` endpoints

2. **Priority Score System**
   - Timestamp-based (higher = better)
   - Cabin+ members get 3-6 year boost
   - Server-side calculation only
   - Cannot be manipulated via API

3. **Waitlist Mechanics**
   - Position calculated by priority score
   - Cannot be modified via API
   - Upgrades must be applied through mobile app
   - Read-only via API

### ❌ Failed Attack Vectors

1. **Membership Bypass** - 13 attempts, all blocked
2. **Trial Activation** - Endpoints return 404
3. **Webhook Simulation** - Security intact
4. **Waitlist Manipulation** - 25+ endpoints, all blocked
5. **Score Modification** - Silently ignored by server

### ❓ Unknown/Unconfirmed

1. **Priority Score Boost from Duffel Bookings**
   - Integration exists but boost mechanism hidden
   - No API evidence of rewards/points system
   - Likely server-side only

---

## 🎯 Testing Capabilities

### Real-Time API Access
- Production API: `vauntapi.flyvaunt.com`
- QA API: `qa-vauntapi.flyvaunt.com`
- Valid bearer tokens for both test accounts

### Available Endpoints
- `/v1/user` - User profile and priority score
- `/v1/flight` - Available flights
- `/v1/flight-waitlist` - Waitlist entries
- `/v1/waitlist-upgrade` - Priority upgrades
- `/v1/app/duffel/*` - Commercial bookings
- And 50+ more documented endpoints

---

## 📚 Documentation Library

### Security Research
- `SECURITY_ANALYSIS_REPORT.md` - Comprehensive security findings
- `HONEST_SECURITY_ASSESSMENT.md` - Reality check on exploits
- `REALITY_CHECK.md` - What actually works vs. claims

### API Testing
- `API_EXPLOITATION_GUIDE.md` - Complete API documentation
- `API_TESTING_RESULTS.md` - All test outcomes
- `IDOR_AND_PRIORITY_FINDINGS.md` - Priority score investigation

### Integration Analysis
- `DUFFEL_BOOKING_ANALYSIS.md` - Commercial flight/hotel research
- `API_INTERCEPTION_ANALYSIS.md` - Traffic analysis

### Testing Guides
- `TESTING_GUIDE_AND_NOTES.md` - How to test manually
- `COMPLETE_LDPLAYER_TESTING_SUITE.md` - Android emulator testing
- `MSI_APP_PLAYER_TESTING_GUIDE.md` - Alternative testing methods

---

## 💡 Tips & Tricks

### For Researchers
1. Use the "Check All APIs" button to get a complete snapshot
2. Compare data between Sameer (Cabin+) and Ashley (Free) accounts
3. Check Documents tab for detailed exploit analysis
4. Priority score changes are calculated server-side - can't be gamed

### For Users
1. Your priority score is based on membership tier + flight behavior
2. Free upgrades are available - use them via mobile app
3. Commercial flight/hotel bookings may boost score (unconfirmed)
4. Waitlist position is automatic - can't be manually changed

### For Developers
1. All API calls use Bearer token authentication
2. CORS is enabled for testing
3. Server validates and sanitizes all inputs
4. Protected fields are silently ignored on PATCH requests

---

## 🔒 Security Notes

### What's Secure
- ✅ Membership tier modifications blocked
- ✅ Trial activation endpoints disabled
- ✅ Webhook simulation prevented
- ✅ Waitlist position calculated server-side
- ✅ Priority score manipulation silently ignored

### Areas of Concern
- ⚠️ IDOR possible (view any user's public data)
- ⚠️ Priority score algorithm not publicly documented
- ⚠️ Duffel booking boost mechanism unknown

---

## 📞 Support & Resources

### Need Help?
- Check the Documents tab for detailed guides
- All API endpoints are documented in `API_EXPLOITATION_GUIDE.md`
- Security findings in `SECURITY_ANALYSIS_REPORT.md`

### Found a Bug?
This is a research tool. Any issues should be documented in the appropriate markdown file in the Documents section.

---

## 🎉 Features

- ✈️ Real-time flight data
- 📋 Waitlist position tracking
- 🎁 Priority upgrade management
- 🌐 Duffel commercial booking integration
- 📚 Complete documentation library
- 🔍 Comprehensive API testing
- 📊 Beautiful, responsive UI
- 🚀 Fast, parallel API calls

---

**Last Updated**: November 2025  
**Version**: 1.0  
**Tested On**: Production API (vauntapi.flyvaunt.com)
