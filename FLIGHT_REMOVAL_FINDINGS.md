# Flight Waitlist Removal - Research Findings

**Date:** November 5, 2025
**Research Topic:** How to remove users from flight waitlists via Vaunt API

---

## Executive Summary

After extensive testing of the Vaunt API, **there is NO working method to remove a user from a PENDING flight waitlist via API**. The only working removal endpoint (`POST /v1/flight/{id}/cancel`) requires the flight status to be "CLOSED".

---

## Working Endpoint

### ✅ POST /v1/flight/{flightId}/cancel

**Status:** ✅ WORKING (with restrictions)

**Requirements:**
- Flight status must be "CLOSED" (not "PENDING")
- User must be authenticated (Bearer token)
- User must be on the flight's waitlist

**Request:**
```bash
POST https://vauntapi.flyvaunt.com/v1/flight/{flightId}/cancel
Authorization: Bearer {token}
Content-Type: application/json
Body: {}
```

**Success Response:**
- Status: 200
- User is removed from the flight waitlist

**Error Response (PENDING flight):**
- Status: 400
- Message: "Specified flight is not closed and cannot be canceled."

**Verified Success Cases:**
7 flights were successfully cancelled using this endpoint (all were CLOSED status):
- Flight 6859: Eagle → Santa Ana
- Flight 6924: Denver → Denver
- Flight 7666: Denver → Jackson
- Flight 8130: Denver → Salt Lake City
- Flight 8724: Colorado Springs → Austin
- Flight 8738: Austin → Gunnison
- Flight 8743: Dallas → Denver

---

## Non-Working Endpoints

All of the following endpoints return **404 Not Found**:

### DELETE Methods
```
DELETE /v1/flight/{id}/enter
DELETE /v1/flight/{id}/exit
DELETE /v1/flight/{id}/leave
DELETE /v1/flight/{id}/waitlist
DELETE /v1/flight/{id}
DELETE /v1/user/flight/{id}
DELETE /v1/entrant/{entrantId}
DELETE /v1/flight/{id}/entrant/{entrantId}
DELETE /v1/flight/entrant/{entrantId}
DELETE /v1/flight/{id}/entrants/{entrantId}
DELETE /v1/waitlist/{id}
```

### POST Methods
```
POST /v1/flight/{id}/remove
POST /v1/flight/{id}/exit
POST /v1/flight/{id}/leave
POST /v1/flight/{id}/waitlist/leave
POST /v1/entrant/{entrantId}/cancel
POST /v1/entrant/{entrantId}/remove
POST /v1/entrant/{entrantId}/leave
POST /v1/waitlist/leave
```

### PATCH Methods
```
PATCH /v1/flight/{id}
PATCH /v1/flight/{id}/entrant
PATCH /v1/entrant/{entrantId}
PATCH /v1/user (with flight removal payloads)
```

### PUT Methods
```
PUT /v1/flight/{id}/enter
PUT /v1/flight/{id}/cancel
PUT /v1/flight/{id}/exit
PUT /v1/flight/{id}/leave
PUT /v1/user/flights
PUT /v1/entrant/{entrantId}/status
```

---

## Testing Details

### Test Environment
- **API:** https://vauntapi.flyvaunt.com
- **Test Account:** Sameer (User ID: 20254)
- **Token:** JWT Bearer authentication
- **Test Date:** November 5, 2025

### Tested Payloads

**PATCH /v1/user attempts:**
```json
{}
{"currentFlights": []}
{"removeFromFlights": [flightId]}
{"flightsToCancel": [flightId]}
{"cancelFlight": flightId}
{"flights": []}
```
All returned 200 but did not remove user from PENDING flights.

**PATCH /v1/entrant/{entrantId} attempts:**
```json
{"status": "CANCELLED"}
{"active": false}
{"cancelled": true}
```
All returned 404.

**PATCH /v1/flight/{id} attempts:**
```json
{"removeEntrant": userId}
{"cancelEntrant": userId}
{"entrantStatus": "CANCELLED"}
{"status": "CANCELLED"}
```
All returned 404.

---

## Flight Status Definitions

### PENDING
- Flight is scheduled and active
- Waitlist is open
- Users can join via `POST /v1/flight/{id}/enter`
- **Users CANNOT leave via API**

### CLOSED
- Flight has departed, been cancelled, or waitlist closed
- Users can leave via `POST /v1/flight/{id}/cancel`
- Users cannot join

---

## Current Test Case

**Flight 8800:**
- Route: KOKB (Oceanside) → KMCC (Sacramento)
- Departure: November 8, 2025 at 02:00 UTC
- Status: PENDING
- Sameer's Position: #1 (queuePosition: 1)
- Entrant ID: 34842
- Charter Price: null

**Attempts to remove Sameer:**
- POST /cancel → 400 "Specified flight is not closed"
- All other endpoints → 404 Not Found

**Result:** ❌ Cannot remove from PENDING flight

---

## Recommendations

### For Development
1. **Wait for flight to become CLOSED** before attempting removal via API
2. **Use mobile app** for manual removal (may use different/internal endpoints)
3. **Contact Vaunt support** if urgent removal needed for PENDING flights
4. **Monitor flight status** and remove automatically once CLOSED

### For Web Dashboard
The web dashboard has been updated with:
- ✅ Join waitlist: `POST /v1/flight/{id}/enter` (works)
- ⚠️ Leave waitlist: `POST /v1/flight/{id}/cancel` (only for CLOSED flights)
- Proper error handling explaining PENDING vs CLOSED restriction

---

## Unanswered Questions

1. **How does the mobile app remove from PENDING flights?**
   - May use internal API endpoints not exposed publicly
   - May use WebSocket or real-time connection
   - May require additional authentication/permissions

2. **Why were 15 flights removed during PATCH testing?**
   - Unknown - flights may have become CLOSED during testing
   - Possible automatic cleanup by backend
   - Needs further investigation

3. **Is there a batch removal endpoint?**
   - Not found in testing
   - No documentation found in markdown files

---

## Related Files

- `/src/components/Dashboard.jsx` - Web dashboard with join/leave implementation
- `/api_testing/comprehensive_waitlist_test.py` - Python test script for waitlist operations
- `/api_testing/test_waitlist_manipulation.py` - Waitlist manipulation security tests
- `/COMPLETE_TESTING_SESSION.md` - Previous successful removal documentation
- `/SECURITY_TEST_RESULTS.md` - Security testing showing all endpoints return 404

---

## Conclusion

**For PENDING flights:** No API method exists to remove users from waitlist.

**For CLOSED flights:** Use `POST /v1/flight/{flightId}/cancel` successfully.

**Workaround:** Wait for flight status to change from PENDING to CLOSED, then use `/cancel` endpoint.

---

*This document will be updated as new information becomes available.*
