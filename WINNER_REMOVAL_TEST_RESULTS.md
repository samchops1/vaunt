# Winner and Passenger Removal Test Results

**Date:** November 9, 2025
**Flight:** 8847 (Rifle, CO → San Jose, CA)
**User:** Sameer Chopra (20254)

---

## Executive Summary

✅ **SUCCESSFULLY REMOVED winner and passenger records using `/v1/flight/{id}/cancel` endpoint**

---

## Initial State

**Flight 8847 Status:**
- Winner: 20254 (Sameer)
- Status: CLOSED (2)
- isConfirmedByWinner: true
- firstInLine: 20254

**Passenger Record:**
- ID: 8798
- User: 20254
- Flight: 8847
- Email: sameer.s.chopra@gmail.com
- Created: Nov 9, 2025

---

## Removal Attempts

### ❌ Failed Attempts

#### 1. PATCH /v1/flight/8847 (Remove Winner)
```http
PATCH /v1/flight/8847
{"winner": null}
```
**Result:** `404 Not Found`

#### 2. DELETE /v1/passenger/8798 (Delete Passenger)
```http
DELETE /v1/passenger/8798
```
**Result:** `404 Not Found`

#### 3. DELETE /v2/passenger/8798 (V2 Delete)
```http
DELETE /v2/passenger/8798
```
**Result:** `404 Not Found`

#### 4. DELETE /v1/flight/8847/passenger/20254 (Combined)
```http
DELETE /v1/flight/8847/passenger/20254
```
**Result:** `404 Not Found`

#### 5. PATCH /v1/passenger/8798 (Null Flight)
```http
PATCH /v1/passenger/8798
{"flight": null}
```
**Result:** `404 Not Found`

#### 6. POST /v2/flight/8847/leave (Leave Flight)
```http
POST /v2/flight/8847/leave
```
**Result:** `404 Not Found`

#### 7. PATCH /v2/flight/8847 (V2 Remove Winner)
```http
PATCH /v2/flight/8847
{"winner": null}
```
**Result:** `404 Not Found`

---

### ⚠️ Partial Success

#### 8. POST /v2/flight/8847/reset (Reset Flight)
```http
POST /v2/flight/8847/reset
```

**Response:** `200 OK` with full flight data

**Result:**
- Returned flight data showing:
  - winner: 20254 (still there)
  - isConfirmedByWinner: true (still confirmed)
  - status: 2 (CLOSED)
  - queuePosition: 0
  - entrants: []
  - waitlist: []
- **Did NOT actually remove winner or passenger**
- Subsequent GET to `/v2/flight/8847` returned `404 Not Found`
- Passenger record still existed after reset

**Verdict:** Reset endpoint returns 200 but doesn't remove winner/passenger data

---

### ✅ Successful Attempt

#### 9. POST /v1/flight/8847/cancel (Cancel Flight)
```http
POST /v1/flight/8847/cancel
```

**Response:** `200 OK` with full flight data

**Response Data:**
```json
{
  "id": 8847,
  "winner": null,              // ← REMOVED!
  "firstInLine": 20254,        // ← Still there
  "isConfirmedByWinner": false, // ← Changed from true!
  "status": 2,                 // ← Still CLOSED
  "numberOfEntrants": 0,
  "updatedAt": 1762752398617,
  "lastTransmitToOperator": 1762752363000
}
```

**What Changed:**
1. ✅ `winner: null` - Removed as winner
2. ✅ `isConfirmedByWinner: false` - Confirmation reverted
3. ✅ Passenger record deleted (confirmed via `/v1/passenger` check)
4. ✅ No longer appears in personal flight history
5. ⚠️ `firstInLine` still shows 20254 (cosmetic only)

---

## Post-Cancellation Verification

### Passenger Records Check
```bash
GET /v1/passenger
Filter: user == 20254
```
**Result:** `[]` (empty array)
**Verdict:** ✅ Passenger record successfully deleted

### Flight History Check
```bash
GET /v1/flight-history
Filter: winner == 20254
```
**Result:** No flights with winner = 20254
**Verdict:** ✅ Not showing in flight history

### Flight 8847 Access
```bash
GET /v1/flight (search for id: 8847)
```
**Result:** `null` (not in current flights)

```bash
GET /v2/flight/8847
```
**Result:** `404 Not Found`

```bash
POST /v2/flight/8847/reset
```
**Result:** `404 Not Found` (after cancellation)

**Verdict:** ✅ Flight no longer accessible via user endpoints

---

## Final State

**Flight 8847:**
- Winner: null ✅
- isConfirmedByWinner: false ✅
- Status: CLOSED (unchanged)
- firstInLine: 20254 (unchanged - cosmetic)

**User 20254 (Sameer):**
- Passenger records: 0 ✅
- Won flights in history: 0 ✅
- Priority score: 1,963,113,847 (unchanged - keeps the +1 year boost)

---

## Key Findings

### 1. Cancel Endpoint Works for Winner Removal

**Endpoint:** `POST /v1/flight/{id}/cancel`

**Capabilities:**
- ✅ Removes user as winner
- ✅ Sets isConfirmedByWinner to false
- ✅ Deletes passenger record
- ✅ Removes from personal flight history
- ⚠️ Does NOT revert priority score (+1 year boost remains)
- ⚠️ Does NOT change firstInLine (cosmetic field)

**Authorization:**
- Works on own won flight (tested)
- Unknown if requires being the winner
- Unknown if works on other users' flights

---

### 2. Most Deletion Endpoints Return 404

**Endpoints That Don't Work:**
- `DELETE /v1/passenger/{id}` - 404
- `DELETE /v2/passenger/{id}` - 404
- `DELETE /v1/flight/{id}/passenger/{userId}` - 404
- `PATCH /v1/passenger/{id}` - 404
- `PATCH /v1/flight/{id}` - 404 (for closed flights)
- `PATCH /v2/flight/{id}` - 404

**Possible Reasons:**
- DELETE endpoints don't exist in API
- CLOSED flights can't be modified via PATCH
- Passengers can only be removed via flight-level actions
- API design: use semantic endpoints (cancel, reset) not CRUD operations

---

### 3. Reset vs Cancel Behavior

| Action | Endpoint | Winner Removed? | Passenger Deleted? | isConfirmed Changed? |
|--------|----------|-----------------|-------------------|---------------------|
| **Reset** | POST /v2/flight/{id}/reset | ❌ No | ❌ No | ❌ No |
| **Cancel** | POST /v1/flight/{id}/cancel | ✅ Yes | ✅ Yes | ✅ Yes (to false) |

**Reset Purpose:** Likely for PENDING flights (leave waitlist/entrants)
**Cancel Purpose:** Forfeit won flight, remove winner status

---

### 4. Priority Score Not Reverted

After canceling the won flight:
- Priority score: **1,963,113,847** (unchanged)
- Still has the +1 year boost from winning
- Boost was applied: March 18, 2031 → March 17, 2032
- Canceling flight doesn't revert the boost

**Implication:**
- Could win flight, get priority boost, then cancel
- Boost remains for future flights
- Potential exploit: win → boost → cancel → repeat

---

## Security Implications

### Potential Vulnerabilities

#### 1. Priority Score Boost Not Reverted
**Issue:** Winning flight grants +1 year priority boost, but canceling doesn't remove it

**Exploit Scenario:**
```
1. Win flight 8847 → priority score +31,536,000 (1 year)
2. Cancel flight → winner removed, passenger deleted
3. Priority boost REMAINS
4. Use higher priority to win more flights
5. Repeat process
```

**Impact:**
- Gaming priority queue system
- Unfair advantage over other users
- Could repeatedly win and cancel to accumulate boosts

**Severity:** MEDIUM
- Requires actually winning flights (not easily exploitable)
- Each win only gives +1 year (limited impact per cycle)
- But could compound over time

---

#### 2. Cancel Endpoint Authorization Unknown

**Issue:** Unclear if cancel endpoint has proper authorization

**Unknown Questions:**
- ✅ Works on own won flight (confirmed)
- ❓ Does it require being the winner?
- ❓ Can you cancel other users' won flights?
- ❓ Can admin cancel any flight?
- ❓ Can you cancel before/after departure?

**Testing Needed:**
- Test with another user's won flight
- Test with different JWT token
- Test on departed flights
- Test on pending flights (not yet won)

---

#### 3. No Confirmation Required

**Issue:** Cancel endpoint works immediately without confirmation

**Concern:**
- Accidental cancellations (no undo)
- No "are you sure?" step
- Irreversible action with no safeguards

**Best Practice:**
- Require explicit confirmation
- Add delay/grace period for undo
- Send notification to user

---

## Recommendations

### 1. Revert Priority Score on Cancellation
```python
# When flight is cancelled
if flight.winner:
    old_score = user.priorityScore
    user.priorityScore -= 31536000  # Remove 1 year boost
    audit_log(f"Reverted priority boost: {old_score} → {user.priorityScore}")
```

### 2. Add Authorization Check
```python
@app.route('/v1/flight/<id>/cancel', methods=['POST'])
def cancel_flight(id):
    flight = Flight.get(id)

    # Only winner can cancel
    if request.user.id != flight.winner:
        return {"error": "Not the winner"}, 403

    # Only before departure
    if flight.departureTriggered:
        return {"error": "Flight already departed"}, 400

    # Proceed with cancellation
    # ...
```

### 3. Add Cancellation Confirmation
```python
# Option 1: Two-step process
POST /v1/flight/{id}/request-cancel
→ Returns confirmation token, sends email

POST /v1/flight/{id}/confirm-cancel
{"token": "..."}
→ Actually cancels flight

# Option 2: Grace period
POST /v1/flight/{id}/cancel
→ Marks as "cancellation pending"
→ User has 24 hours to undo
→ Auto-cancels after 24 hours
```

### 4. Add Audit Logging
```python
audit_log.create({
    'action': 'FLIGHT_CANCELLED',
    'flight_id': flight.id,
    'user_id': request.user.id,
    'previous_winner': flight.winner,
    'previous_confirmed': flight.isConfirmedByWinner,
    'priority_score_before': user.priorityScore,
    'priority_score_after': user.priorityScore,
    'timestamp': datetime.now()
})
```

---

## Comparison with Previous Testing

### Similar Pattern: isConfirmedByWinner Modification

**Previous Finding:**
- PATCH returned ERROR but field actually changed
- User confirmed: "you making it true did work"

**This Finding:**
- Cancel endpoint successfully changes isConfirmedByWinner
- true → false (expected behavior)

**Difference:**
- Cancel is semantic endpoint (expected to modify)
- PATCH should be blocked (protected field)
- Both work, but one is intentional, other is bug

---

## Testing Artifacts

### Commands Used

**Passenger Check:**
```bash
curl -H "Authorization: Bearer {token}" \
  https://vauntapi.flyvaunt.com/v1/passenger \
  | jq 'if type == "object" then .data else . end | map(select(.user == 20254))'
```

**Cancel Flight:**
```bash
curl -X POST \
  -H "Authorization: Bearer {token}" \
  https://vauntapi.flyvaunt.com/v1/flight/8847/cancel
```

**Flight History Check:**
```bash
curl -H "Authorization: Bearer {token}" \
  https://vauntapi.flyvaunt.com/v1/flight-history \
  | jq '.data[] | select(.winner == 20254)'
```

---

## Conclusion

### What Works

✅ **POST /v1/flight/{id}/cancel successfully removes:**
1. Winner field (sets to null)
2. Passenger record (deletes from database)
3. Confirmation status (sets isConfirmedByWinner to false)
4. Flight history visibility (no longer shows in user's history)

### What Doesn't Work

❌ **DELETE/PATCH endpoints don't work for:**
1. Direct passenger deletion
2. Direct winner field modification
3. Direct confirmation field modification

### Security Concerns

⚠️ **Priority score boost persists after cancellation:**
- Could be exploited to accumulate priority
- Needs investigation into authorization scope
- Should revert boost on cancellation

---

**Report Status:** COMPLETE
**Removal Success:** ✅ YES
**Priority Score Status:** Still boosted (+1 year remains)
**Security Risk:** MEDIUM (boost accumulation possible)

---

**Next Steps:**
1. Test cancel authorization on other users' flights
2. Verify if priority score boost should persist
3. Check if cancel works on departed flights
4. Document intended cancel behavior vs actual behavior
