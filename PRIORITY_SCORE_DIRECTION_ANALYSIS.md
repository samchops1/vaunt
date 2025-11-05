# Priority Score Direction Analysis - API Data Only

**Date:** November 5, 2025
**Analysis Method:** Live API Testing (No Markdown File Assumptions)
**Accounts Tested:**
- Sameer (User 20254): Priority Score 1,931,577,847, Subscription Status: 3 (Cabin+)
- Ashley (User 171208): Priority Score 1,761,681,536, Subscription Status: None (Basic)

---

## Executive Summary

**Question:** Does a HIGHER or LOWER priority score result in better queue positions?

**Answer:** ⚠️ **CANNOT BE DEFINITIVELY DETERMINED FROM API DATA ALONE**

**Reason:** Insufficient data points and confounding variables prevent causal determination.

---

## Testing Methodology

All testing was conducted using ONLY live API calls to production endpoints. No assumptions were made based on documentation or decompiled code.

### API Endpoints Used:
- `GET /v1/user` - User profile with priority score
- `GET /v1/flight` - Available flights and waitlist data
- `GET /v1/flight/{id}` - Individual flight details
- `GET /v1/flight-history` - Historical flight participation
- `GET /v1/user/{id}` - Other user profiles (tested for IDOR)

---

## Data Collected

### Account Profiles (from `/v1/user`)

**Sameer:**
```json
{
  "id": 20254,
  "priorityScore": 1931577847,
  "subscriptionStatus": 3,
  "phoneNumber": "+13035234453"
}
```

**Ashley:**
```json
{
  "id": 171208,
  "priorityScore": 1761681536,
  "subscriptionStatus": null,
  "phoneNumber": "+17203521547"
}
```

**Observation:** Sameer has HIGHER score (170M point difference)

---

### Waitlist Participation (from `/v1/flight`)

**Sameer:**
- Currently on **7 waitlists**
- Average position: **#1.0**
- Position distribution:
  - Position #0: 4 flights
  - Position #1: 1 flight
  - Position #2: 1 flight
  - Position #4: 1 flight

**Ashley:**
- Currently on **0 waitlists**
- No position data available

**Observation:** Cannot compare positions - no overlapping flights

---

### Users Who Beat Sameer

From 3 flights where Sameer was NOT in position #0:

| Flight ID | Sameer Position | Users Ahead | Total Entrants |
|-----------|----------------|-------------|----------------|
| 5431 | #1 | User 54125 | 2 |
| 5424 | #4 | Users 28547, 35631, 25222, 70535 | 11 |
| 5442 | #2 | Users 36062, 40825 | 4 |

**Attempted to query these users:**
- Result: All returned `404 Not Found`
- Indicates: IDOR protection prevents accessing other users' data
- **Cannot see their priority scores for comparison**

---

### Flight History Analysis (from `/v1/flight-history`)

**Sameer:** 10 flights, 0 won, 0.0% win rate
**Ashley:** 10 flights, 0 won, 0.0% win rate

**Historical position data:** None available in flight history responses

**Observation:** No historical evidence to correlate score with outcomes

---

## Analysis Attempts

### ❌ Attempt 1: Direct Competition
**Method:** Find flights where both accounts are on the same waitlist
**Result:** 0 overlapping flights found
**Conclusion:** Cannot directly compare positions

### ❌ Attempt 2: Query Other Users' Scores
**Method:** Get profiles of users who beat Sameer (54125, 28547, 35631, etc.)
**Result:** All returned 404 (IDOR protection)
**Conclusion:** Cannot see if users ahead have higher or lower scores

### ❌ Attempt 3: Historical Position Tracking
**Method:** Analyze flight history for position changes over time
**Result:** Flight history does not include position data
**Conclusion:** No temporal data available

### ❌ Attempt 4: API Endpoint Discovery
**Method:** Test for endpoints like `/v1/leaderboard`, `/v1/rankings`, `/v1/user/priority`
**Result:** All returned 404
**Conclusion:** No additional scoring metadata exposed

### ❌ Attempt 5: Subscription Status Isolation
**Method:** Determine if subscription alone determines position
**Result:** Both accounts see same 112 flights, but only Sameer on waitlists
**Conclusion:** Cannot isolate subscription vs score effects

---

## Confounding Variables

### Problem: Multiple Variables Correlated

**Sameer (good positions):**
- Higher score (1.93B)
- Cabin+ subscription (status 3)

**Ashley (no positions):**
- Lower score (1.76B)
- Basic subscription (status None)

**Cannot determine if Sameer's good positions are due to:**
1. Having a HIGHER priority score, OR
2. Having a Cabin+ subscription, OR
3. Both factors combined

---

## What Would Be Needed for Definitive Answer

### Option 1: Direct Competition
- Both accounts on the same flight waitlist
- Compare their queue positions directly
- **Status:** Not currently available

### Option 2: Other Users' Scores
- Access priority scores of users ahead of Sameer
- See if they have higher or lower scores than 1.93B
- **Status:** Blocked by IDOR protection (404)

### Option 3: Score Variation Within Same Tier
- Find two Cabin+ users with different scores
- Compare their positions on same flight
- **Status:** Cannot access other users' data

### Option 4: API Documentation
- Endpoint that reveals scoring formula
- Metadata explaining score calculation
- **Status:** No such endpoint found

### Option 5: Controlled Test
- Change one account's score (if possible)
- Observe position changes
- **Status:** No API for modifying scores

---

## Correlation vs Causation

### Observed Correlation:
```
Higher Score (Sameer: 1.93B) → Better Positions (avg #1.0)
Lower Score (Ashley: 1.76B)  → No Positions (0 waitlists)
```

### Possible Explanations:

**Hypothesis A: Higher Score = Better**
- Sameer's high score → good positions
- Ashley's low score → no positions
- **Problem:** Confounded by subscription status

**Hypothesis B: Subscription Status = Primary Factor**
- Cabin+ members get priority regardless of score
- Basic members can't join waitlists (or don't)
- Score only matters within same tier
- **Problem:** Can't test without seeing other Cabin+ users

**Hypothesis C: Both Factors Combined**
- Subscription status determines tier eligibility
- Priority score determines position within tier
- **Problem:** Need more data points to confirm

---

## Data Limitations

### What the API Exposes:
✅ Own priority score
✅ Own queue positions
✅ Other users' IDs on same flights
✅ Other users' partial names
✅ Other users' queue positions
✅ Total entrants per flight

### What the API Does NOT Expose:
❌ Other users' priority scores
❌ Other users' subscription status
❌ Scoring formula or calculation
❌ Historical position data
❌ Score change logs
❌ Leaderboards or rankings
❌ Why specific positions were assigned

---

## Conclusion

### Definitive Statement:

**From API data alone, it is IMPOSSIBLE to prove whether higher or lower priority scores result in better queue positions.**

### Observed But Unproven:
- Sameer (higher score, Cabin+) has good positions
- Ashley (lower score, basic) has no positions
- Correlation exists but causation cannot be established

### Why We Cannot Conclude:

1. **No Direct Comparison:** Both accounts never compete on same flight
2. **IDOR Protection:** Cannot see other users' scores who beat Sameer
3. **Confounding Variable:** Subscription status correlates with both score and positions
4. **No Historical Data:** Cannot track score-position relationships over time
5. **No API Metadata:** System doesn't expose scoring logic

### Confidence Level:

**0%** - Cannot make any definitive claim about direction based solely on API data

---

## Recommendations for Future Testing

### To Definitively Determine Direction:

1. **Get Ashley on a waitlist** - Have both accounts join same flight to compare positions directly

2. **Access Production Database** - If authorized, query database directly to see:
   - All users' priority scores
   - Their corresponding positions
   - Correlation analysis

3. **Code Review** - Review backend queue assignment logic (if source code access available)

4. **Developer Documentation** - Consult internal API documentation or ask engineering team

5. **A/B Test** - If score can be modified, change one account's score and observe position changes

---

## Methodological Note

This analysis adhered strictly to empirical API testing without making assumptions from:
- Decompiled APK code
- Markdown documentation files
- Variable names or comments
- Previous security reports

Only live production API responses were used as evidence.

---

**Prepared by:** Independent Security Analysis
**Date:** November 5, 2025
**Status:** INCONCLUSIVE - Insufficient data for causal determination
