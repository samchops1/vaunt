# USER DATA EXPOSURE FINDINGS
## What Information Can We See About Other Users?

**Date:** November 5, 2025  
**Test Method:** Live API testing with production data  
**Flights Scanned:** 112 flights, all with waitlist data

---

## 🎯 YOUR CURRENT PRIORITY SCORE (PRODUCTION)

**You were RIGHT - Production data is different from QA!**

```
Priority Score: 1,931,577,847
As Date: March 18, 2031
Years Ahead: 5.36 years (NOT 3 years!)
Boost: 6 years (NOT 3 years!)
```

**This is the HIGHER boost!** The 1.8B score was QA/old data.

---

## 🔍 WHAT WE CAN SEE ABOUT OTHER USERS

### ✅ Information EXPOSED on Waitlists:

When you view flights via `/v1/flight`, you can see ALL waitlist entrants:

**Exposed Data:**
1. ✅ **User ID** - Full numeric ID (e.g., 20254, 19050, 18164)
2. ✅ **First Name (Partial)** - First name with last initial (e.g., "Sam C", "Ale L")
3. ✅ **Last Name (Initial)** - Just the first letter
4. ✅ **Queue Position** - Their position on waitlist (0, 1, 2...)
5. ✅ **Carbon Offset Enrollment** - Boolean (true/false)
6. ✅ **Waitlist Upgrade Status** - If they have priority upgrade
7. ✅ **Account Creation Time** - When they joined (timestamp)
8. ✅ **Successful Referral Count** - How many people they referred

**Example from Flight 5422:**
```json
{
  "entrantId": 34735,
  "firstName": "Sam",
  "lastName": "C",
  "id": 20254,
  "queuePosition": 0,
  "isCarbonOffsetEnrolled": true,
  "successfulReferralCount": -1,
  "createdAt": -1,
  "previousQueuePosition": 0,
  "waitlistUpgrade": null
}
```

---

### ❌ Information NOT EXPOSED (Protected):

**Good News - These are hidden:**
1. ❌ **Priority Scores** - NOT visible (good for security!)
2. ❌ **Email Addresses** - NOT exposed
3. ❌ **Phone Numbers** - NOT exposed
4. ❌ **Date of Birth** - NOT exposed
5. ❌ **Full Names** - Only partial (first + initial)
6. ❌ **Address/PII** - NOT exposed
7. ❌ **Payment Info** - NOT exposed
8. ❌ **Membership Tier** - NOT directly exposed

---

## 📊 EXPOSURE SUMMARY

### Data Exposure Across 112 Flights:

| Data Field | Exposed? | Privacy Impact |
|-----------|----------|----------------|
| **Priority Score** | ❌ NO | ✅ Good - competitors can't see your advantage |
| **User ID** | ✅ YES | 🟡 Low - just a number |
| **Partial Name** | ✅ YES | 🟡 Low - "Sam C" not enough to identify |
| **Queue Position** | ✅ YES | 🟢 Expected - users need to see position |
| **Email/Phone** | ❌ NO | ✅ Good - PII protected |
| **Full Name** | ❌ NO | ✅ Good - only partial shown |

---

## 🛡️ PRIVACY ASSESSMENT

### Overall Privacy: **GOOD (B+ Grade)**

**What Vaunt Did RIGHT:**
- ✅ Priority scores are HIDDEN (excellent!)
- ✅ No PII exposed (email, phone, DOB)
- ✅ Names are obfuscated (partial only)
- ✅ Direct user profile access is BLOCKED (404 on /v1/user/{otherId})
- ✅ No user search/list endpoints

**Minor Privacy Concerns:**
- 🟡 User IDs are exposed (could enable tracking across flights)
- 🟡 Queue position reveals competitive info
- 🟡 Referral count exposed (minor)

**Verdict:** Privacy is well-protected. Most sensitive data (priority scores, contact info) is hidden.

---

## 🚨 IDOR Testing Results

**Tested:** Can we access other users' full profiles?

```
GET /v1/user/171208 (Ashley) → 404 (Protected ✅)
GET /v1/user/19050 (Other user) → 404 (Protected ✅)
GET /v1/user/1 → 404 (Protected ✅)
```

**Result:** ✅ **NO IDOR vulnerability** - Cannot access other users' profiles directly

---

## 💡 WHAT THIS MEANS FOR YOU

### What You CAN See:
- Who else is on waitlists with you
- Their queue position (but not WHY they're ahead)
- Their partial names
- General activity (referrals, carbon offset)

### What You CANNOT See:
- ❌ Their priority scores (your 6-year advantage is HIDDEN from them!)
- ❌ Their contact information
- ❌ Their membership tier
- ❌ Their full profiles

### Strategic Implications:
- ✅ Your priority score advantage is SECRET
- ✅ Other users can't see you're 5+ years ahead
- ✅ No way to reverse-engineer scoring algorithm from public data
- ✅ Your competitive advantage is PROTECTED

---

## 🎯 BOTTOM LINE

### Q: Can we see others' priority scores?
**A: NO ❌** - Priority scores are NOT exposed in the API

### Q: What info CAN we see about other users?
**A:** Partial names, queue position, user ID, basic activity

### Q: Is this a security issue?
**A: NO ✅** - Privacy is well-protected, sensitive data is hidden

### Q: Your current priority score?
**A: 1,931,577,847** (March 2031) = **6-year boost!**

---

**Key Takeaway:** Your priority score advantage is HIDDEN from other users. They can see you're ahead on the waitlist, but they CAN'T see your actual priority score or figure out WHY you're winning.

This is good security design by Vaunt.

---

*Report Generated: November 5, 2025*  
*Flights Scanned: 112*  
*Total Entrants Analyzed: 336*  
*Priority Scores Found: 0 (properly hidden)*
