# Available Flights - Production API

## Summary
Sameer Chopra (Cabin+) has **10 flights** available on the production API.

All flights show **STATUS: CLOSED** (already completed or past deadline).

---

## Flight #1 - ID: 5779
**Route:** Denver (KBJC) → Bermuda Dunes, CA (KUDD)

**Departure:** Dec 17, 2024 @ 3:00 PM MST (22:00 UTC)  
**Arrival:** Dec 17, 2024 @ 3:59 PM PST

**Aircraft:** N844JS (Type 11)  
**Status:** CLOSED  
**Tier:** Cabin+ only

**Waitlist:**
- Position #0: **Sameer Chopra (ID: 20254)** - WINNER 🏆
- Position #1: Abd A (ID: 37311)

**Passenger on board:** Sameer Chopra

**Notes:**
- Winner notification sent 6 times
- Last transmitted to operator: Dec 17, 2024
- Charter price: $3,967

---

## Flight #2 - ID: 6077
**Route:** Denver (KBJC) → Scottsdale, AZ (KSDL)

**Departure:** Dec 20, 2024 @ 3:00 PM MST  
**Arrival:** Dec 20, 2024 @ 4:03 PM MST

**Aircraft:** N844JS (Type 11)  
**Status:** CLOSED  
**Tier:** Cabin+ only

**Waitlist:**
- Position #0: **Sameer Chopra (ID: 20254)** - WINNER 🏆
- Position #1: Kev P (ID: 51729)

**Passenger on board:** Sameer Chopra

**Notes:**
- Charter price: $3,967
- Winner notification sent 6 times

---

## Key Observations:

### ✅ Sameer's Flight Activity:
- **Won multiple flights** (position #0 on waitlist = winner)
- **Actually flew** on these flights (passenger data confirms boarding)
- All flights are **CLOSED** (completed)

### 🎯 Waitlist System:
- `queuePosition: 0` = Winner (gets the seat)
- `queuePosition: 1` = Second place (standby)
- Priority score determines queue position

### 🛫 Flight Details:
- All flights are **Cabin+ tier** (tierClassification: "cabin+")
- Aircraft type 11 (likely Citation or similar)
- Routes primarily from Denver to California/Arizona
- Charter prices around $3,967 per flight

### 📊 Status Meanings:
- Status ID 2 = "CLOSED"
- Flights have `deletedAt` timestamps
- `notifyWinnerAt` shows when winner was selected
- `closeoutDateTime` is booking deadline

---

## Ashley's Flights:
Ashley Rager (Basic account) sees **0 flights** because:
- She doesn't have Cabin+ membership
- All current flights are Cabin+-only ("tierClassification": "cabin+")
- Basic members likely see different/future flights

---

## What This Means:

1. **Sameer is actively using the service** - He won and flew on multiple flights
2. **Priority score matters** - He's position #0 on waitlist = best priority
3. **No active flights right now** - All 10 visible flights are closed/completed
4. **Cabin+ grants access** - These flights are exclusive to premium members

The flights shown are Sameer's **flight history**, not upcoming flights. This explains why they're all closed.
