# Agent Knowledge Base – Vaunt App

## API Overview
- Base API: `https://qa-vauntapi.flyvaunt.com`; Bearer-authenticated JWTs issued via `/v1/auth/initiateSignIn` + `/v1/auth/completeSignIn`.
- Core user endpoint: `GET /v1/user` returns membership, `subscriptionStatus`, `priorityScore`, and profile metadata; protected fields ignored on `PUT /v1/user`.
- Subscription control: `/v1/subscription/paymentIntent`, `/v1/subscription/restore`, `/v1/subscription/pk`; payment flow depends on Stripe publishable key `pk_live_51Is7UdBkrWmvysmuX4hyzaPiAKfXxkFvYabmpKe6igGDXdUjT9nL4bJRyS4ngfKw6SwqpmEoxrP3vU8GwBBHkwMr00GkDgedAF`.
- Flight data: `/v1/flight/available`, `/v1/flight/current`, `/v1/flight-history`; upgrade offers via `/v1/app/upgrade-offer/list`.
- No SSL certificate pinning; all calls observable with MITM tooling.

## Duffel Integration
- Confirmed endpoints under `/v1/app/duffel/*` (airlines, place-suggestions, orders, create-hold-order) and `/v1/duffel/stays/*` for hotel flows.
- React Native bundle includes dedicated Duffel booking screens (search, class selection, checkout, order detail, hotel map/filter).
- Sameer (Cabin+) snapshot shows zero Duffel orders to date; priority-score linkage remains server-side and undetermined.

## Client Data & Storage
- Expo/React Native app stores session state in SQLite `RKStorage` (`authenticationStore.jwt`, `userStore.authenticatedUser`, `paymentStore.stripePk`); no at-rest encryption, `android:allowBackup="true"`.
- Premium account snapshot: `subscriptionStatus: 3`, `membershipTier: "cabin+"`, `priorityScore: 1931577847`.
- Push/analytics identifiers (OneSignal app ID, FCM token, AppsFlyer install ID, Facebook analytics IDs) present in shared prefs.

## Security Posture Highlights
- Stripe live publishable key bundled; multiple third-party credentials exposed in `assets/app.config` (Facebook client token, Intercom API keys, OneSignal app ID, LogRocket repo, EAS project ID).
- Client weaknesses: no certificate pinning, plaintext token storage, broad permissions (`RECORD_AUDIO`, `SYSTEM_ALERT_WINDOW`, `ACCESS_ADSERVICES_*`), missing root/jailbreak detection.
- Server-side protections observed: membership writes rejected, priority score reset during tests; Ashley’s JWT returns 401, while Sameer’s remains valid.

## Testing Playbook
1. Acquire JWT via in-app capture or `/v1/auth/*` flow.
2. Baseline `GET /v1/user` and `GET /v1/flight/available`.
3. Attempt guarded updates (`PUT /v1/user`), `POST /v1/subscription/restore`, zero-amount `/v1/subscription/paymentIntent`.
4. Exercise Duffel endpoints (e.g., `/v1/app/duffel/place-suggestions?query=City`) and monitor for priority-score deltas.
5. Document all responses and compare against snapshots in `FINAL_COMPREHENSIVE_RESULTS.md` and `API_TESTING_RESULTS.md`.

