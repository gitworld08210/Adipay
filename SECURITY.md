# Adipay security model

This is what protects a gateway that holds your money flow. Read it before going live.

## Who can do what

| Caller | Can | Cannot |
| --- | --- | --- |
| **Anyone on the internet** | open the customer checkout, read the status of *their own* payment id, `GET /health` | read or change anything under `/api/v1/admin/*`, create orders, confirm payments, inject bank alerts |
| **Your server** (holds `PAYMENT_API_KEYS`) | `POST /api/v1/payments` to create an order with a price *your server* chose | use the admin dashboard |
| **A paired Android phone** | send signed bank-SMS events and heartbeats | anything else; its key only signs events |
| **The Gmail/SMS observer process** (holds `OBSERVER_INGEST_SECRET`) | send signed events, read its own Gmail OAuth config | use the admin dashboard |
| **You, the owner** | everything in `/admin`, after password **and** 2FA | — |

Every route under `/api/v1/admin/`, `/api/services` and `/api/logs/` is owner-only **by default**, so an admin route added in future is protected automatically (`apps/payment-api/src/security/guard.js`).

## Why a payment cannot be faked

`SUCCESS` is produced only by the verification pipeline when a **signed** bank observation matches a live session. The shortcuts that used to exist are closed:

- `POST /admin/counter-confirm` now needs the owner, and only works for **cash/card counter** payments that are still open. A UPI payment can never be confirmed by hand.
- `POST /pollers/events` needs an HMAC signature (`X-Observer-Signature`) bound to the path, body and a timestamp (60 s window, replays rejected).
- Android events need the per-device HMAC. It used to be skipped when the headers were missing; it is now mandatory. Pairing needs a **one-time token only the signed-in owner can create**; the old hard-coded tokens are gone.
- `simulate-observation` does not exist in production; elsewhere it is owner-only.

## Owner login

Password (scrypt) **+ TOTP 2FA**, `HttpOnly; SameSite=Strict; Secure` session cookie (8 h), per-IP and per-account throttling, and each 2FA code works only once. All failures return the same message. Run `npm run admin:setup` to create the credentials; nothing is stored on disk by that command.

**Single sign-on from the Oneleven admin website:** the website sends your Supabase access token in the URL *fragment* (never sent to a server). The gateway verifies it with Supabase, requires that the user id is in `ADMIN_SSO_USER_IDS` **and** that the session used a second factor (`aal2`).

## Secrets

- The webhook signing secret is **write-only**: it is shown once when you rotate it (`POST /api/v1/admin/webhook-secret/rotate`) and never returned by any API.
- Webhooks carry `X-Gateway-Signature-V2` (HMAC over `timestamp.body`). Receivers should verify with `verifyWebhook(body, v1, null, { timestamp, signatureV2 })`, which also rejects deliveries older than 5 minutes.
- Webhook destinations must be public **https** URLs; loopback, private, link-local and cloud-metadata addresses are refused, including hostnames that *resolve* to them.
- In production the process **refuses to start** if the owner credentials/secrets are missing or are one of the old defaults.

## Known limits (be honest with yourself)

- Confirmation depends on a bank alert reaching the observer. If the phone is off, the payment is not confirmed; reconcile against your bank statement.
- Sessions are stateless; to sign everyone out, change `ADMIN_SESSION_SECRET`.
- The in-memory rate limiter and replay cache reset on restart and are per-instance (run a single instance).
- The checkout customer flow (WhatsApp OTP) was not changed in this pass.

## Reporting

If you find a hole, rotate `ADMIN_SESSION_SECRET`, `OBSERVER_INGEST_SECRET` and `PAYMENT_API_KEYS`, and run `POST /api/v1/admin/webhook-secret/rotate`.
