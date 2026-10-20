# Configuration & Secret Management Guide

## 1. Environment Parameters Reference

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `development` | Runtime environment (`development` or `production`) |
| `CONTROL_CENTER_PORT` | `8090` | Host port for the Local Process Supervisor |
| `PAYMENT_API_PORT` | `6100` | Host port for the central Payment Core REST API |
| `CHECKOUT_PORTAL_PORT` | `7000` | Host port for the customer-facing Checkout page |
| `MERCHANT_ADMIN_PORT` | `6001` | Host port for the Merchant Admin Dashboard |
| `HELP_PORTAL_PORT` | `3000` | Host port for the Customer Payment Help Portal |
| `GMAIL_OBSERVER_PORT` | `6003` | Host port for the Gmail Polling Service & OAuth Callback |
| `SMS_OBSERVER_PORT` | `6002` | Host port for the Google Messages / SMS Web Automator |
| `DATABASE_URL` | `postgresql://...` | PostgreSQL connection URL |
| `USE_SQLITE_FALLBACK` | `true` | When true, uses embedded SQLite if PostgreSQL is unreachable |
| `SQLITE_DB_PATH` | `./data/youpi_pg.sqlite`| Path to local SQLite database file |
| `ADMIN_EMAIL` | `you@example.com` | Owner account email (from `npm run admin:setup`) |
| `ADMIN_PASSWORD_HASH` | `scrypt$...` | Owner password hash (never the password) |
| `ADMIN_TOTP_SECRET` | `base32` | Owner 2FA key for your authenticator app |
| `ADMIN_SESSION_SECRET` | `32+ chars` | Signs the admin session cookie; change it to sign everyone out |
| `OBSERVER_INGEST_SECRET` | `32+ chars` | Observers sign their requests with this |
| `PAYMENT_API_KEYS` | `pk_live_...` | Server-side keys allowed to create payments (comma-separated) |
| `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `ADMIN_SSO_USER_IDS` | optional | Enables "Payments" single sign-on from the Oneleven admin |

> In production the gateway refuses to start if the owner variables are missing or are a known default. See [`SECURITY.md`](../SECURITY.md).
| `PAYMENT_ACTIVE_WINDOW_MS` | `300000` | Duration of active payment slot (5 minutes = 300,000ms) |
| `PAYMENT_PROCESSING_WINDOW_MS` | `30000` | Duration of verification slot (30 seconds = 30,000ms) |
| `LATE_OBSERVATION_WINDOW_MS` | `1800000` | Safety window for matching late observations (30 minutes) |
| *(removed)* `ANDROID_ENROLLMENT_SECRET` | , | Phones now pair with a one-time token minted by the signed-in owner |
| `ANDROID_HEARTBEAT_TIMEOUT_MS` | `180000` | Inactivity window before Android device is marked DISCONNECTED |

---

## 2. Cryptographic Secret Generation

Generate strong 256-bit encryption and HMAC keys using Node.js native crypto:

```bash
# Generate 256-bit Master Key (64 hex characters)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Never commit production `.env` files to source code repositories.
