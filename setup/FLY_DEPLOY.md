# Adipay on Fly.io — free, with a persistent volume (data survives restarts)

Why Fly: the free allowance includes a **persistent volume**, so the SQLite
database is NOT wiped on restart/deploy (unlike Render's free tier). No paid
disk and no Postgres rewrite needed. An always-on Node machine runs the API,
checkout and the owner admin (`/admin`).

Files here: `fly.toml` (app + volume + health), `Dockerfile` (Node 22 image).

## One-time, on your own computer

Install the Fly CLI and sign in:
```bash
# macOS/Linux:
curl -L https://fly.io/install.sh | sh
fly auth login
```

Clone and enter the repo:
```bash
git clone https://github.com/gitworld08210/Adipay.git
cd Adipay
```

## 1) Create the app (in your org) WITHOUT deploying yet
```bash
fly launch --no-deploy --copy-config --name adipay --org aditya-246 --region sin
```
- `--copy-config` uses the committed `fly.toml`.
- If the name `adipay` is taken, pick another and it updates `app =` in fly.toml.
- Keep region `sin` (Singapore) or change it in `fly.toml`.

## 2) Create the persistent volume (same name + region as fly.toml)
```bash
fly volumes create adipay_data --size 1 --region sin
```
(1 GB is plenty for SQLite. This is the volume mounted at `/data`.)

## 3) Generate the owner secrets (printed once — never paste them in chat)
```bash
npm install
npm run admin:setup
```
It asks for your email, a password, and a 2FA code (add the key to Google
Authenticator/Authy). It prints 6 lines: `ADMIN_EMAIL`, `ADMIN_PASSWORD_HASH`,
`ADMIN_TOTP_SECRET`, `ADMIN_SESSION_SECRET`, `OBSERVER_INGEST_SECRET`,
`PAYMENT_API_KEYS`.

## 4) Set the secrets on Fly (these are encrypted, not in the repo)
```bash
fly secrets set \
  ADMIN_EMAIL="you@example.com" \
  ADMIN_PASSWORD_HASH="...from admin:setup..." \
  ADMIN_TOTP_SECRET="...from admin:setup..." \
  ADMIN_SESSION_SECRET="...from admin:setup..." \
  OBSERVER_INGEST_SECRET="...from admin:setup..." \
  PAYMENT_API_KEYS="pk_live_...from admin:setup..."
```

For the "Payments" button in the Oneleven admin website to sign you in, also:
```bash
fly secrets set \
  SUPABASE_URL="https://xyuzzjwmpyckuhtiygpk.supabase.co" \
  SUPABASE_ANON_KEY="<your Supabase anon/publishable key>" \
  ADMIN_SSO_USER_IDS="<your Supabase user id>"
```
(Get your user id in the Supabase SQL editor: `select auth.uid();`)

## 5) Deploy
```bash
fly deploy
```
When it's live:
```bash
fly open /admin        # opens https://adipay.fly.dev/admin
```
Sign in with your email + password + 2FA. Done.

## 6) Point the Oneleven admin website at this Adipay
In Vercel (or Render) where the admin website is hosted, set:
```
VITE_ADIPAY_URL = https://adipay.fly.dev
```
Redeploy the admin site. Now its **Payments** button opens this Adipay already
signed in.

## Notes
- `auto_stop_machines` lets the machine sleep when idle (saves the free
  allowance) and wake on the next request; the volume keeps the data either way.
- First boot runs migrations and seeds a demo merchant — the health check has a
  40s grace period for that.
- **Rotate the webhook secret** after going live (it was exposed in old code):
  in the admin dashboard, or `POST /api/v1/admin/webhook-secret/rotate`.
- Free machines are small (256 MB). Fine for testing and light traffic; bump
  `[[vm]]` memory/size later if needed.
