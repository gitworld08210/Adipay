# Adipay on your phone with Termux (free, data stays on the phone)

Run Adipay directly on your Android phone using Termux. No hosting bill, the
SQLite database lives on your phone (nothing is wiped), and you can stop it
whenever you want. A small Cloudflare tunnel gives it a public HTTPS URL so the
Oneleven admin website's "Payments" button can reach it.

Adipay has **no native/compiled dependencies** and uses Node's built-in
`node:sqlite`, so it runs on Termux as-is.

---

## A. One-time setup (paste these in Termux, one block at a time)

### 1. Install the tools
```bash
pkg update -y && pkg upgrade -y
pkg install -y nodejs-lts git
node -v      # should print v20 or newer
```

### 2. Get Adipay
```bash
cd ~
git clone https://github.com/gitworld08210/Adipay.git
cd Adipay
npm install
npm run build
```

### 3. Create your owner login (secrets — keep them private, do NOT share)
```bash
npm run admin:setup
```
It asks for your email, a password, and a 2FA code (add the printed key to
Google Authenticator / Authy). It prints several lines. **Copy them into a new
file** called `.env` in the Adipay folder, like this:
```bash
nano .env
```
Paste and fill (one per line), then save (Ctrl+O, Enter, Ctrl+X):
```
NODE_ENV=production
PORT=6100
SQLITE_DB_PATH=/data/data/com.termux/files/home/Adipay/data/youpi_pg.sqlite
ADMIN_EMAIL=you@example.com
ADMIN_PASSWORD_HASH=...from admin:setup...
ADMIN_TOTP_SECRET=...from admin:setup...
ADMIN_SESSION_SECRET=...from admin:setup...
OBSERVER_INGEST_SECRET=...from admin:setup...
PAYMENT_API_KEYS=pk_live_...from admin:setup...
SUPABASE_URL=https://xyuzzjwmpyckuhtiygpk.supabase.co
SUPABASE_ANON_KEY=<your Supabase anon/publishable key>
ADMIN_SSO_USER_IDS=<your Supabase user id>
```
(Get your Supabase user id in the Supabase SQL editor: `select auth.uid();`)

### 4. Install the Cloudflare tunnel (gives a public https link)
```bash
pkg install -y cloudflared
```

---

## B. Every time you want Adipay ON

Open Termux and run two things (two Termux tabs/sessions — swipe from the left
edge → "New session"):

**Session 1 — start Adipay:**
```bash
cd ~/Adipay
set -a; . ./.env; set +a      # load the .env values
npm start
```
Leave it running. It serves on port 6100.

**Session 2 — open the public link:**
```bash
cloudflared tunnel --url http://localhost:6100
```
It prints a URL like `https://something-random.trycloudflare.com`. **That is
your Adipay address.** Open `.../admin` in a browser to sign in.

> Keep Termux open while you need Adipay. To avoid Android killing it, run
> `termux-wake-lock` once (install Termux:API if needed). To stop Adipay, press
> Ctrl+C in each session, or just close Termux — your data stays saved.

---

## C. Point the Oneleven admin website at it
The `trycloudflare.com` URL changes each time you restart the tunnel. For a
quick test that is fine. In the Oneleven admin site (Vercel/Render) set
`VITE_ADIPAY_URL` to the current tunnel URL and redeploy; then its **Payments**
button opens this Adipay.

For a URL that does NOT change, set up a **named** Cloudflare tunnel with your
own domain (free Cloudflare account): https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
Then `VITE_ADIPAY_URL` stays fixed.

---

## D. Backups (your data is one file)
The whole database is `~/Adipay/data/youpi_pg.sqlite`. To back it up:
```bash
cp ~/Adipay/data/youpi_pg.sqlite ~/storage/downloads/adipay-backup-$(date +%F).sqlite
```
(Run `termux-setup-storage` once to allow access to Downloads.) Copy that file
to Google Drive / anywhere. To restore, stop Adipay and copy a backup back over
`data/youpi_pg.sqlite`.

---

## Notes
- Adipay only runs while Termux is running and the phone is on — exactly the
  "turn it off when you want" behaviour you asked for.
- After going live, **rotate the webhook secret** (it was exposed in old code):
  in the admin dashboard or `POST /api/v1/admin/webhook-secret/rotate`.
- Never paste your `.env` / secrets into chat. They stay on your phone.
- Real payment verification needs the bank observers (SMS/Gmail) set up
  separately; this guide gets the gateway + admin + SSO running.
