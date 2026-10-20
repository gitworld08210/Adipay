#!/usr/bin/env node
/**
 * One-time owner setup. Run it on YOUR machine (not on the server):
 *
 *     npm run admin:setup
 *
 * It asks for your email and a password (hidden while typing, never stored in
 * shell history), then prints the environment variables to paste into Render
 * (or your .env). Nothing is written to disk and nothing is sent anywhere.
 */
import readline from 'node:readline';
import crypto from 'node:crypto';
import { hashPassword, generateTotpSecret, otpauthUri, totpAt } from '../apps/payment-api/src/security/crypto.js';

function ask(question, { hidden = false } = {}) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) {
      rl._writeToOutput = str => {
        if (str.includes(question)) rl.output.write(str);
        else if (str === '\r\n' || str === '\n') rl.output.write(str);
      };
    }
    rl.question(question, answer => {
      rl.close();
      if (hidden) process.stdout.write('\n');
      resolve(answer);
    });
  });
}

const random = bytes => crypto.randomBytes(bytes).toString('hex');

async function main() {
  console.log('\nAdipay owner setup\n------------------');
  const email = (await ask('Owner email: ')).trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    console.error('That does not look like an email address.');
    process.exit(1);
  }
  const password = await ask('Password (min 12 characters, hidden): ', { hidden: true });
  const again = await ask('Repeat password: ', { hidden: true });
  if (password !== again) {
    console.error('Passwords do not match.');
    process.exit(1);
  }
  let passwordHash;
  try {
    passwordHash = hashPassword(password);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }

  const totpSecret = generateTotpSecret();
  const uri = otpauthUri({ secret: totpSecret, account: email });

  console.log('\n1) Add the 2FA code to your authenticator app (Google Authenticator, Authy, 1Password...)');
  console.log('   Choose "Enter a setup key" and use:');
  console.log(`     Account : ${email}`);
  console.log(`     Key     : ${totpSecret}`);
  console.log('   (or open this link on your phone)');
  console.log(`     ${uri}`);

  const check = (await ask('\nType the 6-digit code your app shows now, to confirm it works: ')).trim();
  const now = Date.now();
  const ok = [-30_000, 0, 30_000].some(skew => totpAt(totpSecret, now + skew) === check);
  if (!ok) {
    console.error('\nThat code is wrong, so 2FA is not set up correctly. Run the setup again.');
    process.exit(1);
  }

  console.log('\n2) Paste these into Render -> your service -> Environment (or your .env).');
  console.log('   Treat every line as a password. Do not commit them or share them in chat.\n');
  console.log('------------------------------------------------------------');
  console.log(`ADMIN_EMAIL=${email}`);
  console.log(`ADMIN_PASSWORD_HASH=${passwordHash}`);
  console.log(`ADMIN_TOTP_SECRET=${totpSecret}`);
  console.log(`ADMIN_SESSION_SECRET=${random(32)}`);
  console.log(`OBSERVER_INGEST_SECRET=${random(32)}`);
  console.log(`PAYMENT_API_KEYS=pk_live_${random(24)}`);
  console.log('------------------------------------------------------------');
  console.log('\nOptional - single sign-on from the Oneleven admin website:');
  console.log('   SUPABASE_URL=https://<your-project>.supabase.co');
  console.log('   SUPABASE_ANON_KEY=<your Supabase anon/publishable key>');
  console.log('   ADMIN_SSO_USER_IDS=<your Supabase user id, comma-separated for several>');
  console.log('\nThen redeploy. Sign in at https://<your-service>/admin');
  console.log('PAYMENT_API_KEYS is what your server (not a browser) sends as "Authorization: Bearer <key>" to create payments.\n');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
