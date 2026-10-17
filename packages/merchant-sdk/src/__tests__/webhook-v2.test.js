import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateHmac } from '@youpi/common';
import { YoupiPaymentClient } from '../client.js';

const SECRET = 'whsec_test_secret_value_0123456789abcdef';
const body = JSON.stringify({ event: 'SUCCESS', orderId: 'O-1', amountPaise: 9937 });
const client = new YoupiPaymentClient({ webhookSecret: SECRET });

test('V2 accepts a fresh, correctly signed delivery', () => {
  const ts = String(Date.now());
  const sig = `sha256=${generateHmac(`${ts}.${body}`, SECRET)}`;
  assert.equal(client.verifyWebhook(body, `sha256=${generateHmac(body, SECRET)}`, null, { timestamp: ts, signatureV2: sig }).orderId, 'O-1');
});

test('V2 rejects a replayed (old) delivery even though the signature is valid', () => {
  const ts = String(Date.now() - 10 * 60 * 1000);
  const sig = `sha256=${generateHmac(`${ts}.${body}`, SECRET)}`;
  assert.throws(() => client.verifyWebhook(body, 'sha256=x', null, { timestamp: ts, signatureV2: sig }), /replay/);
});

test('V2 rejects a tampered body and a forged timestamp', () => {
  const ts = String(Date.now());
  const sig = `sha256=${generateHmac(`${ts}.${body}`, SECRET)}`;
  assert.throws(() => client.verifyWebhook(body.replace('9937', '1'), 'sha256=x', null, { timestamp: ts, signatureV2: sig }), /mismatch/);
  assert.throws(() => client.verifyWebhook(body, 'sha256=x', null, { timestamp: String(Date.now() + 1), signatureV2: sig }), /mismatch/);
});

test('V1 still works unchanged for existing receivers', () => {
  assert.equal(client.verifyWebhook(body, `sha256=${generateHmac(body, SECRET)}`).event, 'SUCCESS');
  assert.throws(() => client.verifyWebhook(body, 'sha256=deadbeef'), /mismatch/);
});

test('apiKey is sent as a Bearer token when creating payments', async () => {
  let seen;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => { seen = init.headers; return { ok: true, json: async () => ({ paymentId: 'p' }) }; };
  try {
    await new YoupiPaymentClient({ apiUrl: 'http://x', apiKey: 'pk_test_abc' }).createPayment({ orderId: 'A', amount: '1.00' });
    assert.equal(seen.Authorization, 'Bearer pk_test_abc');
  } finally { globalThis.fetch = realFetch; }
});
