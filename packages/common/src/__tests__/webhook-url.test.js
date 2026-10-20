import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateWebhookUrl, isPrivateAddress, assertSafeResolvedAddress } from '../webhook-url.js';

const prod = { production: true };

test('production accepts a normal public https endpoint', () => {
  assert.equal(validateWebhookUrl('https://abc.supabase.co/functions/v1/adipay-webhook', prod).ok, true);
});

test('production refuses http, credentials and internal hostnames', () => {
  for (const url of ['http://example.com/hook', 'https://user:pw@example.com/h', 'https://localhost/h', 'https://db.internal/h', 'https://printer.local/h']) {
    assert.equal(validateWebhookUrl(url, prod).ok, false, url);
  }
});

test('production refuses loopback, private, link-local and cloud-metadata addresses (SSRF)', () => {
  for (const url of [
    'https://127.0.0.1/h', 'https://10.1.2.3/h', 'https://172.16.0.1/h', 'https://192.168.1.10/h',
    'https://169.254.169.254/latest/meta-data/', 'https://100.64.0.1/h', 'https://0.0.0.0/h',
    'https://[::1]/h', 'https://[fd00::1]/h', 'https://[fe80::1]/h', 'https://[::ffff:10.0.0.1]/h'
  ]) {
    assert.equal(validateWebhookUrl(url, prod).ok, false, url);
  }
  assert.equal(isPrivateAddress('8.8.8.8'), false);
  assert.equal(isPrivateAddress('172.32.0.1'), false);
});

test('outside production, local test receivers on http://localhost stay allowed', () => {
  assert.equal(validateWebhookUrl('http://localhost:4000/api/webhook').ok, true);
  assert.equal(validateWebhookUrl('ftp://example.com/x').ok, false);
  assert.equal(validateWebhookUrl('not a url').ok, false);
});

test('a public-looking hostname that resolves to a private address is refused (DNS rebinding)', async () => {
  const resolvesTo = address => async () => [{ address }];
  assert.equal((await assertSafeResolvedAddress('https://pay.example.com/h', { production: true, lookup: resolvesTo('10.0.0.5') })).ok, false);
  assert.equal((await assertSafeResolvedAddress('https://pay.example.com/h', { production: true, lookup: async () => [{ address: '8.8.8.8' }, { address: '169.254.169.254' }] })).ok, false);
  assert.equal((await assertSafeResolvedAddress('https://pay.example.com/h', { production: true, lookup: resolvesTo('8.8.8.8') })).ok, true);
  assert.equal((await assertSafeResolvedAddress('https://pay.example.com/h', { production: true, lookup: async () => { throw new Error('nx'); } })).ok, false);
  // not enforced outside production so local receivers keep working
  assert.equal((await assertSafeResolvedAddress('http://localhost:3000/h', { production: false })).ok, true);
});
