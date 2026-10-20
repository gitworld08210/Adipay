import net from 'node:net';
import dns from 'node:dns/promises';

/**
 * Validates a webhook destination. In production the gateway sends signed
 * payment events to this URL, so it must not be usable to reach the gateway's
 * own network (SSRF): HTTPS only, no credentials in the URL, and no
 * loopback / private / link-local / cloud-metadata addresses.
 *
 * Hostnames are checked syntactically here; a hostname that later resolves to
 * a private address is checked again by `assertSafeResolvedAddress`.
 *
 * @param {string} rawUrl
 * @param {{ production?: boolean }} [opts]
 * @returns {{ ok: true, url: string } | { ok: false, reason: string }}
 */
export function validateWebhookUrl(rawUrl, { production = false } = {}) {
  let u;
  try {
    u = new URL(String(rawUrl || '').trim());
  } catch {
    return { ok: false, reason: 'Not a valid URL.' };
  }
  if (u.username || u.password) return { ok: false, reason: 'Credentials in the URL are not allowed.' };
  if (!production) {
    return u.protocol === 'http:' || u.protocol === 'https:'
      ? { ok: true, url: u.toString() }
      : { ok: false, reason: 'Only http(s) URLs are allowed.' };
  }
  if (u.protocol !== 'https:') return { ok: false, reason: 'Webhook URLs must use https in production.' };
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return { ok: false, reason: 'Internal hostnames are not allowed.' };
  }
  if (net.isIP(host) && isPrivateAddress(host)) {
    return { ok: false, reason: 'Private or reserved IP addresses are not allowed.' };
  }
  return { ok: true, url: u.toString() };
}

/** True for loopback, RFC1918, link-local, CGNAT, multicast and metadata ranges. */
export function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||            // link-local + cloud metadata (169.254.169.254)
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||  // CGNAT
      a >= 224                               // multicast / reserved
    );
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v === '::1' || v === '::') return true;
    if (v.startsWith('fe8') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb')) return true; // fe80::/10
    if (v.startsWith('fc') || v.startsWith('fd')) return true;                                                // fc00::/7
    // IPv4-mapped (::ffff:a.b.c.d). WHATWG URL normalises these to hex
    // (::ffff:a00:1), so decode both spellings back to dotted IPv4.
    const dotted = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (dotted) return isPrivateAddress(dotted[1]);
    const hex = v.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const hi = parseInt(hex[1], 16);
      const lo = parseInt(hex[2], 16);
      return isPrivateAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    // IPv4-compatible / NAT64 prefixes embed an IPv4 address too; refuse them.
    if (v.startsWith('::') && !v.startsWith('::ffff:')) return true;
    if (v.startsWith('64:ff9b:')) return true;
    return false;
  }
  return false;
}

/**
 * Resolves the hostname and refuses it when ANY returned address is private
 * (defends against DNS names that point at internal services). Call this right
 * before sending; it is a no-op outside production.
 *
 * @param {string} rawUrl
 * @param {{ production?: boolean, lookup?: (host: string) => Promise<Array<{address: string}>> }} [opts]
 * @returns {Promise<{ ok: true } | { ok: false, reason: string }>}
 */
export async function assertSafeResolvedAddress(rawUrl, { production = false, lookup = h => dns.lookup(h, { all: true }) } = {}) {
  if (!production) return { ok: true };
  const host = new URL(rawUrl).hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) return isPrivateAddress(host) ? { ok: false, reason: 'Private address.' } : { ok: true };
  try {
    const addresses = await lookup(host);
    if (!addresses.length) return { ok: false, reason: 'Hostname did not resolve.' };
    if (addresses.some(a => isPrivateAddress(a.address))) {
      return { ok: false, reason: 'Hostname resolves to a private address.' };
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: 'Hostname could not be resolved.' };
  }
}
