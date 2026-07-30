const crypto = require('node:crypto');

// Overridable purely so this can be pointed at a local mock during testing —
// there is no reason to ever set this in a real deployment. OPay issues
// separate test and live API hosts; unlike Paystack (one host, test/live
// determined by which secret key you use), this needs to point at the right
// one explicitly.
const BASE_URL = process.env.OPAY_BASE_URL || 'https://liveapi.opaycheckout.com';

// Built against OPay's publicly documented Cashier (hosted checkout) API:
// MerchantId + Bearer public-key auth, an HMAC-SHA512-signed request body,
// a cashierUrl to redirect the payer to. This environment couldn't reach
// OPay's docs site to verify field names line-by-line the way Paystack's
// were (see README.md) — treat this as best-effort plumbing and confirm the
// endpoint path, request/response fields, and signature scheme against your
// actual OPay merchant dashboard before relying on it for a real payment.
function sign(payload) {
  const secretKey = process.env.OPAY_SECRET_KEY;
  return crypto.createHmac('sha512', secretKey).update(JSON.stringify(payload)).digest('hex');
}

async function initializeTransaction({ amountNaira, reference, returnUrl }) {
  const merchantId = process.env.OPAY_MERCHANT_ID;
  const publicKey = process.env.OPAY_PUBLIC_KEY;
  const secretKey = process.env.OPAY_SECRET_KEY;
  if (!merchantId || !publicKey || !secretKey) throw new Error('OPay is not configured.');
  const payload = {
    country: 'NG',
    reference,
    amount: { total: Math.round(amountNaira * 100), currency: 'NGN' }, // smallest currency unit, same as Paystack's kobo.
    returnUrl: returnUrl || undefined,
  };
  const response = await fetch(`${BASE_URL}/api/v1/international/cashier/create`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${publicKey}`,
      merchantid: merchantId,
      'content-type': 'application/json',
      signature: sign(payload),
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.code !== '00000') throw new Error(data.message || 'OPay initialize request failed.');
  return { authorizationUrl: data.data.cashierUrl, reference: data.data.reference || reference };
}

// OPay signs webhook bodies with HMAC-SHA512 over the raw request body,
// sent in a signature header. This must run against the exact raw bytes
// received — parsing to JSON and re-stringifying can reorder keys or change
// whitespace and silently break verification, which is why server.js reads
// the raw body before ever calling JSON.parse on it.
function verifySignature(rawBody, signatureHeader) {
  const secretKey = process.env.OPAY_SECRET_KEY;
  if (!secretKey || !signatureHeader) return false;
  let payload;
  try { payload = JSON.parse(rawBody); } catch { return false; }
  const expected = sign(payload.payload || payload);
  const expectedBuf = Buffer.from(expected, 'utf8');
  const givenBuf = Buffer.from(String(signatureHeader), 'utf8');
  if (expectedBuf.length !== givenBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, givenBuf);
}

module.exports = { initializeTransaction, verifySignature };
