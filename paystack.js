const crypto = require('node:crypto');

// Overridable purely so this can be pointed at a local mock during testing —
// there is no reason to ever set this in a real deployment.
const BASE_URL = process.env.PAYSTACK_BASE_URL || 'https://api.paystack.co';

// Players authenticate with phone + OTP only and have no email on file, but
// Paystack's transaction-initialize endpoint requires one. This synthesizes
// a stable, deterministic placeholder from the phone number — it's not meant
// to receive real mail, just to satisfy the API contract. Collecting a real,
// optional email for payment receipts is worth revisiting before real-money
// launch, but isn't part of this pass.
function placeholderEmail(phoneNumber) {
  const digits = String(phoneNumber || '').replace(/\D/g, '');
  return `player-${digits}@deposits.winza.invalid`;
}

async function initializeTransaction({ amountNaira, phoneNumber, reference, callbackUrl }) {
  const secretKey = process.env.PAYSTACK_SECRET_KEY;
  if (!secretKey) throw new Error('PAYSTACK_SECRET_KEY is not configured.');
  const response = await fetch(`${BASE_URL}/transaction/initialize`, {
    method: 'POST',
    headers: { authorization: `Bearer ${secretKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      email: placeholderEmail(phoneNumber),
      amount: Math.round(amountNaira * 100), // Paystack amounts are in kobo.
      reference,
      callback_url: callbackUrl || undefined,
    }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.status) throw new Error(data.message || 'Paystack initialize request failed.');
  return { authorizationUrl: data.data.authorization_url, accessCode: data.data.access_code, reference: data.data.reference };
}

// Paystack signs webhook bodies with HMAC-SHA512 over the raw request body,
// sent in the x-paystack-signature header. This must run against the exact
// raw bytes received — parsing to JSON and re-stringifying can reorder keys
// or change whitespace and silently break verification, which is why
// server.js reads the raw body before ever calling JSON.parse on it.
function verifySignature(rawBody, signatureHeader) {
  const secretKey = process.env.PAYSTACK_SECRET_KEY;
  if (!secretKey || !signatureHeader) return false;
  const expected = crypto.createHmac('sha512', secretKey).update(rawBody).digest('hex');
  const expectedBuf = Buffer.from(expected, 'utf8');
  const givenBuf = Buffer.from(String(signatureHeader), 'utf8');
  if (expectedBuf.length !== givenBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, givenBuf);
}

module.exports = { placeholderEmail, initializeTransaction, verifySignature };
