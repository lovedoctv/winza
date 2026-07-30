const crypto = require('node:crypto');

const MODE = process.env.WINZA_MODE || 'sandbox';

// --- Paystack ---------------------------------------------------------
// https://api.paystack.co — same host for test and live secret keys; which
// mode you're in is determined entirely by whether PAYSTACK_SECRET_KEY
// starts with sk_test_ or sk_live_.
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const PAYSTACK_BASE = 'https://api.paystack.co';

async function paystackInitialize({ amount, email, reference, callbackUrl }) {
  const res = await fetch(`${PAYSTACK_BASE}/transaction/initialize`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      amount: Math.round(amount * 100), // Paystack takes the smallest currency unit (kobo for NGN).
      currency: 'NGN',
      reference,
      callback_url: callbackUrl,
    }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.status) throw new Error(json.message || 'Paystack initialize failed.');
  return { redirectUrl: json.data.authorization_url, providerReference: json.data.reference };
}

async function paystackVerify(reference) {
  const res = await fetch(`${PAYSTACK_BASE}/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.status) throw new Error(json.message || 'Paystack verify failed.');
  return {
    success: json.data.status === 'success',
    amount: json.data.amount / 100,
    currency: json.data.currency,
    raw: json.data,
  };
}

function paystackVerifySignature(rawBody, signatureHeader) {
  if (!signatureHeader || !PAYSTACK_SECRET_KEY) return false;
  const expected = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(rawBody).digest('hex');
  const a = Buffer.from(expected, 'utf8'), b = Buffer.from(String(signatureHeader), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// --- OPay ---------------------------------------------------------------
// Built against OPay's publicly documented Cashier (hosted checkout) API
// (MerchantId + Bearer public-key auth, HMAC-SHA512 request signing, a
// cashierUrl to redirect the payer to). OPay's merchant dashboard is the
// source of truth for your specific integration once it's approved —
// confirm the endpoint path, field names, and signature scheme there before
// taking a real payment, and adjust opaySign()/opayInitialize()/opayVerify()
// if anything differs. This environment couldn't reach OPay's docs site to
// double-check them line-by-line.
const OPAY_MERCHANT_ID = process.env.OPAY_MERCHANT_ID || '';
const OPAY_PUBLIC_KEY = process.env.OPAY_PUBLIC_KEY || '';
const OPAY_SECRET_KEY = process.env.OPAY_SECRET_KEY || '';
// OPay issues separate test and live API hosts; pick based on WINZA_MODE so
// sandbox testing can never accidentally hit the live processor.
const OPAY_BASE = MODE === 'live' ? 'https://liveapi.opaycheckout.com' : 'https://testapi.opaycheckout.com';

function opaySign(payload) {
  return crypto.createHmac('sha512', OPAY_SECRET_KEY).update(JSON.stringify(payload)).digest('hex');
}

async function opayInitialize({ amount, reference, callbackUrl, returnUrl, userMobile }) {
  const payload = {
    country: 'NG',
    reference,
    amount: { total: Math.round(amount * 100), currency: 'NGN' }, // smallest currency unit, like Paystack.
    returnUrl,
    callbackUrl,
    cancelUrl: returnUrl,
    expireAt: 30, // minutes
    ...(userMobile ? { userInfo: { userMobile } } : {}),
  };
  const res = await fetch(`${OPAY_BASE}/api/v1/international/cashier/create`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${OPAY_PUBLIC_KEY}`,
      MerchantId: OPAY_MERCHANT_ID,
      'Content-Type': 'application/json',
      Signature: opaySign(payload),
    },
    body: JSON.stringify(payload),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.code !== '00000') throw new Error(json.message || 'OPay initialize failed.');
  return { redirectUrl: json.data.cashierUrl, providerReference: json.data.reference || reference };
}

async function opayVerify(reference) {
  const payload = { country: 'NG', reference };
  const res = await fetch(`${OPAY_BASE}/api/v1/international/cashier/status`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${OPAY_PUBLIC_KEY}`,
      MerchantId: OPAY_MERCHANT_ID,
      'Content-Type': 'application/json',
      Signature: opaySign(payload),
    },
    body: JSON.stringify(payload),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.code !== '00000') throw new Error(json.message || 'OPay verify failed.');
  const data = json.data || {};
  return {
    success: data.status === 'SUCCESS',
    amount: (data.amount && data.amount.total || 0) / 100,
    currency: (data.amount && data.amount.currency) || 'NGN',
    raw: data,
  };
}

function opayVerifySignature(rawBody, signatureHeader) {
  if (!signatureHeader || !OPAY_SECRET_KEY) return false;
  let payload;
  try { payload = JSON.parse(rawBody); } catch { return false; }
  const expected = opaySign(payload.payload || payload);
  const a = Buffer.from(expected, 'utf8'), b = Buffer.from(String(signatureHeader), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Only providers with credentials set are offered to players — this is how
// OPay can be wired up now and switched on later just by setting its env
// vars, with no code or deploy change needed at that point.
function configuredProviders() {
  const list = [];
  if (PAYSTACK_SECRET_KEY) list.push('paystack');
  if (OPAY_MERCHANT_ID && OPAY_PUBLIC_KEY && OPAY_SECRET_KEY) list.push('opay');
  return list;
}

module.exports = {
  configuredProviders,
  paystackInitialize,
  paystackVerify,
  paystackVerifySignature,
  opayInitialize,
  opayVerify,
  opayVerifySignature,
};
