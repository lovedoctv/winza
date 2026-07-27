const crypto = require('node:crypto');

// Accepts +234XXXXXXXXXX (already international), 0XXXXXXXXXX (Nigerian local
// format), or 234XXXXXXXXXX, and normalizes to E.164 (+234XXXXXXXXXX).
// Extend this if you need to support other countries.
function normalizePhone(raw) {
  const trimmed = String(raw || '').trim().replace(/[\s\-()]/g, '');
  if (/^\+\d{8,15}$/.test(trimmed)) return trimmed;
  if (/^0\d{10}$/.test(trimmed)) return '+234' + trimmed.slice(1);
  if (/^234\d{10}$/.test(trimmed)) return '+' + trimmed;
  throw new Error('Enter a valid phone number.');
}

function generateCode() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

// Pluggable delivery. If OTP_SMS_WEBHOOK_URL is set, the phone number and code
// are POSTed to it — your actual SMS provider (Termii, Africa's Talking,
// Twilio, etc.) lives behind that webhook, not in this codebase. If it's not
// configured, delivery simply doesn't happen; the caller decides what to do
// with that (server.js only echoes the code back in non-live modes, purely so
// the flow is testable before a provider is wired in).
async function sendOtpSms(phone, code) {
  const webhook = process.env.OTP_SMS_WEBHOOK_URL;
  if (!webhook) return { delivered: false, reason: 'no_provider_configured' };
  await fetch(webhook, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ phone, message: `Your WINZA verification code is ${code}. It expires in 5 minutes.` }),
  });
  return { delivered: true };
}

module.exports = { normalizePhone, generateCode, hashCode, sendOtpSms };
