const crypto = require('node:crypto');
const termii = require('./termii');

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

// Pluggable delivery, tried in order:
//   1. Termii (termii.js), if TERMII_API_KEY is configured — a direct,
//      built-in integration, since Termii is Nigeria-focused and this app's
//      phone numbers always are too (see normalizePhone above).
//   2. OTP_SMS_WEBHOOK_URL, if set — POSTs the phone number and message to
//      it; any other SMS provider (Africa's Talking, Twilio, etc.) lives
//      behind that webhook, not in this codebase.
//   3. Neither configured: delivery simply doesn't happen; the caller
//      decides what to do with that (server.js only echoes the code back in
//      non-live modes, purely so the flow is testable before a provider is
//      wired in).
async function sendOtpSms(phone, code) {
  const message = `Your WINZA verification code is ${code}. It expires in 5 minutes.`;

  const termiiResult = await termii.sendSms(phone, message);
  if (termiiResult.delivered) return termiiResult;
  if (termiiResult.reason !== 'termii_not_configured') return termiiResult;

  const webhook = process.env.OTP_SMS_WEBHOOK_URL;
  if (!webhook) return { delivered: false, reason: 'no_provider_configured' };
  await fetch(webhook, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ phone, message }),
  });
  return { delivered: true };
}

module.exports = { normalizePhone, generateCode, hashCode, sendOtpSms };
