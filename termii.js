// Sends OTP SMS via Termii's Messaging API (https://developers.termii.com/messaging-api),
// a Nigeria-focused provider — a natural fit since OTP login here only
// accepts Nigerian numbers (see otp.js's normalizePhone). Only used when
// TERMII_API_KEY is configured; otherwise otp.js falls back to the generic
// OTP_SMS_WEBHOOK_URL, or (sandbox/testing only) OTP_DEV_ECHO. See .env.example.
// Termii documents this as the default global host, but a Termii account can
// be assigned a region-specific base URL (shown on your Termii dashboard) —
// set TERMII_BASE_URL if yours differs from this default.
const DEFAULT_BASE_URL = 'https://api.ng.termii.com';

async function sendSms(phone, message) {
  const apiKey = process.env.TERMII_API_KEY;
  const senderId = process.env.TERMII_SENDER_ID;
  if (!apiKey || !senderId) return { delivered: false, reason: 'termii_not_configured' };
  const baseUrl = (process.env.TERMII_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, '');
  try {
    const response = await fetch(`${baseUrl}/api/sms/send`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        api_key: apiKey,
        // Termii expects the destination number without a leading '+';
        // otp.js's normalizePhone always stores it as +234XXXXXXXXXX.
        to: String(phone || '').replace(/^\+/, ''),
        from: senderId,
        sms: message,
        type: 'plain',
        // 'dnd' (not 'generic') is Termii's transactional route — required
        // for OTP/transactional messages so delivery isn't blocked the way
        // promotional SMS is by Nigeria's Do-Not-Disturb list.
        channel: 'dnd',
      }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.code !== 'ok') {
      return { delivered: false, reason: data.message || `termii_http_${response.status}` };
    }
    return { delivered: true, messageId: data.message_id };
  } catch (e) {
    return { delivered: false, reason: 'termii_request_failed' };
  }
}

module.exports = { sendSms };
