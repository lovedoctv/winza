// Pluggable sanctions/PEP screening. If SANCTIONS_SCREENING_WEBHOOK_URL is
// set, the identity fields from a KYC submission are POSTed to it — your
// actual screening provider (ComplyAdvantage, Refinitiv World-Check, a
// national sanctions-list API, etc.) lives behind that webhook, not in this
// codebase. It's expected to respond with JSON: { hit: boolean, detail?: string }.
//
// If it's not configured, screening simply doesn't happen automatically —
// the caller (server.js's KYC approval handler) decides what to do with
// that. It does NOT treat an unscreened submission as clear; it requires an
// explicit, logged staff override instead, same shape as the OTP dev-echo
// and payment-provider patterns elsewhere in this codebase.
async function screen(identity) {
  const webhook = process.env.SANCTIONS_SCREENING_WEBHOOK_URL;
  if (!webhook) return { configured: false };
  const response = await fetch(webhook, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(identity),
  });
  if (!response.ok) throw new Error('Sanctions screening provider returned an error.');
  const data = await response.json();
  return { configured: true, hit: Boolean(data.hit), detail: typeof data.detail === 'string' ? data.detail.slice(0, 500) : undefined };
}

module.exports = { screen };
