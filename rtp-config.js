// Single source of truth for WINZA's Return-to-Player (RTP) floor/ceiling and
// validation. Both the server (server.js, via require()) and the client
// (winza.html, via <script src="/rtp-config.js">) load this exact file, so a
// value can never be accepted on one side and rejected on the other.
//
// 90% is the regulatory-style floor this platform is adopting ahead of a
// future real-money launch; 100% is the ceiling (the house never pays out
// less than it takes in, on average). 96% is the default/fallback used
// whenever a stored value is missing or invalid.
(function (root) {
  const RTP_MIN = 0.90;
  const RTP_MAX = 1.00;
  const RTP_DEFAULT = 0.96;

  function isValidRtp(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= RTP_MIN && value <= RTP_MAX;
  }

  // For RTP values coming from somewhere that isn't freshly-validated input
  // (a saved config, a database row, an old file predating the 90-100%
  // floor) — never throws, always returns something safe to run the game on.
  function sanitizeRtp(value) {
    return isValidRtp(value) ? value : RTP_DEFAULT;
  }

  const api = { RTP_MIN, RTP_MAX, RTP_DEFAULT, isValidRtp, sanitizeRtp };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.WINZA_RTP_CONFIG = api;
})(typeof window !== 'undefined' ? window : globalThis);
