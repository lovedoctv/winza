// Single source of truth for WINZA's game math: the Return-to-Player (RTP)
// floor/ceiling, the odds/payout formulas, and the stake/multiplier bounds.
// Both the server (server.js, game-engine.js, via require()) and the client
// (winza.html, via <script src="/rtp-config.js">) load this exact file, so a
// value or formula can never differ between what the client previews and
// what the server actually resolves.
//
// IMPORTANT: loading this file client-side is for *display* only — showing
// the player their odds and potential payout before they bet. The client
// never uses it to decide win/loss or to move money. Every bet's outcome is
// generated server-side with a cryptographically secure RNG (see
// game-engine.js) and settled in a single database transaction (see
// wallet.js's placeBet and the /api/v1/games/bets handler in server.js).
//
// 90% is the regulatory-style floor this platform is adopting ahead of a
// future real-money launch; 100% is the ceiling (the house never pays out
// less than it takes in, on average). 96% is the default/fallback used
// whenever a stored value is missing or invalid.
(function (root) {
  const RTP_MIN = 0.90;
  const RTP_MAX = 1.00;
  const RTP_DEFAULT = 0.96;

  // Odds are derived from RTP/multiplier so the expected return stays close
  // to RTP regardless of which multiplier a player picks (chance x
  // multiplier x stake ~= RTP x stake). Clamped so no multiplier ever
  // produces a near-0% or near-100% chance of winning.
  const MIN_CHANCE = 0.03;
  const MAX_CHANCE = 0.9;

  // Must match winza.html's #multSlider min/max/step exactly — the server
  // rejects anything outside this range or off the 0.1 step regardless of
  // what a client sends.
  const MULTIPLIER_MIN = 1.1;
  const MULTIPLIER_MAX = 10;
  const MULTIPLIER_STEP = 0.1;

  // Must match winza.html's #stakeSlider min/max exactly, for the same reason.
  const STAKE_MIN = 100;
  const STAKE_MAX = 50000;

  const GAME_IDS = ['wheel', 'lotto'];

  function isValidRtp(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= RTP_MIN && value <= RTP_MAX;
  }

  // For RTP values coming from somewhere that isn't freshly-validated input
  // (a saved config, a database row, an old file predating the 90-100%
  // floor) — never throws, always returns something safe to run the game on.
  function sanitizeRtp(value) {
    return isValidRtp(value) ? value : RTP_DEFAULT;
  }

  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

  // The one formula both the pre-bet client preview and the server's actual
  // outcome draw use (see the module-level note above) — never duplicate
  // this math anywhere else.
  function computeChance(rtp, multiplier) {
    return clamp(sanitizeRtp(rtp) / multiplier, MIN_CHANCE, MAX_CHANCE);
  }

  // Rounded to the nearest ₦100 so payouts always look like real money
  // rather than a raw floating-point product.
  function computePayout(stake, multiplier) {
    return Math.round((stake * multiplier) / 100) * 100;
  }

  function isValidGameId(value) {
    return typeof value === 'string' && GAME_IDS.includes(value);
  }

  function isValidStake(value) {
    return typeof value === 'number' && Number.isFinite(value) && Number.isInteger(value)
      && value >= STAKE_MIN && value <= STAKE_MAX;
  }

  // Only ever offered in MULTIPLIER_STEP increments client-side (see
  // winza.html's #multSlider) — reject anything finer so a crafted request
  // can't probe for floating-point edge cases in computeChance/computePayout.
  // Rounding the candidate back to the nearest step before comparing avoids
  // false negatives from binary floating-point representation (e.g. 1.1
  // itself isn't exactly representable).
  function isValidMultiplier(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) return false;
    if (value < MULTIPLIER_MIN || value > MULTIPLIER_MAX) return false;
    const steps = Math.round(value / MULTIPLIER_STEP);
    return Math.abs(steps * MULTIPLIER_STEP - value) < 1e-9;
  }

  const api = {
    RTP_MIN, RTP_MAX, RTP_DEFAULT, isValidRtp, sanitizeRtp,
    MIN_CHANCE, MAX_CHANCE,
    MULTIPLIER_MIN, MULTIPLIER_MAX, MULTIPLIER_STEP,
    STAKE_MIN, STAKE_MAX, GAME_IDS,
    computeChance, computePayout, isValidGameId, isValidStake, isValidMultiplier,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.WINZA_RTP_CONFIG = api;
})(typeof window !== 'undefined' ? window : globalThis);
