#!/usr/bin/env node
// Smoke-tests a running WINZA deployment before you open it to testers.
// Registers a throwaway account, logs in, checks the wallet, and confirms
// logout actually revokes the session. Doesn't touch real money — there is
// none to touch yet.
//
// Usage:
//   node smoke-test.js https://your-app.onrender.com

const BASE_URL = (process.argv[2] || process.env.WINZA_BASE_URL || '').replace(/\/$/, '');
if (!BASE_URL) {
  console.error('Usage: node smoke-test.js <base-url>');
  console.error('e.g.   node smoke-test.js https://winza.onrender.com');
  process.exit(1);
}

const results = [];
function record(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
}
async function json(res) { try { return await res.json(); } catch { return {}; } }

async function main() {
  // 1. Server is up and knows about its database.
  let res = await fetch(`${BASE_URL}/healthz`);
  let data = await json(res);
  record('GET /healthz', res.ok && data.ok === true, JSON.stringify(data));
  if (!data.databaseConfigured) {
    record('database configured on server', false, 'DATABASE_URL is not set — nothing past this point can pass');
    return finish();
  }

  // 2. Public config still reports real money as disabled.
  res = await fetch(`${BASE_URL}/api/v1/public/config`);
  data = await json(res);
  record('GET /api/v1/public/config', res.ok && data.realMoneyEnabled === false, JSON.stringify(data));

  // 3. Register a throwaway account.
  const email = `smoketest+${Date.now()}@example.com`;
  const password = 'smoke-test-password-123';
  res = await fetch(`${BASE_URL}/api/v1/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password, displayName: 'Smoke Test' }),
  });
  data = await json(res);
  record('POST /api/v1/auth/register', res.status === 201, res.status === 201 ? email : JSON.stringify(data));
  if (res.status !== 201) return finish();

  // 4. Log in with it.
  res = await fetch(`${BASE_URL}/api/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  data = await json(res);
  const token = data.accessToken;
  record('POST /api/v1/auth/login', res.ok && Boolean(token), token ? 'token received' : JSON.stringify(data));
  if (!token) return finish();

  // 5. Authenticated identity check.
  res = await fetch(`${BASE_URL}/api/v1/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
  data = await json(res);
  record('GET /api/v1/auth/me', res.ok && data.user?.email === email, JSON.stringify(data.user));

  // 6. Wallet exists and starts at zero.
  res = await fetch(`${BASE_URL}/api/v1/wallet/me`, { headers: { Authorization: `Bearer ${token}` } });
  data = await json(res);
  const w = data.wallet || {};
  const startsAtZero = Number(w.cashAvailable) === 0 && Number(w.bonusAvailable) === 0 && Number(w.lockedBalance) === 0;
  record('GET /api/v1/wallet/me', res.ok && startsAtZero, JSON.stringify(w));

  // 7. Wrong password is rejected.
  res = await fetch(`${BASE_URL}/api/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'definitely-wrong-password' }),
  });
  record('wrong password rejected (401)', res.status === 401);

  // 8. Logout, then confirm the old token no longer works.
  res = await fetch(`${BASE_URL}/api/v1/auth/logout`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
  record('POST /api/v1/auth/logout', res.status === 204);

  res = await fetch(`${BASE_URL}/api/v1/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
  record('token rejected after logout', res.status === 401);

  finish();
}

function finish() {
  const passed = results.filter(r => r.ok).length;
  console.log(`\n${passed}/${results.length} checks passed`);
  if (passed !== results.length) process.exitCode = 1;
}

main().catch(err => {
  console.error('Smoke test crashed before finishing:', err);
  process.exitCode = 1;
});
