#!/usr/bin/env node
// Smoke-tests a running WINZA deployment: phone+OTP auth, wallet, the KYC
// gate on withdrawals, and (optionally) staff approval of a KYC submission.
// Doesn't touch real money — there is none to touch yet.
//
// Usage:
//   node smoke-test.js https://your-app.onrender.com
//
// To also test the admin approval step, provide a staff account created with
// create-staff-account.js (role must be risk, admin, or owner):
//   STAFF_EMAIL=you@example.com STAFF_PASSWORD=... node smoke-test.js https://your-app.onrender.com
//
// The OTP steps below need the target server to have OTP_DEV_ECHO=true set
// (dev/staging only — never on a deployment real users can reach).

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
function randomPhone() {
  // Nigerian-shaped local number, random enough not to collide between runs.
  const suffix = String(Date.now()).slice(-8);
  return { raw: '070' + suffix, suffix };
}

async function main() {
  // 1. Server is up and knows about its database.
  let res = await fetch(`${BASE_URL}/healthz`);
  let data = await json(res);
  record('GET /healthz', res.ok && data.ok === true, JSON.stringify(data));
  if (!data.databaseConfigured) {
    record('database configured on server', false, 'DATABASE_URL is not set — nothing past this point can pass');
    return finish();
  }

  // 2. Public config still reports real money as disabled, and RTP is
  // within the 90-100% floor/ceiling.
  res = await fetch(`${BASE_URL}/api/v1/public/config`);
  data = await json(res);
  record('GET /api/v1/public/config', res.ok && data.realMoneyEnabled === false, JSON.stringify(data));
  record('public RTP is within 90-100%', typeof data.rtp === 'number' && data.rtp >= 0.90 && data.rtp <= 1.00, `rtp=${data.rtp}`);

  // 3. Request an OTP for a fresh phone number.
  const { raw: phone, suffix } = randomPhone();
  res = await fetch(`${BASE_URL}/api/v1/auth/otp/request`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ phone }),
  });
  data = await json(res);
  record('POST /api/v1/auth/otp/request', res.status === 202, JSON.stringify(data));
  if (res.status !== 202) return finish();
  if (!data.devCode) {
    record('devCode present (no SMS provider configured)', false, 'Set OTP_DEV_ECHO=true (and leave OTP_SMS_WEBHOOK_URL unset, WINZA_MODE non-live) on the target server to test this way, or supply the code manually.');
    return finish();
  }

  // 4. Verify it — this both registers and logs in on first use.
  res = await fetch(`${BASE_URL}/api/v1/auth/otp/verify`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ phone, code: data.devCode }),
  });
  data = await json(res);
  const token = data.accessToken;
  const originalUserId = data.user?.id;
  record('POST /api/v1/auth/otp/verify', res.ok && Boolean(token) && data.isNewAccount === true, token ? 'token received, new account' : JSON.stringify(data));
  if (!token) return finish();

  // 5. Wrong code on a second request is rejected.
  res = await fetch(`${BASE_URL}/api/v1/auth/otp/request`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ phone }),
  });
  await json(res);
  res = await fetch(`${BASE_URL}/api/v1/auth/otp/verify`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ phone, code: '000000' }),
  });
  record('wrong OTP code rejected (400)', res.status === 400);

  // 6. Identity check: phone present, no KYC fields collected at registration.
  res = await fetch(`${BASE_URL}/api/v1/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
  data = await json(res);
  record('GET /api/v1/auth/me', res.ok && data.user?.phoneNumber?.endsWith(suffix) && data.user?.kycStatus === 'not_verified', JSON.stringify(data.user));

  // 7. Wallet exists and starts at zero.
  res = await fetch(`${BASE_URL}/api/v1/wallet/me`, { headers: { Authorization: `Bearer ${token}` } });
  data = await json(res);
  const w = data.wallet || {};
  const startsAtZero = Number(w.cashAvailable) === 0 && Number(w.bonusAvailable) === 0;
  record('GET /api/v1/wallet/me', res.ok && startsAtZero, JSON.stringify(w));

  // Responsible-gambling limits: server-enforced stake-limit scheduling and
  // self-exclusion blocking login. Uses its own throwaway account since
  // self-exclusion can't be undone — reusing `token`/`phone` here would
  // permanently lock the account used by every step below this one.
  {
    const { raw: rgPhone } = randomPhone();
    res = await fetch(`${BASE_URL}/api/v1/auth/otp/request`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ phone: rgPhone }) });
    data = await json(res);
    if (data.devCode) {
      res = await fetch(`${BASE_URL}/api/v1/auth/otp/verify`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ phone: rgPhone, code: data.devCode }) });
      data = await json(res);
      const rgToken = data.accessToken;
      if (rgToken) {
        res = await fetch(`${BASE_URL}/api/v1/account/limits/stake`, { method: 'PUT', headers: { 'content-type': 'application/json', Authorization: `Bearer ${rgToken}` }, body: JSON.stringify({ dailyStakeLimit: 1000 }) });
        data = await json(res);
        record('PUT stake limit (first time, applies immediately)', res.ok && data.limits?.dailyStakeLimit === 1000, JSON.stringify(data));

        res = await fetch(`${BASE_URL}/api/v1/account/limits/stake`, { method: 'PUT', headers: { 'content-type': 'application/json', Authorization: `Bearer ${rgToken}` }, body: JSON.stringify({ dailyStakeLimit: 5000 }) });
        data = await json(res);
        record('loosening a stake limit is scheduled, not immediate', res.ok && data.limits?.dailyStakeLimit === 1000 && data.limits?.pendingDailyStakeLimit === 5000, JSON.stringify(data));

        res = await fetch(`${BASE_URL}/api/v1/account/limits/self-exclude`, { method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${rgToken}` }, body: '{}' });
        record('POST /api/v1/account/limits/self-exclude', res.ok);

        res = await fetch(`${BASE_URL}/api/v1/auth/me`, { headers: { Authorization: `Bearer ${rgToken}` } });
        record('session revoked immediately after self-exclusion', res.status === 401);

        res = await fetch(`${BASE_URL}/api/v1/auth/otp/request`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ phone: rgPhone }) });
        data = await json(res);
        if (data.devCode) {
          res = await fetch(`${BASE_URL}/api/v1/auth/otp/verify`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ phone: rgPhone, code: data.devCode }) });
          data = await json(res);
          record('login blocked after self-exclusion (403)', res.status === 403 && /self-exclusion/i.test(data.error || ''), JSON.stringify(data));
        }
      }
    } else {
      console.log('(skipping responsible-gambling checks — needs OTP_DEV_ECHO=true on the target server)');
    }
  }

  // 8. Withdrawal is blocked before KYC (assuming the default setting is on).
  res = await fetch(`${BASE_URL}/api/v1/wallet/withdrawal-requests`, {
    method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ amount: 100 }),
  });
  data = await json(res);
  record('withdrawal blocked before KYC (403)', res.status === 403, JSON.stringify(data));

  // 9. Submit KYC.
  res = await fetch(`${BASE_URL}/api/v1/kyc/submit`, {
    method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ fullName: 'Smoke Test', dateOfBirth: '1995-01-01', idType: 'nin', idNumber: '12345678901' }),
  });
  data = await json(res);
  record('POST /api/v1/kyc/submit', res.status === 201, JSON.stringify(data));

  // 10. Status now shows pending.
  res = await fetch(`${BASE_URL}/api/v1/kyc/me`, { headers: { Authorization: `Bearer ${token}` } });
  data = await json(res);
  record('GET /api/v1/kyc/me shows pending', res.ok && data.kycStatus === 'pending', JSON.stringify(data));

  // 11. Optional: staff approval, if credentials were supplied.
  if (process.env.STAFF_EMAIL && process.env.STAFF_PASSWORD) {
    res = await fetch(`${BASE_URL}/api/v1/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: process.env.STAFF_EMAIL, password: process.env.STAFF_PASSWORD }),
    });
    data = await json(res);
    const staffToken = data.accessToken;
    record('staff login', res.ok && Boolean(staffToken));
    if (staffToken) {
      res = await fetch(`${BASE_URL}/api/v1/admin/kyc/submissions?status=pending`, { headers: { Authorization: `Bearer ${staffToken}` } });
      data = await json(res);
      const submission = (data.submissions || []).find(s => s.phoneNumber?.endsWith(suffix));
      record('admin sees the pending submission', Boolean(submission));
      if (submission) {
        // No SANCTIONS_SCREENING_WEBHOOK_URL is assumed configured on a
        // typical test/staging server, so approving with no override reason
        // should be refused — the fail-safe (not fail-open) behavior is
        // exactly what's under test here, not a provider integration.
        res = await fetch(`${BASE_URL}/api/v1/admin/kyc/submissions/${submission.id}/approve`, { method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${staffToken}` }, body: '{}' });
        data = await json(res);
        const noProviderConfigured = res.status === 400 && /sanctionsScreeningOverrideReason/i.test(data.error || '');
        if (noProviderConfigured) {
          record('approval without screening requires an override reason (400)', true);
          res = await fetch(`${BASE_URL}/api/v1/admin/kyc/submissions/${submission.id}/approve`, { method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${staffToken}` }, body: JSON.stringify({ sanctionsScreeningOverrideReason: 'Smoke test — no provider configured on this deployment.' }) });
          record('admin approves the submission with an override reason', res.ok, JSON.stringify(await json(res)));
        } else {
          // A real screening provider is configured on this deployment — the
          // first call above should have succeeded outright (assuming a clear result).
          record('admin approves the submission', res.ok, JSON.stringify(data));
        }

        res = await fetch(`${BASE_URL}/api/v1/kyc/me`, { headers: { Authorization: `Bearer ${token}` } });
        data = await json(res);
        record('player now shows verified', res.ok && data.kycStatus === 'verified', JSON.stringify(data));
      }

      // RTP admin endpoint: an out-of-bounds value is rejected, a valid one is accepted.
      res = await fetch(`${BASE_URL}/api/v1/admin/game-config`, {
        method: 'PUT', headers: { 'content-type': 'application/json', Authorization: `Bearer ${staffToken}` },
        body: JSON.stringify({ rtpPercent: 50 }),
      });
      record('RTP below 90% rejected (400)', res.status === 400);

      res = await fetch(`${BASE_URL}/api/v1/admin/game-config`, {
        method: 'PUT', headers: { 'content-type': 'application/json', Authorization: `Bearer ${staffToken}` },
        body: JSON.stringify({ rtpPercent: 96 }),
      });
      data = await json(res);
      record('RTP set to 96% accepted', res.ok && data.rtp === 0.96, JSON.stringify(data));

      // Withdrawal velocity limits: bounds are enforced on the admin write,
      // and a lowered limit blocks a withdrawal request before it ever
      // reaches the balance check — the wallet stays at ₦0 in sandbox (no
      // payment processor to fund it), so this is the only way to exercise
      // the block without a real deposit.
      res = await fetch(`${BASE_URL}/api/v1/admin/withdrawal-limits`, {
        method: 'PUT', headers: { 'content-type': 'application/json', Authorization: `Bearer ${staffToken}` },
        body: JSON.stringify({ dailyAmountLimit: 1, dailyCountLimit: 5 }),
      });
      record('withdrawal amount limit below bounds rejected (400)', res.status === 400);

      res = await fetch(`${BASE_URL}/api/v1/admin/withdrawal-limits`, {
        method: 'PUT', headers: { 'content-type': 'application/json', Authorization: `Bearer ${staffToken}` },
        body: JSON.stringify({ dailyAmountLimit: 1000, dailyCountLimit: 5 }),
      });
      record('withdrawal amount limit set to ₦1,000', res.ok);

      res = await fetch(`${BASE_URL}/api/v1/wallet/withdrawal-requests`, {
        method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ amount: 5000 }),
      });
      data = await json(res);
      record('withdrawal above the daily amount limit is blocked (429)', res.status === 429 && /amount limit/i.test(data.error || ''), JSON.stringify(data));

      res = await fetch(`${BASE_URL}/api/v1/admin/withdrawal-limits`, {
        method: 'PUT', headers: { 'content-type': 'application/json', Authorization: `Bearer ${staffToken}` },
        body: JSON.stringify({ dailyAmountLimit: 500000, dailyCountLimit: 5 }),
      });
      record('withdrawal limits restored to defaults', res.ok);
    }
  } else {
    console.log('(skipping admin-approval checks — set STAFF_EMAIL/STAFF_PASSWORD to include them)');
  }

  // 12. Logout, then confirm the old token no longer works.
  res = await fetch(`${BASE_URL}/api/v1/auth/logout`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
  record('POST /api/v1/auth/logout', res.status === 204);

  res = await fetch(`${BASE_URL}/api/v1/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
  record('token rejected after logout', res.status === 401);

  // 13. Optional: phone recovery flow end-to-end (needs staff credentials,
  // same as step 11). Run last since approval revokes the account's sessions
  // and changes which phone number logs into it — reusing `token` afterward
  // would no longer prove anything.
  if (process.env.STAFF_EMAIL && process.env.STAFF_PASSWORD) {
    res = await fetch(`${BASE_URL}/api/v1/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: process.env.STAFF_EMAIL, password: process.env.STAFF_PASSWORD }),
    });
    data = await json(res);
    const staffToken = data.accessToken;
    if (staffToken) {
      const { raw: newPhoneRaw } = randomPhone();
      res = await fetch(`${BASE_URL}/api/v1/auth/recovery/phone-change-request`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ oldPhone: phone, newPhone: newPhoneRaw, fullName: 'Smoke Test', dateOfBirth: '1995-01-01', idType: 'nin', idNumber: '12345678901', reason: 'Lost phone' }),
      });
      record('POST /api/v1/auth/recovery/phone-change-request', res.status === 202);

      res = await fetch(`${BASE_URL}/api/v1/admin/phone-recovery-requests?status=pending`, { headers: { Authorization: `Bearer ${staffToken}` } });
      data = await json(res);
      const recoveryReq = (data.requests || []).find(r => r.oldPhoneNumber?.endsWith(suffix));
      record('admin sees the pending phone recovery request', Boolean(recoveryReq));
      if (recoveryReq) {
        record('KYC-on-file comparison present', Boolean(recoveryReq.kycOnFile));
        res = await fetch(`${BASE_URL}/api/v1/admin/phone-recovery-requests/${recoveryReq.id}/approve`, { method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${staffToken}` }, body: '{}' });
        record('admin approves the phone recovery request', res.ok);

        // Confirm the new number now logs into the *same* account rather
        // than registering a fresh one.
        res = await fetch(`${BASE_URL}/api/v1/auth/otp/request`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ phone: newPhoneRaw }) });
        data = await json(res);
        if (data.devCode) {
          res = await fetch(`${BASE_URL}/api/v1/auth/otp/verify`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ phone: newPhoneRaw, code: data.devCode }) });
          data = await json(res);
          record('new number logs into the same account after approval', res.ok && data.user?.id === originalUserId && data.isNewAccount === false, JSON.stringify(data.user));
        } else {
          console.log('(skipping post-approval login check — needs OTP_DEV_ECHO=true on the target server)');
        }
      }
    }
  } else {
    console.log('(skipping phone recovery checks — set STAFF_EMAIL/STAFF_PASSWORD to include them)');
  }

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
