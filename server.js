const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const auth = require('./auth');
const wallet = require('./wallet');
const otpLib = require('./otp');
const rtpConfig = require('./rtp-config');
const sanctions = require('./sanctions');
const paystackLib = require('./paystack');
const opayLib = require('./opay');
const reconciliation = require('./reconciliation');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const MODE = process.env.WINZA_MODE || 'sandbox';
// Separate from WINZA_MODE on purpose: WINZA_MODE stays 'sandbox' all the way
// through the public Play Store launch (no real money yet), so it can't be
// what gates a code-in-the-response debug path. This must be explicitly
// opted into per-deployment and left unset anywhere the app is reachable by
// real users, or anyone can request an OTP for any phone number and read the
// code straight back out of the API response.
const OTP_DEV_ECHO = process.env.OTP_DEV_ECHO === 'true';
const JWT_SECRET = process.env.JWT_SECRET || '';
// Keys the tamper-evident audit fingerprint stored on every bet (see
// game-engine.js). Not an encryption key and never sent to the client, so
// reusing JWT_SECRET as a fallback is safe (the HMAC label domain-separates
// it from JWT signing) — set a dedicated GAME_AUDIT_SECRET if you'd rather
// rotate the two independently.
const GAME_AUDIT_SECRET = process.env.GAME_AUDIT_SECRET || JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL || '';
const root = __dirname;
function sslConfig() {
  const mode = (process.env.DATABASE_SSL || '').toLowerCase();
  if (mode === '' || mode === 'false') return undefined;
  // Most managed Postgres providers (Render, Heroku, etc.) present certificates
  // that aren't in Node's default trusted CA bundle. The connection is still
  // TLS-encrypted either way; this only controls whether the certificate chain
  // itself is verified. Use DATABASE_SSL=strict once you've loaded the
  // provider's specific CA certificate via NODE_EXTRA_CA_CERTS.
  return { rejectUnauthorized: mode === 'strict' };
}
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: sslConfig() }) : null;
const attempts = new Map();

function headers(type) { return { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'" }; }
function send(res, status, payload, type='application/json; charset=utf-8') { res.writeHead(status, headers(type)); res.end(typeof payload === 'string' ? payload : JSON.stringify(payload)); }
function fail(res, status, message, requestId) { return send(res, status, { error: message, requestId }); }
function audit(userId, type, ip, metadata={}) { if (!pool) return; const ipHash=crypto.createHash('sha256').update(String(ip||'')).digest('hex'); pool.query('INSERT INTO audit_events (id,user_id,type,ip_hash,metadata) VALUES ($1,$2,$3,$4,$5)',[crypto.randomUUID(),userId||null,type,ipHash,metadata]).catch(()=>{}); }
function throttled(ip) { const now=Date.now(), record=attempts.get(ip)||{count:0,start:now}; if(now-record.start>15*60_000){record.count=0;record.start=now;} record.count++;attempts.set(ip,record);return record.count>20; }
// Behind a reverse proxy (Render, or any other PaaS), req.socket.remoteAddress
// is the proxy's own internal address — identical for every request — which
// would make rate limiting and the audit log's IP tracking meaningless. Trust
// the first hop of X-Forwarded-For instead, falling back to the socket address
// when there's no proxy in front (e.g. running locally).
function clientIp(req) { const forwarded=req.headers['x-forwarded-for']; if (forwarded) return String(forwarded).split(',')[0].trim(); return req.socket.remoteAddress; }
async function body(req) { return new Promise((resolve,reject)=>{let raw='';req.on('data',c=>{raw+=c;if(raw.length>16_384)req.destroy();});req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{});}catch{reject(new Error('Invalid JSON body'));}});req.on('error',reject);}); }
// Separate from body() on purpose: webhook signature verification (see
// paystack.js / opay.js) must run over the exact raw bytes received, before
// any JSON parsing — parsing and re-stringifying can reorder keys or change
// whitespace and silently break an HMAC computed over the original body.
async function rawBody(req) { return new Promise((resolve,reject)=>{let raw='';req.on('data',c=>{raw+=c;if(raw.length>65_536)req.destroy();});req.on('end',()=>resolve(raw));req.on('error',reject);}); }
function ready(res, requestId) { if (!pool || !JWT_SECRET || JWT_SECRET.length < 32) { fail(res,503,'Authentication service is not configured.',requestId); return false; } return true; }
async function sessionFrom(req) { const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,''); const payload=auth.verify(token,JWT_SECRET); const { rows }=await pool.query('SELECT s.id,u.id AS user_id,u.email,u.phone_number,u.display_name,u.role,u.is_active,u.kyc_status FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.expires_at>now() AND s.revoked_at IS NULL',[payload.sid]); if(!rows[0]||!rows[0].is_active)throw new Error('Unauthorized'); return rows[0]; }
function issueSession(user) { const sid=crypto.randomUUID(), expires=new Date(Date.now()+8*60*60_000); return pool.query('INSERT INTO auth_sessions (id,user_id,expires_at) VALUES ($1,$2,$3)',[sid,user.id,expires]).then(()=>({accessToken:auth.sign({sub:user.id,sid,role:user.role},JWT_SECRET,8*60*60),expiresAt:expires.toISOString()})); }
function safeUser(row) { return { id:row.id||row.user_id,email:row.email,phoneNumber:row.phone_number,displayName:row.display_name,role:row.role,mfaEnabled:Boolean(row.mfa_enabled_at),kycStatus:row.kyc_status }; }
function safeSubmission(row) { return { id:row.id,status:row.status,idType:row.id_type,submittedAt:row.created_at,reviewedAt:row.reviewed_at,rejectionReason:row.rejection_reason,sanctionsScreeningStatus:row.sanctions_screening_status,sanctionsScreeningDetail:row.sanctions_screening_detail }; }
async function getSetting(key, fallback) { const { rows }=await pool.query('SELECT value FROM platform_settings WHERE key=$1',[key]); return rows[0] ? rows[0].value : fallback; }
// The authoritative RTP for a future real-money launch. Validated on the way
// out, not just on the way in: a database row can only be written within
// bounds (see the /api/v1/admin/game-config handler and the
// enforce_game_rtp_bounds trigger in schema.sql), but this still guards
// against a missing pool (sandbox mode, no database configured) or a stored
// value that predates the 90-100% floor — either way, callers always get a
// valid RTP back, falling back to the centralized default.
async function getGameRtp() {
  if (!pool) return rtpConfig.RTP_DEFAULT;
  const raw = await getSetting('game_rtp', rtpConfig.RTP_DEFAULT);
  const value = Number(raw);
  return rtpConfig.isValidRtp(value) ? value : rtpConfig.RTP_DEFAULT;
}
function ageFromDob(dobStr) { const dob=new Date(dobStr+'T00:00:00Z'); if(Number.isNaN(dob.getTime()))return 0; const now=new Date(); let age=now.getUTCFullYear()-dob.getUTCFullYear(); const m=now.getUTCMonth()-dob.getUTCMonth(); if(m<0||(m===0&&now.getUTCDate()<dob.getUTCDate()))age--; return age; }

// Responsible-gambling limits, read fresh on every login/withdrawal attempt
// rather than cached anywhere client-side. If a scheduled stake-limit
// loosening/removal has come due, applies it here so every caller sees the
// current, correct value without a separate cron job.
async function getEffectiveLimits(userId) {
  const { rows } = await pool.query('SELECT * FROM player_limits WHERE user_id=$1',[userId]);
  let row = rows[0];
  if (row && row.pending_daily_stake_limit !== null && row.pending_stake_limit_effective_at && new Date(row.pending_stake_limit_effective_at) <= new Date()) {
    const updated = await pool.query('UPDATE player_limits SET daily_stake_limit=$1, pending_daily_stake_limit=NULL, pending_stake_limit_effective_at=NULL, updated_at=now() WHERE user_id=$2 RETURNING *',[row.pending_daily_stake_limit, userId]);
    row = updated.rows[0];
  }
  return row || null;
}
function safeLimits(row) {
  if (!row) return { dailyStakeLimit:null, pendingDailyStakeLimit:null, pendingEffectiveAt:null, coolOffUntil:null, selfExcludedUntil:null };
  return {
    dailyStakeLimit: row.daily_stake_limit===null?null:Number(row.daily_stake_limit),
    pendingDailyStakeLimit: row.pending_daily_stake_limit===null?null:Number(row.pending_daily_stake_limit),
    pendingEffectiveAt: row.pending_stake_limit_effective_at,
    coolOffUntil: row.cool_off_until,
    selfExcludedUntil: row.self_excluded_until,
  };
}
// Self-exclusion and cool-off are checked at the two points that matter most
// given there's no server-mediated wagering endpoint yet (gameplay itself is
// still a client-side simulation, see README): logging in at all, and
// withdrawing funds. Neither can be reversed early through this app — that's
// the point of a cooling-off period.
function restrictionFromLimits(row) {
  if (!row) return null;
  const now = Date.now();
  if (row.self_excluded_until && new Date(row.self_excluded_until).getTime() > now) return { type:'self_exclusion', until:row.self_excluded_until };
  if (row.cool_off_until && new Date(row.cool_off_until).getTime() > now) return { type:'cool_off', until:row.cool_off_until };
  return null;
}
function restrictionMessage(restriction) {
  return restriction.type==='self_exclusion'
    ? `Self-exclusion is active until ${new Date(restriction.until).toISOString()}. This cannot be reversed early.`
    : `Cool-off is active until ${new Date(restriction.until).toISOString()}.`;
}
// Fraud/velocity caps on withdrawals: even a fully KYC-verified account
// shouldn't be able to drain funds in one shot — a compromised session or an
// abused account is exactly the case this exists for. Admin/owner-adjustable
// (see /api/v1/admin/withdrawal-limits), bounded the same way the RTP floor
// is: never unlimited, regardless of what an admin sets.
async function getWithdrawalLimits() {
  const amount = Number(await getSetting('withdrawal_daily_amount_limit', 500000));
  const count = Number(await getSetting('withdrawal_daily_count_limit', 5));
  return {
    amount: Number.isFinite(amount) && amount>0 ? amount : 500000,
    count: Number.isFinite(count) && count>0 ? count : 5,
  };
}
// Sums this wallet's withdrawal-request amounts (the pending_withdrawal side
// of the ledger entry, not the mirrored negative cash_available side) over
// the trailing 24 hours. Reversed/rejected withdrawals still count here on
// purpose — the cap is about how much a wallet has *requested*, not how much
// ultimately got paid out, so an account can't probe the limit by requesting
// and cancelling.
async function getRecentWithdrawalActivity(walletId) {
  const { rows } = await pool.query(
    `SELECT COALESCE(SUM(le.amount),0)::numeric AS total, COUNT(*)::int AS count
     FROM wallet_ledger_entries le JOIN wallet_transactions wt ON wt.id=le.transaction_id
     WHERE wt.wallet_id=$1 AND wt.type='withdrawal_request' AND le.balance_type='pending_withdrawal' AND wt.created_at > now() - interval '24 hours'`,
    [walletId]
  );
  return { total: Number(rows[0].total), count: rows[0].count };
}

// Sums this user's bet stakes over the trailing 24 hours, for enforcing
// player_limits.daily_stake_limit in /api/v1/games/bets — same trailing-24h
// convention as getRecentWithdrawalActivity above, and same reasoning: a
// player shouldn't be able to reset the window by any client-side action.
async function getDailyStakeTotal(userId) {
  const { rows } = await pool.query(
    `SELECT COALESCE(SUM(stake),0)::numeric AS total FROM bets WHERE user_id=$1 AND created_at > now() - interval '24 hours'`,
    [userId]
  );
  return Number(rows[0].total);
}

async function handleAuth(req,res,url,requestId,ip) {
  if (!ready(res,requestId)) return;
  // Scoped to state-changing/credential-testing requests (OTP, login,
  // password reset, mutations) — not read-only GETs. A GET under an already-
  // valid session (checking your own balance, KYC status, limits) isn't a
  // brute-force vector and shouldn't share a budget with the traffic this
  // exists to slow down; gating it too just means a normal multi-action
  // session behind a shared IP/proxy can lock itself out.
  if (req.method!=='GET' && throttled(ip)) return fail(res,429,'Too many attempts. Try again later.',requestId);
  const data=await body(req);

  // --- Phone + OTP: this is the only way players register or log in now.
  // No KYC fields are collected here at all — just a phone number. KYC is a
  // separate, later step (see /api/v1/kyc/*), and whether it's required yet
  // is entirely the backend's call (platform_settings), not the client's.
  if (req.method==='POST' && url.pathname==='/api/v1/auth/otp/request') {
    let phone; try { phone=otpLib.normalizePhone(data.phone); } catch(e) { return fail(res,400,e.message,requestId); }
    const code=otpLib.generateCode(), codeHash=otpLib.hashCode(code);
    await pool.query(`INSERT INTO phone_otp_codes (id,phone_number,code_hash,expires_at) VALUES ($1,$2,$3, now() + interval '5 minutes')`,[crypto.randomUUID(),phone,codeHash]);
    const delivery=await otpLib.sendOtpSms(phone,code);
    audit(null,'auth.otp_requested',ip,{phone});
    const payload={ message:'If that number is valid, a verification code has been sent.', requestId };
    // No SMS provider is configured yet. Rather than leave you unable to test
    // this at all, the code can be echoed back here — but only when explicitly
    // opted into via OTP_DEV_ECHO, and never in live mode regardless.
    if (!delivery.delivered && MODE !== 'live' && OTP_DEV_ECHO) payload.devCode=code;
    return send(res,202,payload);
  }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/otp/verify') {
    let phone; try { phone=otpLib.normalizePhone(data.phone); } catch(e) { return fail(res,400,e.message,requestId); }
    const code=String(data.code||'').trim();
    if (!/^\d{6}$/.test(code)) return fail(res,400,'Enter the 6-digit code.',requestId);
    const { rows }=await pool.query(`SELECT * FROM phone_otp_codes WHERE phone_number=$1 AND consumed_at IS NULL AND expires_at>now() ORDER BY created_at DESC LIMIT 1`,[phone]);
    const record=rows[0];
    if (!record || record.attempts>=5 || otpLib.hashCode(code)!==record.code_hash) {
      if (record) await pool.query('UPDATE phone_otp_codes SET attempts=attempts+1 WHERE id=$1',[record.id]);
      audit(null,'auth.otp_failed',ip,{phone});
      return fail(res,400,'Code is invalid or expired.',requestId);
    }
    await pool.query('UPDATE phone_otp_codes SET consumed_at=now() WHERE id=$1',[record.id]);
    const client=await pool.connect();
    let user, isNewAccount=false;
    try {
      await client.query('BEGIN');
      const existing=await client.query('SELECT * FROM users WHERE phone_number=$1',[phone]);
      if (existing.rows[0]) { user=existing.rows[0]; }
      else {
        isNewAccount=true; const id=crypto.randomUUID();
        const inserted=await client.query('INSERT INTO users (id,phone_number,display_name) VALUES ($1,$2,$3) RETURNING *',[id,phone,'Player '+phone.slice(-4)]);
        user=inserted.rows[0];
        // Same guarantee as before: the wallet is created in the same
        // transaction as the user, so the two can never diverge.
        await wallet.createWallet(client,id);
      }
      await client.query('COMMIT');
    } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    if (!user.is_active) return fail(res,403,'This account has been disabled.',requestId);
    // A brand-new account can't have a player_limits row yet, so this only
    // ever blocks a returning player — which is exactly who self-exclusion
    // and cool-off are for.
    if (!isNewAccount) {
      const restriction=restrictionFromLimits(await getEffectiveLimits(user.id));
      if (restriction) {
        audit(user.id, restriction.type==='self_exclusion'?'auth.login_blocked_self_exclusion':'auth.login_blocked_cool_off', ip);
        return fail(res,403,restrictionMessage(restriction),requestId);
      }
    }
    const session=await issueSession(user);
    audit(user.id, isNewAccount?'account.registered_via_otp':'auth.login_succeeded', ip);
    return send(res,200,{ user:safeUser(user), isNewAccount, ...session, requestId });
  }

  // Players have no password, so there's no "forgot password" flow for them —
  // but losing access to the phone number itself (lost phone, stolen SIM, a
  // recycled number) leaves them locked out with nothing to fall back on,
  // since phone_number is a hard unique identifier. This is that recovery
  // path: unauthenticated (they can't log in, that's the whole problem),
  // staff-reviewed rather than automated, matching how KYC submissions work.
  if (req.method==='POST' && url.pathname==='/api/v1/auth/recovery/phone-change-request') {
    let oldPhone, newPhone;
    try { oldPhone=otpLib.normalizePhone(data.oldPhone); newPhone=otpLib.normalizePhone(data.newPhone); }
    catch(e) { return fail(res,400,e.message,requestId); }
    if (oldPhone===newPhone) return fail(res,400,'New number must be different from the number on file.',requestId);
    const fullName=String(data.fullName||'').trim(), dob=String(data.dateOfBirth||'').trim(), idType=String(data.idType||'').trim(), idNumber=String(data.idNumber||'').trim(), reason=String(data.reason||'').trim().slice(0,300);
    if (fullName.length<2||fullName.length>80) return fail(res,400,'Enter your full legal name.',requestId);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dob)) return fail(res,400,'Enter date of birth as YYYY-MM-DD.',requestId);
    if (ageFromDob(dob)<18) return fail(res,400,'You must be 18 or older.',requestId);
    if (!['nin','bvn','drivers_license','passport','voters_card'].includes(idType)) return fail(res,400,'Select a valid ID type.',requestId);
    if (idNumber.length<5||idNumber.length>30) return fail(res,400,'Enter a valid ID number.',requestId);
    // Telling the requester their claimed new number is already taken is
    // useful, actionable feedback and doesn't leak anything about the old
    // (possibly lost) account — safe to answer directly.
    const { rows:newTaken }=await pool.query('SELECT id FROM users WHERE phone_number=$1',[newPhone]);
    if (newTaken[0]) return fail(res,409,'That new number is already registered to an account.',requestId);
    // Same shape as password-reset/request: always return a generic 202 so
    // the response never confirms whether the old number belongs to an
    // account, but only actually create a request row when it does.
    const { rows:existing }=await pool.query('SELECT id FROM users WHERE phone_number=$1 AND is_active=true',[oldPhone]);
    if (existing[0]) {
      const { rows:pending }=await pool.query(`SELECT id FROM phone_recovery_requests WHERE user_id=$1 AND status='pending'`,[existing[0].id]);
      if (!pending[0]) {
        await pool.query('INSERT INTO phone_recovery_requests (id,user_id,old_phone_number,new_phone_number,full_name,date_of_birth,id_type,id_number,reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',[crypto.randomUUID(),existing[0].id,oldPhone,newPhone,fullName,dob,idType,idNumber,reason||null]);
        audit(existing[0].id,'account.phone_recovery_requested',ip,{oldPhone,newPhone});
      }
    }
    return send(res,202,{ message:'If that account exists, your request has been submitted for staff review.', requestId });
  }

  // Email + password registration/login below is for staff accounts
  // (support/risk/admin/owner), not players — but there's no self-serve
  // staff signup yet, so in practice accounts are provisioned with
  // create-staff-account.js. Left in place rather than removed since it's
  // still the correct mechanism once an owner-audited invite flow exists.
  if (req.method==='POST' && url.pathname==='/api/v1/auth/register') {
    auth.validateRegistration(data); const email=auth.normalizeEmail(data.email); const id=crypto.randomUUID();
    const client=await pool.connect();
    try {
      const hash=await auth.hashPassword(data.password);
      await client.query('BEGIN');
      const { rows }=await client.query('INSERT INTO users (id,email,display_name,password_hash) VALUES ($1,$2,$3,$4) RETURNING id,email,phone_number,display_name,role,mfa_enabled_at,kyc_status',[id,email,data.displayName.trim(),hash]);
      // Every account gets exactly one zero-balance wallet, created in the
      // same transaction as the user row so the two can never diverge.
      await wallet.createWallet(client,id);
      await client.query('COMMIT');
      audit(id,'account.registered',ip); return send(res,201,{user:safeUser(rows[0]),requestId});
    }
    catch(e) { await client.query('ROLLBACK'); return fail(res,e.code==='23505'?409:400,e.code==='23505'?'Account already exists.':'Unable to create account.',requestId); }
    finally { client.release(); }
  }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/login') {
    const email=auth.normalizeEmail(data.email); const { rows }=await pool.query('SELECT * FROM users WHERE email=$1',[email]); const user=rows[0];
    if(!user || !user.is_active || !(await auth.verifyPassword(data.password||'',user.password_hash))){audit(user?.id,'auth.login_failed',ip,{email});return fail(res,401,'Invalid email or password.',requestId);}
    if(user.mfa_enabled_at){ if(!data.code || !auth.validTotp(auth.decrypt(user.mfa_secret_encrypted),data.code)){audit(user.id,'auth.mfa_failed',ip);return send(res,200,{mfaRequired:true,requestId});} }
    const session=await issueSession(user);audit(user.id,'auth.login_succeeded',ip);return send(res,200,{user:safeUser(user),...session,requestId});
  }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/password-reset/request') {
    const email=auth.normalizeEmail(data.email); const { rows }=await pool.query('SELECT id FROM users WHERE email=$1 AND is_active=true',[email]);
    if(rows[0]) { const token=crypto.randomBytes(32).toString('base64url'),hash=auth.tokenHash(token); await pool.query('INSERT INTO password_reset_tokens (token_hash,user_id,expires_at) VALUES ($1,$2,now()+interval \'30 minutes\')',[hash,rows[0].id]); audit(rows[0].id,'auth.password_reset_requested',ip);
      if(process.env.PASSWORD_RESET_WEBHOOK_URL) await fetch(process.env.PASSWORD_RESET_WEBHOOK_URL,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email,token})});
    } return send(res,202,{message:'If an account exists, reset instructions will be sent.',requestId});
  }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/password-reset/confirm') {
    if(String(data.password||'').length<12)return fail(res,400,'Password must be at least 12 characters.',requestId); const hash=auth.tokenHash(data.token); const client=await pool.connect();
    try { await client.query('BEGIN'); const {rows}=await client.query('UPDATE password_reset_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING user_id',[hash]); if(!rows[0]){await client.query('ROLLBACK');return fail(res,400,'Reset link is invalid or expired.',requestId);} await client.query('UPDATE users SET password_hash=$1,updated_at=now() WHERE id=$2',[await auth.hashPassword(data.password),rows[0].user_id]);await client.query('UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL',[rows[0].user_id]);await client.query('COMMIT');audit(rows[0].user_id,'auth.password_reset_completed',ip);return send(res,200,{message:'Password updated. Please sign in.',requestId}); } catch(e){await client.query('ROLLBACK');throw e;} finally{client.release();}
  }
  let user; try { user=await sessionFrom(req); } catch { return fail(res,401,'Authentication required.',requestId); }
  if (req.method==='GET' && url.pathname==='/api/v1/auth/me') return send(res,200,{user:safeUser(user),requestId});
  if (req.method==='GET' && url.pathname==='/api/v1/wallet/me') { const row=await wallet.getWalletByUserId(pool,user.user_id); if(!row)return fail(res,404,'Wallet not found.',requestId); return send(res,200,{wallet:wallet.safeWallet(row),requestId}); }

  // Real transaction history — winza.html's Transaction History card used to
  // be entirely client-side (a local addTx() log in browser storage, never
  // fetched from the server), so a player's actual deposits/withdrawals/bets
  // never appeared there. This reads the real wallet_transactions/bets rows
  // instead. `payout` transactions (releasing a held pending_withdrawal
  // amount once staff approve — see /api/v1/admin/withdrawal-requests) are
  // excluded: they never touch cash_available, so there's nothing new to
  // show the player beyond the withdrawal_request they already saw.
  if (req.method==='GET' && url.pathname==='/api/v1/wallet/transactions') {
    const walletRow=await wallet.getWalletByUserId(pool,user.user_id); if(!walletRow)return fail(res,404,'Wallet not found.',requestId);
    const limit=Math.min(Number(url.searchParams.get('limit'))||30,100);
    const { rows }=await pool.query(`
      SELECT wt.id, wt.type, wt.created_at,
             COALESCE(le.amount,0) AS cash_delta,
             b.game_id, b.result AS bet_result, b.multiplier AS bet_multiplier
      FROM wallet_transactions wt
      LEFT JOIN LATERAL (
        SELECT SUM(amount) AS amount FROM wallet_ledger_entries WHERE transaction_id=wt.id AND balance_type='cash_available'
      ) le ON true
      LEFT JOIN bets b ON b.wallet_transaction_id=wt.id
      WHERE wt.wallet_id=$1 AND wt.type<>'payout'
      ORDER BY wt.created_at DESC
      LIMIT $2`,[walletRow.id, limit]);
    const transactions = rows.map(r=>{
      const amount=Number(r.cash_delta);
      if (r.type==='bet') {
        const win=r.bet_result==='win';
        const game=r.game_id==='wheel'?'Wheel':'Lotto';
        return { type: win?'win':'loss', amount, note: win?`${game} win ${Number(r.bet_multiplier).toFixed(1)}×`:`${game} stake`, time:r.created_at };
      }
      const notes={ deposit:'Deposit', withdrawal_request:'Withdrawal requested', withdrawal_reversal:'Withdrawal rejected — refunded', bonus:'Bonus credit' };
      return { type:r.type, amount, note: notes[r.type]||'Balance adjustment', time:r.created_at };
    });
    return send(res,200,{ transactions, requestId });
  }

  // Sandbox-only faucet. WINZA_MODE stays 'sandbox' all the way through the
  // public launch (see the WINZA_MODE comment near the top of this file), so
  // real deposits never actually reach a wallet yet — this exists purely so
  // the wheel/lotto game (a real, server-authoritative bet against this same
  // cash_available balance — see /api/v1/games/bets) has something to play
  // with pre-launch, the same role winza.html's old client-side "refill demo
  // balance" reset used to serve. Hard-disabled the instant WINZA_MODE=live:
  // nobody should ever be able to manufacture real cash this way.
  if (req.method==='POST' && url.pathname==='/api/v1/wallet/sandbox-credit') {
    if (MODE==='live') return fail(res,403,'Not available.',requestId);
    const row=await wallet.getWalletByUserId(pool,user.user_id); if(!row)return fail(res,404,'Wallet not found.',requestId);
    // Bounded regardless of what's requested — winza.html's "Refill demo
    // balance" button omits this (defaults to a full refill) and the
    // loyalty-points redemption UI passes a smaller amount, but neither the
    // client nor this endpoint can ever manufacture more than the cap below,
    // and it's completely inert the instant WINZA_MODE=live either way.
    const requested=data.amount===undefined?50000:Number(data.amount);
    if (!Number.isFinite(requested) || !Number.isInteger(requested) || requested<100 || requested>50000) {
      return fail(res,400,'amount must be a whole number between ₦100 and ₦50,000.',requestId);
    }
    const result=await wallet.postTransaction(pool,{ walletId:row.id, type:'bonus', idempotencyKey:crypto.randomUUID(), referenceType:'sandbox_faucet', entries:[{balanceType:'cash_available',amount:requested}] });
    audit(user.user_id,'wallet.sandbox_credit',ip,{amount:requested});
    return send(res,200,{ wallet:wallet.safeWallet(result.wallet), requestId });
  }

  // Deposits stay inert everywhere except a fully-configured live
  // deployment — /api/v1/public/config's realMoneyEnabled is hardcoded false
  // regardless of this. winza.html's deposit button does call this endpoint,
  // but /api/v1/public/config only ever advertises a provider (via
  // depositProviders) once WINZA_MODE=live and that provider's credentials
  // are set, so in practice nothing reaches here until that's deliberately
  // switched on post-launch-checklist.
  if (req.method==='POST' && url.pathname==='/api/v1/wallet/deposits/initiate') {
    const provider=String(data.provider||'paystack').toLowerCase();
    if (!['paystack','opay'].includes(provider)) return fail(res,400,'Select a valid payment provider.',requestId);
    const providerConfigured = provider==='paystack'
      ? Boolean(process.env.PAYSTACK_SECRET_KEY)
      : Boolean(process.env.OPAY_MERCHANT_ID && process.env.OPAY_PUBLIC_KEY && process.env.OPAY_SECRET_KEY);
    if (MODE!=='live' || !providerConfigured) {
      return fail(res,403,'Payments are unavailable until the live payment service is configured.',requestId);
    }
    const amount=Number(data.amount);
    if (!Number.isFinite(amount) || amount<100) return fail(res,400,'Enter a valid deposit amount (minimum ₦100).',requestId);
    const walletRow=await wallet.getWalletByUserId(pool,user.user_id); if(!walletRow)return fail(res,404,'Wallet not found.',requestId);
    const reference=`winza_dep_${crypto.randomUUID()}`;
    // Recorded before calling out to the provider — this is the
    // reconciliation record the webhook looks up and validates against, not
    // something trusted to appear only after a webhook says so.
    await pool.query('INSERT INTO deposit_intents (id,user_id,wallet_id,reference,amount,provider) VALUES ($1,$2,$3,$4,$5,$6)',[crypto.randomUUID(),user.user_id,walletRow.id,reference,amount,provider]);
    try {
      const result = provider==='paystack'
        ? await paystackLib.initializeTransaction({ amountNaira:amount, phoneNumber:user.phone_number, reference, callbackUrl:process.env.PAYSTACK_CALLBACK_URL })
        : await opayLib.initializeTransaction({ amountNaira:amount, reference, returnUrl:process.env.OPAY_CALLBACK_URL });
      audit(user.user_id,'wallet.deposit_initiated',ip,{reference,amount,provider});
      return send(res,200,{ authorizationUrl:result.authorizationUrl, reference, requestId });
    } catch(e) {
      await pool.query(`UPDATE deposit_intents SET status='failed' WHERE reference=$1`,[reference]);
      return fail(res,502,'Unable to start deposit with the payment provider — try again.',requestId);
    }
  }

  // Withdrawal requests never auto-pay out — they just move funds into
  // pending_withdrawal, status='pending', for staff to review and
  // approve/reject via /api/v1/admin/withdrawal-requests below. What matters
  // right now: if KYC is required, an unverified user is blocked here before
  // anything is locked, and the backend decides that — not the client.
  if (req.method==='POST' && url.pathname==='/api/v1/wallet/withdrawal-requests') {
    const amount=Number(data.amount);
    if (!Number.isFinite(amount) || amount<=0) return fail(res,400,'Enter a valid withdrawal amount.',requestId);
    // In live mode this is non-negotiable — never read from platform_settings,
    // so nobody can disable the KYC gate on a real-money deployment by
    // flipping a DB row (there isn't even an admin endpoint that writes this
    // key, but a direct SQL UPDATE against the database would otherwise still
    // work). The toggle only exists for sandbox/staging convenience.
    const kycRequired = MODE==='live' ? true : await getSetting('kyc_required_for_withdrawal', true);
    if (kycRequired && user.kyc_status!=='verified') return fail(res,403,'KYC verification is required before you can withdraw.',requestId);
    // Defense-in-depth alongside the login-time check: a session issued just
    // before a self-exclusion or cool-off started is still valid for up to 8
    // hours (see issueSession), so withdrawals need their own check too.
    const restriction=restrictionFromLimits(await getEffectiveLimits(user.user_id));
    if (restriction) return fail(res,403,restrictionMessage(restriction),requestId);
    const row=await wallet.getWalletByUserId(pool,user.user_id); if(!row)return fail(res,404,'Wallet not found.',requestId);
    const withdrawalLimits=await getWithdrawalLimits();
    const recentActivity=await getRecentWithdrawalActivity(row.id);
    if (recentActivity.count+1>withdrawalLimits.count) return fail(res,429,`Daily withdrawal request limit reached (${withdrawalLimits.count} per 24 hours). Try again later or contact support.`,requestId);
    if (recentActivity.total+amount>withdrawalLimits.amount) return fail(res,429,`Daily withdrawal amount limit reached (₦${withdrawalLimits.amount.toLocaleString()} per 24 hours). Try again later or contact support.`,requestId);
    try {
      const result=await wallet.postTransaction(pool,{ walletId:row.id, type:'withdrawal_request', status:'pending', idempotencyKey:data.idempotencyKey||crypto.randomUUID(), referenceType:'withdrawal', entries:[{balanceType:'cash_available',amount:-amount},{balanceType:'pending_withdrawal',amount}] });
      audit(user.user_id,'wallet.withdrawal_requested',ip,{amount});
      return send(res,201,{ wallet:wallet.safeWallet(result.wallet), requestId });
    } catch(e) { return fail(res,400,'Unable to process withdrawal request (insufficient balance).',requestId); }
  }

  if (req.method==='GET' && url.pathname==='/api/v1/kyc/me') {
    const { rows }=await pool.query('SELECT * FROM kyc_submissions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1',[user.user_id]);
    return send(res,200,{ kycStatus:user.kyc_status, latestSubmission:rows[0]?safeSubmission(rows[0]):null, requestId });
  }
  if (req.method==='POST' && url.pathname==='/api/v1/kyc/submit') {
    if (user.kyc_status==='verified') return fail(res,400,'This account is already verified.',requestId);
    const fullName=String(data.fullName||'').trim(), dob=String(data.dateOfBirth||'').trim(), idType=String(data.idType||'').trim(), idNumber=String(data.idNumber||'').trim();
    if (fullName.length<2||fullName.length>80) return fail(res,400,'Enter your full legal name.',requestId);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dob)) return fail(res,400,'Enter date of birth as YYYY-MM-DD.',requestId);
    if (ageFromDob(dob)<18) return fail(res,400,'You must be 18 or older.',requestId);
    if (!['nin','bvn','drivers_license','passport','voters_card'].includes(idType)) return fail(res,400,'Select a valid ID type.',requestId);
    if (idNumber.length<5||idNumber.length>30) return fail(res,400,'Enter a valid ID number.',requestId);
    const { rows:pending }=await pool.query(`SELECT id FROM kyc_submissions WHERE user_id=$1 AND status='pending'`,[user.user_id]);
    if (pending[0]) return fail(res,409,'A submission is already pending review.',requestId);
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('INSERT INTO kyc_submissions (id,user_id,full_name,date_of_birth,id_type,id_number) VALUES ($1,$2,$3,$4,$5,$6)',[crypto.randomUUID(),user.user_id,fullName,dob,idType,idNumber]);
      await client.query(`UPDATE users SET kyc_status='pending', updated_at=now() WHERE id=$1`,[user.user_id]);
      await client.query('COMMIT');
    } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    audit(user.user_id,'kyc.submitted',ip);
    return send(res,201,{ message:'Submitted for review.', requestId });
  }

  if (req.method==='GET' && url.pathname==='/api/v1/account/limits') {
    return send(res,200,{ limits: safeLimits(await getEffectiveLimits(user.user_id)), requestId });
  }
  if (req.method==='PUT' && url.pathname==='/api/v1/account/limits/stake') {
    const raw=data.dailyStakeLimit;
    const newLimit = raw===null||raw===undefined||raw==='' ? null : Number(raw);
    if (newLimit!==null && (!Number.isFinite(newLimit) || newLimit<=0)) return fail(res,400,'Enter a valid stake limit, or null to remove it.',requestId);
    const current=await getEffectiveLimits(user.user_id);
    const currentLimit = current && current.daily_stake_limit!==null ? Number(current.daily_stake_limit) : null;
    // Tightening a limit (or setting one for the first time) protects the
    // player, so it applies immediately. Loosening or removing one is
    // exactly the kind of impulsive decision these controls exist to slow
    // down, so it's deferred 24 hours instead.
    const isLoosening = currentLimit!==null && (newLimit===null || newLimit>currentLimit);
    if (isLoosening) {
      await pool.query(`INSERT INTO player_limits (user_id, daily_stake_limit, pending_daily_stake_limit, pending_stake_limit_effective_at, updated_at) VALUES ($1,$2,$3, now() + interval '24 hours', now())
        ON CONFLICT (user_id) DO UPDATE SET pending_daily_stake_limit=$3, pending_stake_limit_effective_at=now()+interval '24 hours', updated_at=now()`,[user.user_id, currentLimit, newLimit]);
      audit(user.user_id,'account.stake_limit_change_scheduled',ip,{newLimit});
      return send(res,200,{ message:'Change scheduled — takes effect in 24 hours.', limits: safeLimits(await getEffectiveLimits(user.user_id)), requestId });
    }
    await pool.query(`INSERT INTO player_limits (user_id, daily_stake_limit, pending_daily_stake_limit, pending_stake_limit_effective_at, updated_at) VALUES ($1,$2,NULL,NULL,now())
      ON CONFLICT (user_id) DO UPDATE SET daily_stake_limit=$2, pending_daily_stake_limit=NULL, pending_stake_limit_effective_at=NULL, updated_at=now()`,[user.user_id,newLimit]);
    audit(user.user_id,'account.stake_limit_updated',ip,{newLimit});
    return send(res,200,{ message:'Stake limit updated.', limits: safeLimits(await getEffectiveLimits(user.user_id)), requestId });
  }
  if (req.method==='POST' && url.pathname==='/api/v1/account/limits/cool-off') {
    const hours=Number(data.hours);
    if (!Number.isFinite(hours) || hours<24 || hours>720) return fail(res,400,'Cool-off must be between 24 and 720 hours.',requestId);
    const current=await getEffectiveLimits(user.user_id);
    const proposedUntil=new Date(Date.now()+hours*3600000);
    // Same no-early-reversal principle as self-exclusion, just for a shorter,
    // player-chosen window: cool-off can be extended but never shortened
    // once active.
    if (current && current.cool_off_until && new Date(current.cool_off_until)>proposedUntil) {
      return fail(res,400,'An active cool-off cannot be shortened.',requestId);
    }
    await pool.query(`INSERT INTO player_limits (user_id, cool_off_until, updated_at) VALUES ($1,$2,now())
      ON CONFLICT (user_id) DO UPDATE SET cool_off_until=$2, updated_at=now()`,[user.user_id, proposedUntil]);
    await pool.query('UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL',[user.user_id]);
    audit(user.user_id,'account.cool_off_started',ip,{hours});
    return send(res,200,{ message:'Cool-off started. You have been signed out and cannot log back in until it ends.', coolOffUntil:proposedUntil.toISOString(), requestId });
  }
  if (req.method==='POST' && url.pathname==='/api/v1/account/limits/self-exclude') {
    const until=new Date(Date.now()+180*86400000);
    await pool.query(`INSERT INTO player_limits (user_id, self_excluded_until, updated_at) VALUES ($1,$2,now())
      ON CONFLICT (user_id) DO UPDATE SET self_excluded_until=$2, updated_at=now()`,[user.user_id, until]);
    await pool.query('UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL',[user.user_id]);
    audit(user.user_id,'account.self_exclusion_started',ip);
    return send(res,200,{ message:'Self-exclusion started. This cannot be undone before it ends.', selfExcludedUntil:until.toISOString(), requestId });
  }

  if (req.method==='POST' && url.pathname==='/api/v1/auth/logout') { await pool.query('UPDATE auth_sessions SET revoked_at=now() WHERE id=$1',[user.id]);audit(user.user_id,'auth.logout',ip);return send(res,204,''); }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/mfa/enroll') { const secret=auth.randomBase32(); await pool.query('UPDATE users SET mfa_pending_secret_encrypted=$1 WHERE id=$2',[auth.encrypt(secret),user.user_id]);return send(res,200,{secret,otpauthUrl:`otpauth://totp/WINZA:${encodeURIComponent(user.email)}?secret=${secret}&issuer=WINZA&algorithm=SHA1&digits=6&period=30`,requestId}); }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/mfa/confirm') { const {rows}=await pool.query('SELECT mfa_pending_secret_encrypted FROM users WHERE id=$1',[user.user_id]);if(!rows[0]?.mfa_pending_secret_encrypted||!auth.validTotp(auth.decrypt(rows[0].mfa_pending_secret_encrypted),data.code))return fail(res,400,'Invalid authenticator code.',requestId);await pool.query('UPDATE users SET mfa_secret_encrypted=mfa_pending_secret_encrypted,mfa_pending_secret_encrypted=NULL,mfa_enabled_at=now() WHERE id=$1',[user.user_id]);audit(user.user_id,'auth.mfa_enabled',ip);return send(res,200,{message:'MFA enabled.',requestId}); }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/mfa/disable') { if(!data.code)return fail(res,400,'Authenticator code is required.',requestId);const {rows}=await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id=$1',[user.user_id]);if(!rows[0]?.mfa_secret_encrypted||!auth.validTotp(auth.decrypt(rows[0].mfa_secret_encrypted),data.code))return fail(res,400,'Invalid authenticator code.',requestId);await pool.query('UPDATE users SET mfa_secret_encrypted=NULL,mfa_enabled_at=NULL WHERE id=$1',[user.user_id]);audit(user.user_id,'auth.mfa_disabled',ip);return send(res,200,{message:'MFA disabled.',requestId}); }
  return fail(res,404,'Not found',requestId);
}

// The only place a wheel/lotto bet is ever placed. The client sends the
// stake, multiplier, and gameId it wants — nothing else it sends can affect
// the outcome. Everything that decides win/loss and money movement (RNG,
// RTP, the wallet debit/credit, the audit row) happens server-side inside
// wallet.placeBet(); this handler is purely request validation plus turning
// the result into the response the client is allowed to see.
async function handleGames(req,res,url,requestId,ip) {
  if (!ready(res,requestId)) return;
  let user; try { user=await sessionFrom(req); } catch { return fail(res,401,'Authentication required.',requestId); }

  if (req.method==='POST' && url.pathname==='/api/v1/games/bets') {
    const data=await body(req);
    const gameId=String(data.gameId||'');
    if (!rtpConfig.isValidGameId(gameId)) return fail(res,400,`gameId must be one of: ${rtpConfig.GAME_IDS.join(', ')}.`,requestId);
    const stake=Number(data.stake);
    if (!rtpConfig.isValidStake(stake)) return fail(res,400,`Stake must be a whole number between ₦${rtpConfig.STAKE_MIN.toLocaleString()} and ₦${rtpConfig.STAKE_MAX.toLocaleString()}.`,requestId);
    const multiplier=Number(data.multiplier);
    if (!rtpConfig.isValidMultiplier(multiplier)) return fail(res,400,`Multiplier must be between ${rtpConfig.MULTIPLIER_MIN}x and ${rtpConfig.MULTIPLIER_MAX}x, in 0.1 steps.`,requestId);
    // The client generates one clientRequestId per spin/draw and resends the
    // exact same value if it retries (e.g. after a dropped connection) —
    // this is what makes a duplicate submission a safe no-op instead of a
    // second charge. See wallet.placeBet()'s idempotency handling.
    const clientRequestId=String(data.clientRequestId||'').trim();
    if (!clientRequestId || clientRequestId.length>128) return fail(res,400,'A valid clientRequestId is required.',requestId);

    // Same protection as login/withdrawal: a session issued just before a
    // self-exclusion or cool-off started is still valid for up to 8 hours
    // (see issueSession), so betting needs its own check too.
    const limits=await getEffectiveLimits(user.user_id);
    const restriction=restrictionFromLimits(limits);
    if (restriction) return fail(res,403,restrictionMessage(restriction),requestId);

    if (limits && limits.daily_stake_limit!==null) {
      const dailyLimit=Number(limits.daily_stake_limit);
      const alreadyStaked=await getDailyStakeTotal(user.user_id);
      if (alreadyStaked+stake>dailyLimit) {
        return fail(res,429,`This bet would exceed your daily stake limit of ₦${dailyLimit.toLocaleString()}. You've staked ₦${alreadyStaked.toLocaleString()} in the last 24 hours.`,requestId);
      }
    }

    const walletRow=await wallet.getWalletByUserId(pool,user.user_id);
    if (!walletRow) return fail(res,404,'Wallet not found.',requestId);

    const rtp=await getGameRtp();
    let placed;
    try {
      placed=await wallet.placeBet(pool,{
        userId:user.user_id, walletId:walletRow.id,
        gameId, stake, multiplier, rtp,
        clientRequestId, auditSecret:GAME_AUDIT_SECRET,
        balanceType:'cash_available',
        metadata:{ gameId },
      });
    } catch(e) {
      // The pre-check inside placeBet already covers the common case; the
      // wallets.cash_available >= 0 CHECK constraint (23514) is the
      // database-level backstop if a race ever got past it.
      if (e.code==='INSUFFICIENT_BALANCE' || e.code==='23514') return fail(res,400,'Insufficient balance for this stake.',requestId);
      throw e;
    }

    const { bet, wallet:updatedWallet }=placed;
    if (!placed.alreadyPlaced) {
      audit(user.user_id, bet.result==='win'?'game.bet_won':'game.bet_lost', ip, {
        betId:bet.id, gameId, stake:Number(bet.stake), multiplier:Number(bet.multiplier), payout:Number(bet.payout),
      });
    }
    // Requirement: return only the final result — outcome, payout, updated
    // balance, transaction id. Nothing here reveals the raw random draw, the
    // chance used, or anything else that could help a client reverse-engineer
    // or predict future outcomes; that detail lives only in the `bets` audit
    // row for staff/regulatory review.
    return send(res, placed.alreadyPlaced?200:201, {
      outcome:bet.result,
      stake:Number(bet.stake),
      multiplier:Number(bet.multiplier),
      payout:Number(bet.payout),
      balance:Number(updatedWallet.cash_available),
      betId:bet.id,
      transactionId:bet.wallet_transaction_id,
      requestId,
    });
  }

  return fail(res,404,'Not found',requestId);
}

async function handleAdmin(req,res,url,requestId,ip) {
  if (!ready(res,requestId)) return;
  let user; try { user=await sessionFrom(req); } catch { return fail(res,401,'Authentication required.',requestId); }
  if (!['risk','admin','owner'].includes(user.role)) return fail(res,403,'Forbidden.',requestId);

  if (req.method==='GET' && url.pathname==='/api/v1/admin/kyc/submissions') {
    const status=url.searchParams.get('status')||'pending';
    if (!['pending','verified','rejected'].includes(status)) return fail(res,400,'Invalid status filter.',requestId);
    const { rows }=await pool.query(`SELECT k.*, u.phone_number, u.display_name FROM kyc_submissions k JOIN users u ON u.id=k.user_id WHERE k.status=$1 ORDER BY k.created_at ASC`,[status]);
    return send(res,200,{ submissions: rows.map(r=>({ ...safeSubmission(r), userId:r.user_id, phoneNumber:r.phone_number, displayName:r.display_name, fullName:r.full_name, dateOfBirth:r.date_of_birth, idNumber:r.id_number })), requestId });
  }

  const approveMatch = req.method==='POST' && url.pathname.match(/^\/api\/v1\/admin\/kyc\/submissions\/([0-9a-f-]{36})\/approve$/);
  const rejectMatch  = req.method==='POST' && url.pathname.match(/^\/api\/v1\/admin\/kyc\/submissions\/([0-9a-f-]{36})\/reject$/);
  const approveWithdrawalMatch = req.method==='POST' && url.pathname.match(/^\/api\/v1\/admin\/withdrawal-requests\/([0-9a-f-]{36})\/approve$/);
  const rejectWithdrawalMatch  = req.method==='POST' && url.pathname.match(/^\/api\/v1\/admin\/withdrawal-requests\/([0-9a-f-]{36})\/reject$/);
  // Read-only RTP lookup — any staff role (support/risk/admin/owner, gated
  // above) can see the current configured RTP and its bounds.
  if (req.method==='GET' && url.pathname==='/api/v1/admin/game-config') {
    return send(res,200,{ rtp:await getGameRtp(), rtpMin:rtpConfig.RTP_MIN, rtpMax:rtpConfig.RTP_MAX, requestId });
  }

  // Changing the RTP is a financial-risk control, not a KYC action — restrict
  // it beyond the support/risk/admin/owner gate above to admin/owner only.
  if (req.method==='PUT' && url.pathname==='/api/v1/admin/game-config') {
    if (!['admin','owner'].includes(user.role)) return fail(res,403,'Forbidden.',requestId);
    const data=await body(req);
    const rtpPercent=Number(data.rtpPercent);
    const rtp=rtpPercent/100;
    // Server-side validation: reject anything outside 90-100% regardless of
    // what the admin UI's slider already enforced client-side — the UI is
    // never trusted as the only line of defense. The database trigger
    // (enforce_game_rtp_bounds in schema.sql) enforces the same bounds again
    // on the write itself, so even a direct SQL statement can't bypass this.
    if (!Number.isFinite(rtpPercent) || !rtpConfig.isValidRtp(rtp)) {
      return fail(res,400,`RTP must be between ${rtpConfig.RTP_MIN*100}% and ${rtpConfig.RTP_MAX*100}%.`,requestId);
    }
    await pool.query('INSERT INTO platform_settings (key,value,updated_at) VALUES ($1,$2,now()) ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=now()',['game_rtp', JSON.stringify(rtp)]);
    audit(user.user_id,'admin.rtp_updated',ip,{ rtp });
    return send(res,200,{ rtp, requestId });
  }

  // Manually resolves deposit_intents rows stuck in `pending` (abandoned
  // checkout, dropped webhook) by polling the provider directly — the same
  // job also runs automatically on a timer (see the setInterval near
  // server.listen below); this lets staff trigger it on demand instead of
  // waiting for the next scheduled run. Same risk tier as RTP/withdrawal
  // limits: it can credit a wallet, so admin/owner only.
  if (req.method==='POST' && url.pathname==='/api/v1/admin/reconcile-deposits') {
    if (!['admin','owner'].includes(user.role)) return fail(res,403,'Forbidden.',requestId);
    const results = await reconciliation.reconcileStuckDeposits(pool, { audit });
    audit(user.user_id,'admin.deposit_reconciliation_run',ip,{ triggeredBy:'manual', count:results.length });
    return send(res,200,{ results, requestId });
  }

  // Read-only queue of withdrawal requests — any staff role gated above
  // (risk/admin/owner) can see it, same as the KYC queue. `status` mirrors
  // wallet_transactions.status for type='withdrawal_request': 'pending'
  // (awaiting review), 'posted' (approved — staff have paid the player
  // outside the app), or 'rejected' (funds returned to cash_available).
  if (req.method==='GET' && url.pathname==='/api/v1/admin/withdrawal-requests') {
    const status=url.searchParams.get('status')||'pending';
    if (!['pending','posted','rejected'].includes(status)) return fail(res,400,'Invalid status filter.',requestId);
    const { rows }=await pool.query(`
      SELECT wt.id, wt.status, wt.created_at, wt.reviewed_at, wt.rejection_reason, le.amount,
             u.id AS user_id, u.display_name, u.phone_number, u.kyc_status
      FROM wallet_transactions wt
      JOIN wallets w ON w.id=wt.wallet_id
      JOIN users u ON u.id=w.user_id
      JOIN wallet_ledger_entries le ON le.transaction_id=wt.id AND le.balance_type='pending_withdrawal'
      WHERE wt.type='withdrawal_request' AND wt.status=$1
      ORDER BY wt.created_at ASC`,[status]);
    return send(res,200,{ requests: rows.map(r=>({ id:r.id, status:r.status, userId:r.user_id, displayName:r.display_name, phoneNumber:r.phone_number, kycStatus:r.kyc_status, amount:Number(r.amount), requestedAt:r.created_at, reviewedAt:r.reviewed_at, rejectionReason:r.rejection_reason })), requestId });
  }

  // Approving/rejecting a withdrawal moves real money — same risk tier as
  // RTP/withdrawal-limit changes, restricted beyond the risk/admin/owner
  // gate above to admin/owner only.
  //
  // This app never pays out automatically (see README): approving here only
  // records that staff have decided to pay the player via bank transfer/
  // payment provider *outside* this app, and releases the held
  // pending_withdrawal amount. The money movement (wallet.postTransaction)
  // happens before the status flip, same ordering the deposit webhooks use —
  // so if the process dies between the two, the ledger is already correct
  // and a retried approve call is a safe no-op (idempotencyKey keyed off
  // this request's id).
  if (approveWithdrawalMatch) {
    if (!['admin','owner'].includes(user.role)) return fail(res,403,'Forbidden.',requestId);
    const withdrawalId=approveWithdrawalMatch[1];
    const { rows }=await pool.query(`
      SELECT wt.id, wt.wallet_id, le.amount FROM wallet_transactions wt
      JOIN wallet_ledger_entries le ON le.transaction_id=wt.id AND le.balance_type='pending_withdrawal'
      WHERE wt.id=$1 AND wt.type='withdrawal_request' AND wt.status='pending'`,[withdrawalId]);
    const reqRow=rows[0];
    if (!reqRow) return fail(res,404,'No pending withdrawal request with that id.',requestId);
    await wallet.postTransaction(pool,{ walletId:reqRow.wallet_id, type:'payout', idempotencyKey:`payout_of_${reqRow.id}`, referenceType:'withdrawal_request', referenceId:reqRow.id, entries:[{balanceType:'pending_withdrawal',amount:-Number(reqRow.amount)}] });
    await pool.query(`UPDATE wallet_transactions SET status='posted', reviewed_by=$1, reviewed_at=now() WHERE id=$2 AND status='pending'`,[user.user_id,reqRow.id]);
    audit(user.user_id,'admin.withdrawal_approved',ip,{withdrawalId:reqRow.id, amount:reqRow.amount});
    return send(res,200,{ message:'Approved.', requestId });
  }
  if (rejectWithdrawalMatch) {
    if (!['admin','owner'].includes(user.role)) return fail(res,403,'Forbidden.',requestId);
    const withdrawalId=rejectWithdrawalMatch[1];
    const data=await body(req);
    const { rows }=await pool.query(`
      SELECT wt.id, wt.wallet_id, le.amount FROM wallet_transactions wt
      JOIN wallet_ledger_entries le ON le.transaction_id=wt.id AND le.balance_type='pending_withdrawal'
      WHERE wt.id=$1 AND wt.type='withdrawal_request' AND wt.status='pending'`,[withdrawalId]);
    const reqRow=rows[0];
    if (!reqRow) return fail(res,404,'No pending withdrawal request with that id.',requestId);
    const reason=String(data.reason||'').trim().slice(0,300)||'Not specified';
    await wallet.postTransaction(pool,{ walletId:reqRow.wallet_id, type:'withdrawal_reversal', idempotencyKey:`reversal_of_${reqRow.id}`, referenceType:'withdrawal_request', referenceId:reqRow.id, entries:[{balanceType:'pending_withdrawal',amount:-Number(reqRow.amount)},{balanceType:'cash_available',amount:Number(reqRow.amount)}] });
    await pool.query(`UPDATE wallet_transactions SET status='rejected', reviewed_by=$1, reviewed_at=now(), rejection_reason=$2 WHERE id=$3 AND status='pending'`,[user.user_id,reason,reqRow.id]);
    audit(user.user_id,'admin.withdrawal_rejected',ip,{withdrawalId:reqRow.id, amount:reqRow.amount, reason});
    return send(res,200,{ message:'Rejected — funds returned to the player.', requestId });
  }

  const WITHDRAWAL_LIMIT_BOUNDS = { minAmount:1000, maxAmount:50000000, minCount:1, maxCount:50 };
  if (req.method==='GET' && url.pathname==='/api/v1/admin/withdrawal-limits') {
    return send(res,200,{ limits:await getWithdrawalLimits(), bounds:WITHDRAWAL_LIMIT_BOUNDS, requestId });
  }
  // Same risk-control tier as RTP: admin/owner only, bounded so an
  // over-permissive value (or an empty one) can't disable fraud protection
  // entirely — there's always SOME daily cap, never "unlimited."
  if (req.method==='PUT' && url.pathname==='/api/v1/admin/withdrawal-limits') {
    if (!['admin','owner'].includes(user.role)) return fail(res,403,'Forbidden.',requestId);
    const data=await body(req);
    const amount=Number(data.dailyAmountLimit), count=Number(data.dailyCountLimit);
    if (!Number.isFinite(amount) || amount<WITHDRAWAL_LIMIT_BOUNDS.minAmount || amount>WITHDRAWAL_LIMIT_BOUNDS.maxAmount) {
      return fail(res,400,`Daily amount limit must be between ₦${WITHDRAWAL_LIMIT_BOUNDS.minAmount.toLocaleString()} and ₦${WITHDRAWAL_LIMIT_BOUNDS.maxAmount.toLocaleString()}.`,requestId);
    }
    if (!Number.isInteger(count) || count<WITHDRAWAL_LIMIT_BOUNDS.minCount || count>WITHDRAWAL_LIMIT_BOUNDS.maxCount) {
      return fail(res,400,`Daily count limit must be a whole number between ${WITHDRAWAL_LIMIT_BOUNDS.minCount} and ${WITHDRAWAL_LIMIT_BOUNDS.maxCount}.`,requestId);
    }
    await pool.query('INSERT INTO platform_settings (key,value,updated_at) VALUES ($1,$2,now()) ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=now()',['withdrawal_daily_amount_limit', JSON.stringify(amount)]);
    await pool.query('INSERT INTO platform_settings (key,value,updated_at) VALUES ($1,$2,now()) ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=now()',['withdrawal_daily_count_limit', JSON.stringify(count)]);
    audit(user.user_id,'admin.withdrawal_limits_updated',ip,{ amount, count });
    return send(res,200,{ limits:{ amount, count }, requestId });
  }

  if (approveMatch) {
    const submissionId=approveMatch[1];
    const data=await body(req);
    // Screen before opening a transaction — an external HTTP call (a real
    // screening provider) should never happen while holding a FOR UPDATE
    // row lock. Re-checked for status='pending' again inside the
    // transaction below to close the race against a second reviewer.
    const { rows:lookup }=await pool.query(`SELECT * FROM kyc_submissions WHERE id=$1 AND status='pending'`,[submissionId]);
    const pendingSubmission=lookup[0];
    if (!pendingSubmission) return fail(res,404,'No pending submission with that id.',requestId);

    let screeningStatus, screeningDetail;
    try {
      const result=await sanctions.screen({ fullName:pendingSubmission.full_name, dateOfBirth:pendingSubmission.date_of_birth, idType:pendingSubmission.id_type, idNumber:pendingSubmission.id_number });
      if (!result.configured) {
        // Fail safe, not fail open: no provider configured does NOT mean
        // "treat as clear" — it means a human has to explicitly say so, and
        // that reason is logged and stored on the submission permanently.
        const override=String(data.sanctionsScreeningOverrideReason||'').trim();
        if (override.length<10) return fail(res,400,'No sanctions-screening provider is configured. Approving requires sanctionsScreeningOverrideReason (10+ characters) explicitly acknowledging this was not automatically screened.',requestId);
        screeningStatus='not_configured_override'; screeningDetail=override.slice(0,500);
      } else if (result.hit) {
        audit(user.user_id,'kyc.sanctions_hit_blocked_approval',ip,{submissionId,detail:result.detail});
        return fail(res,409,'This submission matched a sanctions/PEP screening result and cannot be approved this way. Reject it or escalate for manual review.',requestId);
      } else {
        screeningStatus='clear'; screeningDetail=result.detail||null;
      }
    } catch(e) { return fail(res,502,'Sanctions screening provider request failed — try again.',requestId); }

    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows }=await client.query(`SELECT * FROM kyc_submissions WHERE id=$1 AND status='pending' FOR UPDATE`,[submissionId]);
      const submission=rows[0];
      if (!submission) { await client.query('ROLLBACK'); return fail(res,404,'No pending submission with that id.',requestId); }
      await client.query(`UPDATE kyc_submissions SET status='verified', reviewed_by=$1, reviewed_at=now(), sanctions_screening_status=$2, sanctions_screening_detail=$3, sanctions_screened_at=now() WHERE id=$4`,[user.user_id,screeningStatus,screeningDetail,submissionId]);
      await client.query(`UPDATE users SET kyc_status='verified', kyc_reviewed_by=$1, kyc_reviewed_at=now(), updated_at=now() WHERE id=$2`,[user.user_id,submission.user_id]);
      await client.query('COMMIT');
    } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    audit(user.user_id,'kyc.approved',ip,{submissionId,screeningStatus});
    return send(res,200,{ message:'Approved.', requestId });
  }
  if (rejectMatch) {
    const submissionId=rejectMatch[1];
    const data=await body(req);
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows }=await client.query(`SELECT * FROM kyc_submissions WHERE id=$1 AND status='pending' FOR UPDATE`,[submissionId]);
      const submission=rows[0];
      if (!submission) { await client.query('ROLLBACK'); return fail(res,404,'No pending submission with that id.',requestId); }
      const reason=String(data.reason||'').trim().slice(0,300)||'Not specified';
      await client.query(`UPDATE kyc_submissions SET status='rejected', reviewed_by=$1, reviewed_at=now(), rejection_reason=$2 WHERE id=$3`,[user.user_id,reason,submissionId]);
      await client.query(`UPDATE users SET kyc_status='rejected', kyc_reviewed_by=$1, kyc_reviewed_at=now(), updated_at=now() WHERE id=$2`,[user.user_id,submission.user_id]);
      await client.query('COMMIT');
    } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    audit(user.user_id,'kyc.rejected',ip,{submissionId});
    return send(res,200,{ message:'Rejected.', requestId });
  }

  if (req.method==='GET' && url.pathname==='/api/v1/admin/phone-recovery-requests') {
    const status=url.searchParams.get('status')||'pending';
    if (!['pending','approved','rejected'].includes(status)) return fail(res,400,'Invalid status filter.',requestId);
    // Join the latest verified KYC submission on file (if any) so staff can
    // compare the identity details submitted here against what's already
    // verified for the account, instead of trusting the request in isolation.
    const { rows }=await pool.query(`
      SELECT r.*, u.display_name,
        k.full_name AS kyc_full_name, k.date_of_birth AS kyc_date_of_birth,
        k.id_type AS kyc_id_type, k.id_number AS kyc_id_number
      FROM phone_recovery_requests r
      JOIN users u ON u.id=r.user_id
      LEFT JOIN LATERAL (
        SELECT * FROM kyc_submissions WHERE user_id=r.user_id AND status='verified' ORDER BY created_at DESC LIMIT 1
      ) k ON true
      WHERE r.status=$1 ORDER BY r.created_at ASC`,[status]);
    return send(res,200,{ requests: rows.map(r=>({
      id:r.id, userId:r.user_id, displayName:r.display_name,
      oldPhoneNumber:r.old_phone_number, newPhoneNumber:r.new_phone_number,
      fullName:r.full_name, dateOfBirth:r.date_of_birth, idType:r.id_type, idNumber:r.id_number,
      reason:r.reason, status:r.status, submittedAt:r.created_at, reviewedAt:r.reviewed_at, rejectionReason:r.rejection_reason,
      kycOnFile: r.kyc_full_name ? { fullName:r.kyc_full_name, dateOfBirth:r.kyc_date_of_birth, idType:r.kyc_id_type, idNumber:r.kyc_id_number } : null,
    })), requestId });
  }

  const recoveryApproveMatch = req.method==='POST' && url.pathname.match(/^\/api\/v1\/admin\/phone-recovery-requests\/([0-9a-f-]{36})\/approve$/);
  const recoveryRejectMatch  = req.method==='POST' && url.pathname.match(/^\/api\/v1\/admin\/phone-recovery-requests\/([0-9a-f-]{36})\/reject$/);
  if (recoveryApproveMatch || recoveryRejectMatch) {
    const reqId=(recoveryApproveMatch||recoveryRejectMatch)[1];
    const data=await body(req);
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows }=await client.query(`SELECT * FROM phone_recovery_requests WHERE id=$1 AND status='pending' FOR UPDATE`,[reqId]);
      const reqRow=rows[0];
      if (!reqRow) { await client.query('ROLLBACK'); return fail(res,404,'No pending request with that id.',requestId); }
      if (recoveryApproveMatch) {
        await client.query('UPDATE users SET phone_number=$1, updated_at=now() WHERE id=$2',[reqRow.new_phone_number,reqRow.user_id]);
        await client.query(`UPDATE phone_recovery_requests SET status='approved', reviewed_by=$1, reviewed_at=now() WHERE id=$2`,[user.user_id,reqId]);
        // A session tied to the old identity shouldn't silently carry over a
        // phone-number change — force a fresh OTP login on the new number.
        await client.query('UPDATE auth_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL',[reqRow.user_id]);
      } else {
        const reason=String(data.reason||'').trim().slice(0,300)||'Not specified';
        await client.query(`UPDATE phone_recovery_requests SET status='rejected', reviewed_by=$1, reviewed_at=now(), rejection_reason=$2 WHERE id=$3`,[user.user_id,reason,reqId]);
      }
      await client.query('COMMIT');
    } catch(e) {
      await client.query('ROLLBACK');
      // The new number could have been claimed by another account between
      // request and review — surface that plainly rather than a 500.
      if (e.code==='23505') return fail(res,409,'That number was registered to another account in the meantime.',requestId);
      throw e;
    } finally { client.release(); }
    audit(user.user_id, recoveryApproveMatch?'phone_recovery.approved':'phone_recovery.rejected', ip, { recoveryRequestId:reqId });
    return send(res,200,{ message: recoveryApproveMatch?'Approved. The account now signs in with the new number.':'Rejected.', requestId });
  }

  return fail(res,404,'Not found',requestId);
}

const server = http.createServer(async (req,res) => {
  // clientIp() specifically exists to resolve to the real caller behind a
  // reverse proxy (Render, or any other PaaS) via X-Forwarded-For — using
  // the raw socket address here instead made every request behind such a
  // proxy look like it came from the same address, silently defeating both
  // the per-IP throttle and the audit log's IP tracking.
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`), requestId=crypto.randomUUID(), ip=clientIp(req);
  res.setHeader('X-Request-Id',requestId);
  try {
    if(req.method==='GET'&&url.pathname==='/healthz')return send(res,200,{ok:true,mode:MODE,databaseConfigured:Boolean(pool),requestId});
    if(req.method==='GET'&&url.pathname==='/api/v1/public/config'){
      const rtp=await getGameRtp();
      // Mirrors the deposits/initiate gate exactly (WINZA_MODE=live AND that
      // provider's own credentials set) so the client only ever sees a
      // provider offered when calling it would actually work.
      const depositProviders = MODE==='live' ? [
        ...(process.env.PAYSTACK_SECRET_KEY ? ['paystack'] : []),
        ...(process.env.OPAY_MERCHANT_ID && process.env.OPAY_PUBLIC_KEY && process.env.OPAY_SECRET_KEY ? ['opay'] : []),
      ] : [];
      return send(res,200,{mode:MODE,realMoneyEnabled:false,rtp,rtpMin:rtpConfig.RTP_MIN,rtpMax:rtpConfig.RTP_MAX,depositProviders,message:'Payments and real-money play are disabled until licensed production services are configured.',requestId});
    }
    if(req.method==='GET'&&url.pathname==='/rtp-config.js')return fs.readFile(path.join(root,'rtp-config.js'),'utf8',(e,file)=>e?fail(res,500,'Unable to load application',requestId):send(res,200,file,'application/javascript; charset=utf-8'));

    // Unauthenticated by design — the provider calls these, not a signed-in
    // player — so the raw body's signature is the only thing that proves a
    // request actually came from that provider. No credentials configured
    // for that provider means 404 rather than a more specific error,
    // matching how the rest of this codebase never confirms whether an
    // unauthenticated feature is configured (see the OTP/password-reset
    // request handlers). Both webhooks share the same shape: verify
    // signature over the raw body, ignore anything that isn't a successful
    // payment, look up the deposit_intents row by reference, verify the
    // amount actually paid matches what was initiated, then credit the
    // wallet exactly once via the idempotent wallet.postTransaction().
    if(req.method==='POST'&&url.pathname==='/api/v1/webhooks/paystack'){
      if(!process.env.PAYSTACK_SECRET_KEY||!pool) return fail(res,404,'Not found',requestId);
      const raw=await rawBody(req);
      if(!paystackLib.verifySignature(raw,req.headers['x-paystack-signature'])){
        audit(null,'webhook.paystack_signature_invalid',ip);
        return fail(res,401,'Invalid signature.',requestId);
      }
      let payload; try{payload=JSON.parse(raw);}catch{return fail(res,400,'Invalid JSON.',requestId);}
      // Paystack sends many event types on this same webhook — anything
      // that isn't a successful charge is acknowledged and ignored, not an
      // error, so Paystack doesn't keep retrying it.
      if(payload.event!=='charge.success') return send(res,200,{received:true,requestId});
      const reference=String(payload.data?.reference||'');
      const amountKobo=Number(payload.data?.amount);
      const { rows }=await pool.query(`SELECT * FROM deposit_intents WHERE reference=$1 AND status='pending'`,[reference]);
      const intent=rows[0];
      // Unknown reference, or one already completed by an earlier delivery
      // of this same webhook (Paystack retries) — ack without acting, which
      // is what makes this idempotent rather than double-crediting a wallet.
      if(!intent) return send(res,200,{received:true,requestId});
      const expectedKobo=Math.round(Number(intent.amount)*100);
      if(amountKobo!==expectedKobo){
        audit(intent.user_id,'webhook.paystack_amount_mismatch',ip,{reference,expectedKobo,amountKobo});
        return send(res,200,{received:true,requestId});
      }
      await wallet.postTransaction(pool,{ walletId:intent.wallet_id, type:'deposit', idempotencyKey:reference, referenceType:'paystack', referenceId:reference, entries:[{balanceType:'cash_available',amount:Number(intent.amount)}] });
      await pool.query(`UPDATE deposit_intents SET status='completed', completed_at=now() WHERE reference=$1`,[reference]);
      audit(intent.user_id,'wallet.deposit_completed',ip,{reference,amount:intent.amount});
      return send(res,200,{received:true,requestId});
    }

    if(req.method==='POST'&&url.pathname==='/api/v1/webhooks/opay'){
      if(!process.env.OPAY_MERCHANT_ID||!process.env.OPAY_PUBLIC_KEY||!process.env.OPAY_SECRET_KEY||!pool) return fail(res,404,'Not found',requestId);
      const raw=await rawBody(req);
      if(!opayLib.verifySignature(raw,req.headers['signature'])){
        audit(null,'webhook.opay_signature_invalid',ip);
        return fail(res,401,'Invalid signature.',requestId);
      }
      let payload; try{payload=JSON.parse(raw);}catch{return fail(res,400,'Invalid JSON.',requestId);}
      // OPay's Cashier webhook nests the actual event under `payload` in some
      // documented examples and sends it flat in others — this environment
      // couldn't confirm which against OPay's own docs site (see the caveat
      // in opay.js), so both shapes are accepted here.
      const eventData = payload.payload || payload;
      if(String(eventData.status||'').toUpperCase()!=='SUCCESS') return send(res,200,{received:true,requestId});
      const reference=String(eventData.reference||'');
      const amountKobo=Number(eventData.amount?.total ?? eventData.amount);
      const { rows }=await pool.query(`SELECT * FROM deposit_intents WHERE reference=$1 AND status='pending'`,[reference]);
      const intent=rows[0];
      if(!intent) return send(res,200,{received:true,requestId});
      const expectedKobo=Math.round(Number(intent.amount)*100);
      if(amountKobo!==expectedKobo){
        audit(intent.user_id,'webhook.opay_amount_mismatch',ip,{reference,expectedKobo,amountKobo});
        return send(res,200,{received:true,requestId});
      }
      await wallet.postTransaction(pool,{ walletId:intent.wallet_id, type:'deposit', idempotencyKey:reference, referenceType:'opay', referenceId:reference, entries:[{balanceType:'cash_available',amount:Number(intent.amount)}] });
      await pool.query(`UPDATE deposit_intents SET status='completed', completed_at=now() WHERE reference=$1`,[reference]);
      audit(intent.user_id,'wallet.deposit_completed',ip,{reference,amount:intent.amount,provider:'opay'});
      return send(res,200,{received:true,requestId});
    }

    if(url.pathname.startsWith('/api/v1/admin/'))return await handleAdmin(req,res,url,requestId,ip);
    if(url.pathname.startsWith('/api/v1/games/'))return await handleGames(req,res,url,requestId,ip);
    if(url.pathname.startsWith('/api/v1/auth/')||url.pathname.startsWith('/api/v1/wallet/')||url.pathname.startsWith('/api/v1/kyc/')||url.pathname.startsWith('/api/v1/account/'))return await handleAuth(req,res,url,requestId,ip);
    if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/winza.html'))return fs.readFile(path.join(root,'winza.html'),'utf8',(e,file)=>e?fail(res,500,'Unable to load application',requestId):send(res,200,file,'text/html; charset=utf-8'));
    if(req.method==='GET'&&(url.pathname==='/admin'||url.pathname==='/admin.html'))return fs.readFile(path.join(root,'admin.html'),'utf8',(e,file)=>e?fail(res,500,'Unable to load application',requestId):send(res,200,file,'text/html; charset=utf-8'));
    return fail(res,404,'Not found',requestId);
  } catch(e) { console.error(`[${requestId}]`,e); return fail(res,500,'Unexpected server error.',requestId); }
});
server.listen(PORT,HOST,()=>console.log(`WINZA ${MODE} server listening at http://${HOST}:${PORT}`));

// Automatic deposit reconciliation: catches deposit_intents rows a webhook
// never resolved (dropped delivery, abandoned checkout) without waiting for
// staff to trigger POST /api/v1/admin/reconcile-deposits by hand. No-op
// without a database. `running` prevents a slow provider response from
// causing overlapping runs to stack up if one takes longer than the interval.
if (pool) {
  const intervalMs = Number(process.env.DEPOSIT_RECONCILE_INTERVAL_MINUTES || 15) * 60_000;
  let running = false;
  const timer = setInterval(async () => {
    if (running) return;
    running = true;
    try {
      const results = await reconciliation.reconcileStuckDeposits(pool, { audit });
      if (results.length) audit(null,'admin.deposit_reconciliation_run',null,{ triggeredBy:'scheduled', count:results.length });
    } catch (e) {
      console.error('Deposit reconciliation run failed:', e);
    } finally {
      running = false;
    }
  }, intervalMs);
  timer.unref();
}
