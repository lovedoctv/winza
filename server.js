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

  // Withdrawal requests never auto-pay out — they just move funds into
  // pending_withdrawal for staff to review (that review UI is a later step).
  // What matters right now: if KYC is required, an unverified user is
  // blocked here before anything is locked, and the backend decides that —
  // not the client.
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
    try {
      const result=await wallet.postTransaction(pool,{ walletId:row.id, type:'withdrawal_request', idempotencyKey:data.idempotencyKey||crypto.randomUUID(), referenceType:'withdrawal', entries:[{balanceType:'cash_available',amount:-amount},{balanceType:'pending_withdrawal',amount}] });
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
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`), requestId=crypto.randomUUID(), ip=req.socket.remoteAddress;
  res.setHeader('X-Request-Id',requestId);
  try {
    if(req.method==='GET'&&url.pathname==='/healthz')return send(res,200,{ok:true,mode:MODE,databaseConfigured:Boolean(pool),requestId});
    if(req.method==='GET'&&url.pathname==='/api/v1/public/config'){const rtp=await getGameRtp();return send(res,200,{mode:MODE,realMoneyEnabled:false,rtp,rtpMin:rtpConfig.RTP_MIN,rtpMax:rtpConfig.RTP_MAX,message:'Payments and real-money play are disabled until licensed production services are configured.',requestId});}
    if(req.method==='GET'&&url.pathname==='/rtp-config.js')return fs.readFile(path.join(root,'rtp-config.js'),'utf8',(e,file)=>e?fail(res,500,'Unable to load application',requestId):send(res,200,file,'application/javascript; charset=utf-8'));
    if(url.pathname.startsWith('/api/v1/admin/'))return await handleAdmin(req,res,url,requestId,ip);
    if(url.pathname.startsWith('/api/v1/auth/')||url.pathname.startsWith('/api/v1/wallet/')||url.pathname.startsWith('/api/v1/kyc/')||url.pathname.startsWith('/api/v1/account/'))return await handleAuth(req,res,url,requestId,ip);
    if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/winza.html'))return fs.readFile(path.join(root,'winza.html'),'utf8',(e,file)=>e?fail(res,500,'Unable to load application',requestId):send(res,200,file,'text/html; charset=utf-8'));
    if(req.method==='GET'&&(url.pathname==='/admin'||url.pathname==='/admin.html'))return fs.readFile(path.join(root,'admin.html'),'utf8',(e,file)=>e?fail(res,500,'Unable to load application',requestId):send(res,200,file,'text/html; charset=utf-8'));
    return fail(res,404,'Not found',requestId);
  } catch(e) { console.error(`[${requestId}]`,e); return fail(res,500,'Unexpected server error.',requestId); }
});
server.listen(PORT,HOST,()=>console.log(`WINZA ${MODE} server listening at http://${HOST}:${PORT}`));
