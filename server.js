const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const auth = require('./auth');
const wallet = require('./wallet');
const otpLib = require('./otp');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const MODE = process.env.WINZA_MODE || 'sandbox';
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
function safeSubmission(row) { return { id:row.id,status:row.status,idType:row.id_type,submittedAt:row.created_at,reviewedAt:row.reviewed_at,rejectionReason:row.rejection_reason }; }
async function getSetting(key, fallback) { const { rows }=await pool.query('SELECT value FROM platform_settings WHERE key=$1',[key]); return rows[0] ? rows[0].value : fallback; }
function ageFromDob(dobStr) { const dob=new Date(dobStr+'T00:00:00Z'); if(Number.isNaN(dob.getTime()))return 0; const now=new Date(); let age=now.getUTCFullYear()-dob.getUTCFullYear(); const m=now.getUTCMonth()-dob.getUTCMonth(); if(m<0||(m===0&&now.getUTCDate()<dob.getUTCDate()))age--; return age; }

async function handleAuth(req,res,url,requestId,ip) {
  if (!ready(res,requestId)) return;
  if (throttled(ip)) return fail(res,429,'Too many attempts. Try again later.',requestId);
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
    // this at all, the code is echoed back here — but ONLY outside live mode.
    // This branch is structurally impossible once WINZA_MODE is 'live'.
    if (!delivery.delivered && MODE !== 'live') payload.devCode=code;
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
    const session=await issueSession(user);
    audit(user.id, isNewAccount?'account.registered_via_otp':'auth.login_succeeded', ip);
    return send(res,200,{ user:safeUser(user), isNewAccount, ...session, requestId });
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
    const kycRequired=await getSetting('kyc_required_for_withdrawal', true);
    if (kycRequired && user.kyc_status!=='verified') return fail(res,403,'KYC verification is required before you can withdraw.',requestId);
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
  if (approveMatch || rejectMatch) {
    const submissionId=(approveMatch||rejectMatch)[1];
    const data=await body(req);
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows }=await client.query(`SELECT * FROM kyc_submissions WHERE id=$1 AND status='pending' FOR UPDATE`,[submissionId]);
      const submission=rows[0];
      if (!submission) { await client.query('ROLLBACK'); return fail(res,404,'No pending submission with that id.',requestId); }
      if (approveMatch) {
        await client.query(`UPDATE kyc_submissions SET status='verified', reviewed_by=$1, reviewed_at=now() WHERE id=$2`,[user.user_id,submissionId]);
        await client.query(`UPDATE users SET kyc_status='verified', kyc_reviewed_by=$1, kyc_reviewed_at=now(), updated_at=now() WHERE id=$2`,[user.user_id,submission.user_id]);
      } else {
        const reason=String(data.reason||'').trim().slice(0,300)||'Not specified';
        await client.query(`UPDATE kyc_submissions SET status='rejected', reviewed_by=$1, reviewed_at=now(), rejection_reason=$2 WHERE id=$3`,[user.user_id,reason,submissionId]);
        await client.query(`UPDATE users SET kyc_status='rejected', kyc_reviewed_by=$1, kyc_reviewed_at=now(), updated_at=now() WHERE id=$2`,[user.user_id,submission.user_id]);
      }
      await client.query('COMMIT');
    } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    audit(user.user_id, approveMatch?'kyc.approved':'kyc.rejected', ip, { submissionId });
    return send(res,200,{ message: approveMatch?'Approved.':'Rejected.', requestId });
  }

  return fail(res,404,'Not found',requestId);
}

const server = http.createServer(async (req,res) => {
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`), requestId=crypto.randomUUID(), ip=req.socket.remoteAddress;
  res.setHeader('X-Request-Id',requestId);
  try {
    if(req.method==='GET'&&url.pathname==='/healthz')return send(res,200,{ok:true,mode:MODE,databaseConfigured:Boolean(pool),requestId});
    if(req.method==='GET'&&url.pathname==='/api/v1/public/config')return send(res,200,{mode:MODE,realMoneyEnabled:false,message:'Payments and real-money play are disabled until licensed production services are configured.',requestId});
    if(url.pathname.startsWith('/api/v1/admin/'))return await handleAdmin(req,res,url,requestId,ip);
    if(url.pathname.startsWith('/api/v1/auth/')||url.pathname.startsWith('/api/v1/wallet/')||url.pathname.startsWith('/api/v1/kyc/'))return await handleAuth(req,res,url,requestId,ip);
    if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/winza.html'))return fs.readFile(path.join(root,'winza.html'),'utf8',(e,file)=>e?fail(res,500,'Unable to load application',requestId):send(res,200,file,'text/html; charset=utf-8'));
    if(req.method==='GET'&&(url.pathname==='/admin'||url.pathname==='/admin.html'))return fs.readFile(path.join(root,'admin.html'),'utf8',(e,file)=>e?fail(res,500,'Unable to load application',requestId):send(res,200,file,'text/html; charset=utf-8'));
    return fail(res,404,'Not found',requestId);
  } catch(e) { console.error(`[${requestId}]`,e); return fail(res,500,'Unexpected server error.',requestId); }
});
server.listen(PORT,HOST,()=>console.log(`WINZA ${MODE} server listening at http://${HOST}:${PORT}`));
