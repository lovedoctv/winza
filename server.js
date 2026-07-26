const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const auth = require('./auth');
const wallet = require('./wallet');

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
async function body(req) { return new Promise((resolve,reject)=>{let raw='';req.on('data',c=>{raw+=c;if(raw.length>16_384)req.destroy();});req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{});}catch{reject(new Error('Invalid JSON body'));}});req.on('error',reject);}); }
function ready(res, requestId) { if (!pool || !JWT_SECRET || JWT_SECRET.length < 32) { fail(res,503,'Authentication service is not configured.',requestId); return false; } return true; }
async function sessionFrom(req) { const token=(req.headers.authorization||'').replace(/^Bearer\s+/i,''); const payload=auth.verify(token,JWT_SECRET); const { rows }=await pool.query('SELECT s.id,u.id AS user_id,u.email,u.display_name,u.role,u.is_active FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.expires_at>now() AND s.revoked_at IS NULL',[payload.sid]); if(!rows[0]||!rows[0].is_active)throw new Error('Unauthorized'); return rows[0]; }
function issueSession(user) { const sid=crypto.randomUUID(), expires=new Date(Date.now()+8*60*60_000); return pool.query('INSERT INTO auth_sessions (id,user_id,expires_at) VALUES ($1,$2,$3)',[sid,user.id,expires]).then(()=>({accessToken:auth.sign({sub:user.id,sid,role:user.role},JWT_SECRET,8*60*60),expiresAt:expires.toISOString()})); }
function safeUser(row) { return { id:row.id||row.user_id,email:row.email,displayName:row.display_name,role:row.role,mfaEnabled:Boolean(row.mfa_enabled_at) }; }

async function handleAuth(req,res,url,requestId,ip) {
  if (!ready(res,requestId)) return;
  if (throttled(ip)) return fail(res,429,'Too many attempts. Try again later.',requestId);
  const data=await body(req);
  if (req.method==='POST' && url.pathname==='/api/v1/auth/register') {
    auth.validateRegistration(data); const email=auth.normalizeEmail(data.email); const id=crypto.randomUUID();
    const client=await pool.connect();
    try {
      const hash=await auth.hashPassword(data.password);
      await client.query('BEGIN');
      const { rows }=await client.query('INSERT INTO users (id,email,display_name,password_hash) VALUES ($1,$2,$3,$4) RETURNING id,email,display_name,role,mfa_enabled_at',[id,email,data.displayName.trim(),hash]);
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
  if (req.method==='POST' && url.pathname==='/api/v1/auth/logout') { await pool.query('UPDATE auth_sessions SET revoked_at=now() WHERE id=$1',[user.id]);audit(user.user_id,'auth.logout',ip);return send(res,204,''); }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/mfa/enroll') { const secret=auth.randomBase32(); await pool.query('UPDATE users SET mfa_pending_secret_encrypted=$1 WHERE id=$2',[auth.encrypt(secret),user.user_id]);return send(res,200,{secret,otpauthUrl:`otpauth://totp/WINZA:${encodeURIComponent(user.email)}?secret=${secret}&issuer=WINZA&algorithm=SHA1&digits=6&period=30`,requestId}); }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/mfa/confirm') { const {rows}=await pool.query('SELECT mfa_pending_secret_encrypted FROM users WHERE id=$1',[user.user_id]);if(!rows[0]?.mfa_pending_secret_encrypted||!auth.validTotp(auth.decrypt(rows[0].mfa_pending_secret_encrypted),data.code))return fail(res,400,'Invalid authenticator code.',requestId);await pool.query('UPDATE users SET mfa_secret_encrypted=mfa_pending_secret_encrypted,mfa_pending_secret_encrypted=NULL,mfa_enabled_at=now() WHERE id=$1',[user.user_id]);audit(user.user_id,'auth.mfa_enabled',ip);return send(res,200,{message:'MFA enabled.',requestId}); }
  if (req.method==='POST' && url.pathname==='/api/v1/auth/mfa/disable') { if(!data.code)return fail(res,400,'Authenticator code is required.',requestId);const {rows}=await pool.query('SELECT mfa_secret_encrypted FROM users WHERE id=$1',[user.user_id]);if(!rows[0]?.mfa_secret_encrypted||!auth.validTotp(auth.decrypt(rows[0].mfa_secret_encrypted),data.code))return fail(res,400,'Invalid authenticator code.',requestId);await pool.query('UPDATE users SET mfa_secret_encrypted=NULL,mfa_enabled_at=NULL WHERE id=$1',[user.user_id]);audit(user.user_id,'auth.mfa_disabled',ip);return send(res,200,{message:'MFA disabled.',requestId}); }
  return fail(res,404,'Not found',requestId);
}

const server = http.createServer(async (req,res) => {
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`), requestId=crypto.randomUUID(), ip=req.socket.remoteAddress;
  res.setHeader('X-Request-Id',requestId);
  try {
    if(req.method==='GET'&&url.pathname==='/healthz')return send(res,200,{ok:true,mode:MODE,databaseConfigured:Boolean(pool),requestId});
    if(req.method==='GET'&&url.pathname==='/api/v1/public/config')return send(res,200,{mode:MODE,realMoneyEnabled:false,message:'Payments and real-money play are disabled until licensed production services are configured.',requestId});
    if(url.pathname.startsWith('/api/v1/auth/')||url.pathname.startsWith('/api/v1/wallet/'))return await handleAuth(req,res,url,requestId,ip);
    if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/winza.html'))return fs.readFile(path.join(root,'winza.html'),(e,file)=>e?fail(res,500,'Unable to load application',requestId):send(res,200,file,'text/html; charset=utf-8'));
    return fail(res,404,'Not found',requestId);
  } catch(e) { console.error(`[${requestId}]`,e); return fail(res,500,'Unexpected server error.',requestId); }
});
server.listen(PORT,HOST,()=>console.log(`WINZA ${MODE} server listening at http://${HOST}:${PORT}`));
