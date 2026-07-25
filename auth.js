const crypto = require('node:crypto');

const b64url = value => Buffer.from(value).toString('base64url');
const tokenHash = token => crypto.createHash('sha256').update(token).digest('hex');
const normalizeEmail = email => String(email || '').trim().toLowerCase();
const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function validateRegistration({ email, password, displayName }) {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(email))) throw new Error('Enter a valid email address.');
  if (String(password || '').length < 12) throw new Error('Password must be at least 12 characters.');
  if (String(displayName || '').trim().length < 2 || String(displayName).trim().length > 40) throw new Error('Display name must be 2–40 characters.');
}
function scrypt(password, salt) { return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (e, key) => e ? reject(e) : resolve(key))); }
async function hashPassword(password) { const salt=crypto.randomBytes(16).toString('base64url'); return `scrypt$${salt}$${(await scrypt(password,salt)).toString('base64url')}`; }
async function verifyPassword(password, stored) { try { const [,salt,expected]=stored.split('$'); const actual=await scrypt(password,salt); return crypto.timingSafeEqual(actual,Buffer.from(expected,'base64url')); } catch { return false; } }
function sign(payload, secret, ttlSeconds) { const now=Math.floor(Date.now()/1000), body={...payload,iat:now,exp:now+ttlSeconds}; const head=b64url(JSON.stringify({alg:'HS256',typ:'JWT'})), data=`${head}.${b64url(JSON.stringify(body))}`, sig=crypto.createHmac('sha256',secret).update(data).digest('base64url'); return `${data}.${sig}`; }
function verify(token, secret) { const [h,p,s]=String(token||'').split('.'); if(!h||!p||!s) throw new Error('Invalid token'); const expected=crypto.createHmac('sha256',secret).update(`${h}.${p}`).digest(); const actual=Buffer.from(s,'base64url'); if(expected.length!==actual.length||!crypto.timingSafeEqual(expected,actual)) throw new Error('Invalid token'); const body=JSON.parse(Buffer.from(p,'base64url')); if(!body.exp||body.exp<Math.floor(Date.now()/1000)) throw new Error('Expired token'); return body; }
function randomBase32(bytes=20) { const raw=crypto.randomBytes(bytes); let bits=0,val=0,out=''; for(const byte of raw){val=(val<<8)|byte;bits+=8;while(bits>=5){out+=base32Alphabet[(val>>>(bits-5))&31];bits-=5;}} return out; }
function base32Decode(value) { let bits=0,val=0,out=[]; for(const c of String(value).replace(/[=\s-]/g,'').toUpperCase()){const i=base32Alphabet.indexOf(c);if(i<0)throw new Error('Invalid MFA secret');val=(val<<5)|i;bits+=5;if(bits>=8){out.push((val>>>(bits-8))&255);bits-=8;}}return Buffer.from(out); }
function totp(secret, time=Math.floor(Date.now()/1000)) { const counter=Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(time/30))); const hash=crypto.createHmac('sha1',base32Decode(secret)).update(counter).digest(); const offset=hash[hash.length-1]&15; const code=(hash.readUInt32BE(offset)&0x7fffffff)%1000000; return String(code).padStart(6,'0'); }
function validTotp(secret, code) { return [-30,0,30].some(offset=>crypto.timingSafeEqual(Buffer.from(totp(secret,Math.floor(Date.now()/1000)+offset)),Buffer.from(String(code||'').padStart(6,'0')))); }
function encryptionKey() { const key=Buffer.from(process.env.MFA_ENCRYPTION_KEY||'','base64'); if(key.length!==32) throw new Error('MFA_ENCRYPTION_KEY must be a 32-byte base64 value.'); return key; }
function encrypt(plain) { const iv=crypto.randomBytes(12), cipher=crypto.createCipheriv('aes-256-gcm',encryptionKey(),iv), data=Buffer.concat([cipher.update(plain,'utf8'),cipher.final()]); return [iv.toString('base64url'),cipher.getAuthTag().toString('base64url'),data.toString('base64url')].join('.'); }
function decrypt(value) { const [iv,tag,data]=String(value).split('.'), decipher=crypto.createDecipheriv('aes-256-gcm',encryptionKey(),Buffer.from(iv,'base64url'));decipher.setAuthTag(Buffer.from(tag,'base64url'));return Buffer.concat([decipher.update(Buffer.from(data,'base64url')),decipher.final()]).toString('utf8'); }

module.exports = { normalizeEmail, validateRegistration, hashPassword, verifyPassword, sign, verify, tokenHash, randomBase32, totp, validTotp, encrypt, decrypt };
