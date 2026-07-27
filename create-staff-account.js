// One-off script to provision a staff account (support/risk/admin/owner).
// There is no self-registration or invite flow for privileged roles yet —
// this is the only way to create one, and it should stay that way until an
// owner-audited invite workflow is built.
//
// Usage:
//   DATABASE_URL="..." DATABASE_SSL=true node create-staff-account.js <email> <password> <role>
//
// role is one of: support, risk, admin, owner

const crypto = require('node:crypto');
const { Pool } = require('pg');
const auth = require('./auth');

async function main() {
  const [, , email, password, role] = process.argv;
  if (!email || !password || !role) {
    console.error('Usage: node create-staff-account.js <email> <password> <role: support|risk|admin|owner>');
    process.exit(1);
  }
  if (!['support', 'risk', 'admin', 'owner'].includes(role)) {
    console.error('Role must be one of: support, risk, admin, owner');
    process.exit(1);
  }
  if (String(password).length < 12) {
    console.error('Password must be at least 12 characters.');
    process.exit(1);
  }
  if (!process.env.DATABASE_URL) {
    console.error('Set DATABASE_URL first (the same value your web service uses).');
    process.exit(1);
  }

  const sslMode = (process.env.DATABASE_SSL || '').toLowerCase();
  const ssl = sslMode === '' || sslMode === 'false' ? undefined : { rejectUnauthorized: sslMode === 'strict' };
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl });

  const normalizedEmail = auth.normalizeEmail(email);
  const hash = await auth.hashPassword(password);
  const id = crypto.randomUUID();

  await pool.query(
    `INSERT INTO users (id, email, display_name, password_hash, role)
     VALUES ($1,$2,'Staff',$3,$4)
     ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role, password_hash = EXCLUDED.password_hash, updated_at = now()`,
    [id, normalizedEmail, hash, role]
  );

  console.log(`Staff account ready: ${normalizedEmail} (${role})`);
  await pool.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
