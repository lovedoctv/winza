const crypto = require('node:crypto');

const ALLOWED_TYPES = new Set(['deposit', 'withdrawal_request', 'withdrawal_reversal', 'stake', 'payout', 'bonus', 'adjustment']);
const BALANCE_TYPES = new Set(['cash_available', 'bonus_available', 'locked_balance', 'pending_withdrawal']);

// Called inside the same DB transaction as user registration so every
// account gets exactly one wallet row, or neither row is created at all.
async function createWallet(client, userId, currency = 'NGN') {
  const id = crypto.randomUUID();
  await client.query(
    'INSERT INTO wallets (id, user_id, currency) VALUES ($1,$2,$3)',
    [id, userId, currency]
  );
  return id;
}

async function getWalletByUserId(pool, userId) {
  const { rows } = await pool.query('SELECT * FROM wallets WHERE user_id=$1', [userId]);
  return rows[0] || null;
}

function safeWallet(row) {
  if (!row) return null;
  return {
    cashAvailable: row.cash_available,
    bonusAvailable: row.bonus_available,
    lockedBalance: row.locked_balance,
    pendingWithdrawal: row.pending_withdrawal,
    currency: row.currency,
    updatedAt: row.updated_at,
  };
}

// Internal-only ledger posting helper. This is deliberately NOT wired to any
// HTTP route in server.js — there is no "adjust my balance" endpoint anywhere
// in the API surface. It exists so that future, explicitly-reviewed features
// (a reconciled payment webhook, a settled bet, an admin-audited correction)
// have a single, safe choke point to move money through instead of writing
// ad-hoc UPDATE statements against wallets.
//
// Guarantees:
//   - `type` must be one of the enumerated wallet_transactions types.
//   - Every entry must reference a real balance column and a non-zero amount.
//   - The wallet row is locked (SELECT ... FOR UPDATE) for the duration of
//     the transaction, so concurrent postings serialize instead of racing.
//   - Idempotent: re-posting the same (walletId, idempotencyKey) pair is a
//     no-op that returns the current wallet state rather than double-applying.
//   - Ledger rows are append-only (schema grants should never allow UPDATE or
//     DELETE on wallet_ledger_entries for the application role); the wallets
//     table's own CHECK (... >= 0) constraints reject anything that would
//     drive a balance negative, aborting the whole transaction.
async function postTransaction(pool, { walletId, type, idempotencyKey, referenceType, referenceId, entries, metadata = {} }) {
  if (!ALLOWED_TYPES.has(type)) throw new Error(`Unknown transaction type: ${type}`);
  if (!idempotencyKey) throw new Error('idempotencyKey is required.');
  if (!Array.isArray(entries) || entries.length === 0) throw new Error('At least one ledger entry is required.');
  for (const entry of entries) {
    if (!BALANCE_TYPES.has(entry.balanceType)) throw new Error(`Unknown balance type: ${entry.balanceType}`);
    if (typeof entry.amount !== 'number' || !Number.isFinite(entry.amount) || entry.amount === 0) {
      throw new Error('Ledger entry amount must be a non-zero finite number.');
    }
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: walletRows } = await client.query('SELECT id FROM wallets WHERE id=$1 FOR UPDATE', [walletId]);
    if (!walletRows[0]) throw new Error('Wallet not found.');

    const { rows: txRows } = await client.query(
      `INSERT INTO wallet_transactions (id, wallet_id, type, status, idempotency_key, reference_type, reference_id, metadata)
       VALUES ($1,$2,$3,'posted',$4,$5,$6,$7)
       ON CONFLICT (wallet_id, idempotency_key) DO NOTHING
       RETURNING id`,
      [crypto.randomUUID(), walletId, type, idempotencyKey, referenceType || null, referenceId || null, metadata]
    );

    if (!txRows[0]) {
      await client.query('ROLLBACK');
      const { rows: current } = await pool.query('SELECT * FROM wallets WHERE id=$1', [walletId]);
      return { alreadyPosted: true, wallet: current[0] };
    }

    const transactionId = txRows[0].id;
    const deltas = { cash_available: 0, bonus_available: 0, locked_balance: 0, pending_withdrawal: 0 };
    for (const entry of entries) {
      await client.query(
        'INSERT INTO wallet_ledger_entries (id, transaction_id, wallet_id, balance_type, amount) VALUES ($1,$2,$3,$4,$5)',
        [crypto.randomUUID(), transactionId, walletId, entry.balanceType, entry.amount]
      );
      deltas[entry.balanceType] += entry.amount;
    }

    const { rows: updated } = await client.query(
      `UPDATE wallets SET
         cash_available = cash_available + $1,
         bonus_available = bonus_available + $2,
         locked_balance = locked_balance + $3,
         pending_withdrawal = pending_withdrawal + $4,
         version = version + 1,
         updated_at = now()
       WHERE id = $5
       RETURNING *`,
      [deltas.cash_available, deltas.bonus_available, deltas.locked_balance, deltas.pending_withdrawal, walletId]
    );

    await client.query('COMMIT');
    return { alreadyPosted: false, wallet: updated[0] };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

module.exports = { createWallet, getWalletByUserId, safeWallet, postTransaction };
