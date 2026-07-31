const crypto = require('node:crypto');
const gameEngine = require('./game-engine');

const ALLOWED_TYPES = new Set(['deposit', 'withdrawal_request', 'withdrawal_reversal', 'stake', 'payout', 'bonus', 'adjustment', 'bet']);
const BALANCE_TYPES = new Set(['cash_available', 'bonus_available', 'locked_balance', 'pending_withdrawal']);
const GAME_IDS = new Set(['wheel', 'lotto']);

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

// Places one wheel/lotto bet: stakes and (if it wins) pays out against a
// single balance, atomically, in one database transaction alongside the
// `bets` audit row — see /api/v1/games/bets in server.js for the validation
// that runs before this is called (auth, stake/multiplier bounds,
// responsible-gambling limits) and game-engine.js for how the outcome
// itself is decided (a cryptographically secure RNG, never Math.random()).
//
// Idempotent by (walletId, clientRequestId): the wallet row is locked with
// SELECT ... FOR UPDATE for the whole transaction, so a genuinely concurrent
// retry with the same clientRequestId blocks until the first attempt commits
// (or rolls back) rather than racing it — by the time it proceeds, the
// pre-insert existence check below finds the already-committed bet and
// returns it unchanged instead of placing a second wager. The UNIQUE
// (wallet_id, client_request_id) constraint on `bets` is a second,
// database-level backstop against the same double-charge, handled in the
// catch block below for the case where two requests somehow do arrive
// concurrently enough to both pass the pre-check.
async function placeBet(pool, { userId, walletId, gameId, stake, multiplier, rtp, clientRequestId, auditSecret, balanceType = 'cash_available', metadata = {} }) {
  if (!GAME_IDS.has(gameId)) throw new Error(`Unknown game id: ${gameId}`);
  if (!BALANCE_TYPES.has(balanceType)) throw new Error(`Unknown balance type: ${balanceType}`);
  if (typeof stake !== 'number' || !Number.isFinite(stake) || stake <= 0) throw new Error('Stake must be a positive number.');
  if (typeof multiplier !== 'number' || !Number.isFinite(multiplier) || multiplier <= 0) throw new Error('Multiplier must be a positive number.');
  if (!clientRequestId) throw new Error('clientRequestId is required.');
  if (!auditSecret) throw new Error('auditSecret is required.');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: walletRows } = await client.query('SELECT * FROM wallets WHERE id=$1 FOR UPDATE', [walletId]);
    const walletRow = walletRows[0];
    if (!walletRow) throw new Error('Wallet not found.');

    const { rows: existingBetRows } = await client.query(
      'SELECT * FROM bets WHERE wallet_id=$1 AND client_request_id=$2',
      [walletId, clientRequestId]
    );
    if (existingBetRows[0]) {
      await client.query('ROLLBACK');
      return { alreadyPlaced: true, bet: existingBetRows[0], wallet: walletRow };
    }

    if (Number(walletRow[balanceType]) < stake) {
      await client.query('ROLLBACK');
      const err = new Error('Insufficient balance.');
      err.code = 'INSUFFICIENT_BALANCE';
      throw err;
    }

    const betId = crypto.randomUUID();
    const outcome = gameEngine.resolveBet({ stake, multiplier, rtp, auditSecret, betId });

    const transactionId = crypto.randomUUID();
    await client.query(
      `INSERT INTO wallet_transactions (id, wallet_id, type, status, idempotency_key, reference_type, reference_id, metadata)
       VALUES ($1,$2,'bet','posted',$3,'bet',$4,$5)`,
      [transactionId, walletId, clientRequestId, betId, metadata]
    );
    await client.query(
      'INSERT INTO wallet_ledger_entries (id, transaction_id, wallet_id, balance_type, amount) VALUES ($1,$2,$3,$4,$5)',
      [crypto.randomUUID(), transactionId, walletId, balanceType, -stake]
    );
    if (outcome.payout > 0) {
      await client.query(
        'INSERT INTO wallet_ledger_entries (id, transaction_id, wallet_id, balance_type, amount) VALUES ($1,$2,$3,$4,$5)',
        [crypto.randomUUID(), transactionId, walletId, balanceType, outcome.payout]
      );
    }

    // balanceType is validated against the fixed BALANCE_TYPES allowlist
    // above, never interpolated from unvalidated input, so this is safe
    // despite not being parameterized (column names can't be bind
    // parameters in Postgres).
    const { rows: updatedWalletRows } = await client.query(
      `UPDATE wallets SET ${balanceType} = ${balanceType} + $1, version = version + 1, updated_at = now() WHERE id = $2 RETURNING *`,
      [outcome.payout - stake, walletId]
    );

    const { rows: betRows } = await client.query(
      `INSERT INTO bets (id, user_id, wallet_id, wallet_transaction_id, game_id, client_request_id, stake, multiplier, rtp_used, chance, random_value, audit_fingerprint, payout, result)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [betId, userId, walletId, transactionId, gameId, clientRequestId, stake, multiplier, rtp, outcome.chance, outcome.randomValue, outcome.auditFingerprint, outcome.payout, outcome.result]
    );

    await client.query('COMMIT');
    return { alreadyPlaced: false, bet: betRows[0], wallet: updatedWalletRows[0] };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    // Two requests with the same clientRequestId arrived close enough
    // together to both pass the pre-insert existence check above (should be
    // prevented already by the wallet row lock serializing them, but the
    // UNIQUE (wallet_id, client_request_id) constraint on `bets` is the
    // database-level backstop for it) — treat it as an idempotent replay
    // rather than an error, same as the normal pre-check path.
    if (e.code === '23505') {
      const { rows: existingBetRows } = await pool.query('SELECT * FROM bets WHERE wallet_id=$1 AND client_request_id=$2', [walletId, clientRequestId]);
      if (existingBetRows[0]) {
        const { rows: currentWalletRows } = await pool.query('SELECT * FROM wallets WHERE id=$1', [walletId]);
        return { alreadyPlaced: true, bet: existingBetRows[0], wallet: currentWalletRows[0] };
      }
    }
    throw e;
  } finally {
    client.release();
  }
}

module.exports = { createWallet, getWalletByUserId, safeWallet, postTransaction, placeBet };
