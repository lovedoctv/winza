const paystackLib = require('./paystack');
const opayLib = require('./opay');
const wallet = require('./wallet');

// How long a deposit sits in `pending` before this job will actively poll
// the provider for it — kept well above normal checkout latency (seconds)
// so this never races a webhook that's simply a little slow, and only picks
// up deposits a webhook plausibly should have resolved by now.
const RECONCILE_AFTER_MS = Number(process.env.DEPOSIT_RECONCILE_AFTER_MINUTES || 30) * 60_000;

// How long a `pending` deposit can go without the provider ever reporting
// success before it's written off as abandoned (payer closed the checkout,
// never completed payment) rather than polled forever.
const ABANDON_AFTER_MS = Number(process.env.DEPOSIT_ABANDON_AFTER_HOURS || 24) * 60 * 60_000;

const MAX_PER_RUN = 100;

async function checkProvider(intent) {
  if (intent.provider === 'paystack') {
    const result = await paystackLib.verifyTransaction(intent.reference);
    return { succeeded: result.status === 'success', definitelyFailed: ['failed', 'abandoned', 'reversed'].includes(result.status), amountKobo: result.amountKobo, rawStatus: result.status };
  }
  const result = await opayLib.queryTransactionStatus(intent.reference);
  return { succeeded: result.status === 'SUCCESS', definitelyFailed: ['FAIL', 'CLOSE'].includes(result.status), amountKobo: result.amountKobo, rawStatus: result.status };
}

// Resolves a single stuck deposit_intents row by asking its provider what
// actually happened, instead of leaving it `pending` forever because a
// webhook was dropped. Shares the exact same crediting path as the webhook
// handlers in server.js (wallet.postTransaction keyed by the deposit's
// reference), so if a delayed webhook and this job both resolve the same
// deposit, only the first to arrive actually credits the wallet — the
// second is a no-op.
async function reconcileOne(pool, intent, audit) {
  let check;
  try {
    check = await checkProvider(intent);
  } catch (e) {
    audit(intent.user_id, 'wallet.deposit_reconcile_check_failed', null, { reference: intent.reference, provider: intent.provider, error: e.message });
    return { reference: intent.reference, action: 'check_failed' };
  }

  if (check.succeeded) {
    const expectedKobo = Math.round(Number(intent.amount) * 100);
    if (check.amountKobo !== expectedKobo) {
      audit(intent.user_id, 'wallet.deposit_reconcile_amount_mismatch', null, { reference: intent.reference, provider: intent.provider, expectedKobo, amountKobo: check.amountKobo });
      return { reference: intent.reference, action: 'amount_mismatch' };
    }
    await wallet.postTransaction(pool, {
      walletId: intent.wallet_id, type: 'deposit', idempotencyKey: intent.reference,
      referenceType: intent.provider, referenceId: intent.reference,
      entries: [{ balanceType: 'cash_available', amount: Number(intent.amount) }],
    });
    await pool.query(`UPDATE deposit_intents SET status='completed', completed_at=now() WHERE reference=$1 AND status='pending'`, [intent.reference]);
    audit(intent.user_id, 'wallet.deposit_completed', null, { reference: intent.reference, amount: intent.amount, provider: intent.provider, source: 'reconciliation' });
    return { reference: intent.reference, action: 'completed' };
  }

  const ageMs = Date.now() - new Date(intent.created_at).getTime();
  if (check.definitelyFailed || ageMs > ABANDON_AFTER_MS) {
    await pool.query(`UPDATE deposit_intents SET status='failed' WHERE reference=$1 AND status='pending'`, [intent.reference]);
    audit(intent.user_id, 'wallet.deposit_reconciled_failed', null, { reference: intent.reference, provider: intent.provider, providerStatus: check.rawStatus, abandoned: !check.definitelyFailed });
    return { reference: intent.reference, action: 'failed' };
  }

  return { reference: intent.reference, action: 'still_pending' };
}

// Finds deposit_intents rows stuck in `pending` — an abandoned checkout, or
// a webhook Paystack/OPay attempted but this server never received — and
// resolves each one by polling the provider directly. Errors on one row
// never abort the batch; each row's own try/catch (in reconcileOne) reports
// it and moves on.
async function reconcileStuckDeposits(pool, { audit = () => {} } = {}) {
  const cutoff = new Date(Date.now() - RECONCILE_AFTER_MS);
  const { rows } = await pool.query(
    `SELECT * FROM deposit_intents WHERE status='pending' AND created_at < $1 ORDER BY created_at ASC LIMIT $2`,
    [cutoff, MAX_PER_RUN]
  );
  const results = [];
  for (const intent of rows) {
    results.push(await reconcileOne(pool, intent, audit));
  }
  return results;
}

module.exports = { reconcileStuckDeposits };
