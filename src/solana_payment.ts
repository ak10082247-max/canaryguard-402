import type { RequestHandler } from 'express';
import { SOLANA_NETWORK, SOLANA_USDC_MINT, SOLANA_RECIPIENT, SOLANA_FEE_PAYER, PAYAI_FACILITATOR, ENDPOINT_MAP } from './config.js';
import { ExecutionError, executeEndpoint } from './execution.js';

export function solanaPaymentRequirements(amount: string) {
  return { scheme: 'exact', network: SOLANA_NETWORK, amount, asset: SOLANA_USDC_MINT,
    payTo: SOLANA_RECIPIENT, maxTimeoutSeconds: 300, extra: { name: 'USD Coin (Solana)', version: '2', feePayer: SOLANA_FEE_PAYER } };
}

/** Shared HTTP/MCP transaction lifecycle: verify, acquire, then settle. The
 * caller owns idempotency and persists the prepared result before settlement. */
export async function executeSolanaPurchase<T>(payment: any, resource: string, amount: string, acquire: () => Promise<T>,
  hooks: { verified?: () => void; acquired?: (result: T) => void; settling?: () => void } = {}, request: typeof fetch = fetch) {
  const requirements = solanaPaymentRequirements(amount);
  if (payment?.x402Version !== 2 || !payment.accepted ||
      ['scheme','network','amount','asset','payTo','maxTimeoutSeconds'].some(key => payment.accepted[key] !== (requirements as any)[key]) ||
      payment.resource?.url !== resource || Object.entries(requirements.extra).some(([key,value]) => payment.accepted.extra?.[key] !== value) ||
      typeof payment.payload?.transaction !== 'string') throw new ExecutionError(402, 'payment_requirements_mismatch', 'Payment does not match this resource');
  const body = JSON.stringify({ x402Version: 2, paymentPayload: payment, paymentRequirements: requirements });
  const verification = await request(PAYAI_FACILITATOR + '/verify', { method:'POST', headers:{'Content-Type':'application/json'}, body, signal:AbortSignal.timeout(15000) });
  const verified: any = await verification.json();
  if (!verification.ok || verified.isValid !== true) throw new ExecutionError(402, 'invalid_payment', 'Payment verification failed');
  hooks.verified?.();
  const result = await acquire();
  hooks.acquired?.(result);
  hooks.settling?.();
  const settlement = await request(PAYAI_FACILITATOR + '/settle', { method:'POST', headers:{'Content-Type':'application/json'}, body, signal:AbortSignal.timeout(30000) });
  const settled: any = await settlement.json();
  if (!settlement.ok || settled.success !== true || settled.network !== SOLANA_NETWORK ||
      !/^[1-9A-HJ-NP-Za-km-z]{80,90}$/.test(settled.transaction || '') || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(settled.payer || '') ||
      (verified.payer && settled.payer !== verified.payer)) throw Error('settlement_unconfirmed');
  return { result, receipt: { success:true, payer:settled.payer, transaction:settled.transaction,
    network:SOLANA_NETWORK, amount, resource:{url:resource} } };
}

export function solanaPaymentGate(publicUrl: string, request: typeof fetch = fetch, execute: typeof executeEndpoint = executeEndpoint): RequestHandler {
  return async (req, res, next) => {
    const spec = ENDPOINT_MAP.get(req.path);
    const header = req.get('PAYMENT-SIGNATURE') || req.get('X-PAYMENT');
    if (!spec || !header) return next();
    let payment: any;
    try { payment = JSON.parse(header.trim().startsWith('{') ? header : Buffer.from(header, 'base64').toString('utf8')); }
    catch { return next(); }
    if (!String(payment.accepted?.network || '').startsWith('solana')) return next();
    if (!['POST', 'GET'].includes(req.method)) { res.status(405).json({ error: 'paid_method_not_supported' }); return; }
    const resource = publicUrl + spec.path;
    try {
      const { result, receipt } = await executeSolanaPurchase(payment, resource, spec.amountMicro, async () => {
        const input: any = req.method === 'POST' ? req.body : { ...req.query };
        if (req.method === 'GET' && input.strict_mode !== undefined) {
          if (!['true','false','1','0'].includes(input.strict_mode)) throw new ExecutionError(400, 'invalid_strict_mode', 'strict_mode must be true, false, 1 or 0');
          input.strict_mode = ['true','1'].includes(input.strict_mode);
        }
        return execute(spec.path,input);
      }, {
        verified: () => res.locals.claimPaymentOperation?.(),
        acquired: result => { res.locals.acquiredResult = result; res.locals.paymentJournal?.prepare(res.locals.paymentOperationId,result); },
        settling: () => { res.locals.settlementStarted = true; },
      }, request);
      res.setHeader('PAYMENT-RESPONSE', Buffer.from(JSON.stringify(receipt)).toString('base64'));
      res.locals.sanitized = true;
      res.json(result);
    } catch (error) {
      if (error instanceof ExecutionError && !res.locals.settlementStarted) {
        if(res.locals.paymentOperationClaimed) res.locals.paymentJournal?.releaseUnacquired(res.locals.paymentOperationId);
        res.status(error.status).json({ error: error.code, message: error.message, charged: false }); return;
      }
      res.status(503).json({ error: res.locals.settlementStarted ? 'settlement_unconfirmed' : 'payment_verification_unavailable', charged: res.locals.settlementStarted ? 'unknown' : false });
    }
  };
}
