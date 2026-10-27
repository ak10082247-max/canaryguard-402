import type { RequestHandler } from 'express';
import { SOLANA_NETWORK, SOLANA_USDC_MINT, SOLANA_RECIPIENT, SOLANA_FEE_PAYER, PAYAI_FACILITATOR, ENDPOINT_MAP } from './config.js';
import { ExecutionError, executeEndpoint } from './execution.js';

export function solanaPaymentGate(publicUrl: string, request: typeof fetch = fetch): RequestHandler {
  return async (req, res, next) => {
    const spec = ENDPOINT_MAP.get(req.path);
    const header = req.get('PAYMENT-SIGNATURE') || req.get('X-PAYMENT');
    if (!spec || !header) return next();
    let payment: any;
    try { payment = JSON.parse(header.trim().startsWith('{') ? header : Buffer.from(header, 'base64').toString('utf8')); }
    catch { return next(); }
    if (!String(payment.accepted?.network || '').startsWith('solana')) return next();
    if (!['POST', 'GET'].includes(req.method)) { res.status(405).json({ error: 'paid_method_not_supported' }); return; }
    const requirements = { scheme: 'exact', network: SOLANA_NETWORK, amount: spec.amountMicro, asset: SOLANA_USDC_MINT,
      payTo: SOLANA_RECIPIENT, maxTimeoutSeconds: 300, extra: { name: 'USD Coin (Solana)', version: '2', feePayer: SOLANA_FEE_PAYER } };
    const resource = publicUrl + spec.path;
    if (payment.x402Version !== 2 || !payment.accepted || ['scheme','network','amount','asset','payTo'].some(key => payment.accepted[key] !== (requirements as any)[key]) || payment.resource?.url !== resource || payment.accepted.maxTimeoutSeconds !== requirements.maxTimeoutSeconds || Object.entries(requirements.extra).some(([key,value])=>payment.accepted.extra?.[key]!==value) || typeof payment.payload?.transaction !== 'string') {
      res.status(402).json({ error: 'payment_requirements_mismatch' }); return;
    }
    const body = JSON.stringify({ x402Version: 2, paymentPayload: payment, paymentRequirements: requirements });
    try {
      const verification = await request(PAYAI_FACILITATOR + '/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, signal: AbortSignal.timeout(15000) });
      const verified: any = await verification.json();
      if (!verification.ok || verified.isValid !== true) { res.status(402).json({ error: 'invalid_payment' }); return; }
      res.locals.claimPaymentOperation?.();
      // Acquire and buffer the actual requested result before authorizing a charge.
      const input: any = req.method === 'POST' ? req.body : { ...req.query };
      if (req.method === 'GET' && input.strict_mode !== undefined) {
        if (!['true','false','1','0'].includes(input.strict_mode)) throw new ExecutionError(400, 'invalid_strict_mode', 'strict_mode must be true, false, 1 or 0');
        input.strict_mode = ['true','1'].includes(input.strict_mode);
      }
      const result = await executeEndpoint(spec.path, input);
      res.locals.acquiredResult = result;
      res.locals.paymentJournal?.prepare(res.locals.paymentOperationId,result);
      res.locals.settlementStarted = true;
      const settlement = await request(PAYAI_FACILITATOR + '/settle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, signal: AbortSignal.timeout(30000) });
      const settled: any = await settlement.json();
      if (!settlement.ok || settled.success !== true || settled.network !== SOLANA_NETWORK || !/^[1-9A-HJ-NP-Za-km-z]{80,90}$/.test(settled.transaction || '') || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(settled.payer || '') || (verified.payer && settled.payer !== verified.payer)) {
        res.status(503).json({ error: 'settlement_unconfirmed', retry: 'Reuse this authorization for recovery; do not submit another payment' }); return;
      }
      const receipt = { success: true, payer: settled.payer, transaction: settled.transaction, network: SOLANA_NETWORK, amount: spec.amountMicro, resource: { url: resource } };
      res.setHeader('PAYMENT-RESPONSE', Buffer.from(JSON.stringify(receipt)).toString('base64'));
      res.locals.sanitized = true;
      res.json(result);
    } catch (error) {
      if (error instanceof ExecutionError && !res.locals.settlementStarted) { res.status(error.status).json({ error: error.code, message: error.message, charged: false }); return; }
      res.status(503).json({ error: res.locals.settlementStarted ? 'settlement_unconfirmed' : 'payment_verification_unavailable', charged: res.locals.settlementStarted ? 'unknown' : false });
    }
  };
}
