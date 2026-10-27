import { createHash } from 'node:crypto';
import type { RequestHandler } from 'express';
import { decodePaymentResponseHeader } from '@x402/core/http';
import { ENDPOINT_MAP } from './config.js';
import { configuredJournal, type PaymentJournal } from './payment_journal.js';
import { verifyPaymentOwnership, canonicalPaymentIdentity } from './payment_auth.js';

export function fingerprint(value: unknown) {
  const canonical = JSON.stringify(value, (_key, item: unknown) => {
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      return Object.fromEntries(Object.entries(item).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0));
    }
    return item;
  });
  return createHash('sha256').update(canonical ?? 'undefined').digest('hex');
}

export function paymentIdentity(value: any) {
  return canonicalPaymentIdentity(value) || fingerprint(value);
}

type Receipt = { bodyHash: string; body: Buffer; headers: Record<string, string>; expires: number };

// Same authorization + different content is a conflict. Receipt cache is bounded,
// volatile and never authorizes a fresh payment; it only repeats completed output.
export function receiptRetries(limit = 256, maxBytes = 8 * 1024 * 1024, inFlightTimeoutMs = 4 * 60 * 1000, journal: PaymentJournal | undefined = configuredJournal()): RequestHandler {
  const receipts = new Map<string, Receipt>();
  const inFlight = new Map<string, { bodyHash: string; done: Promise<void> }>();
  let bytes = 0;
  const remove = (key: string) => { const row = receipts.get(key); if (row) bytes -= row.body.length; receipts.delete(key); };
  return async (req, res, next) => {
    const header = req.get('PAYMENT-SIGNATURE') || req.get('X-PAYMENT');
    if (!header || !['GET','POST','HEAD'].includes(req.method) || !ENDPOINT_MAP.has(req.path)) return next();
    let payload: unknown;
    try { payload = JSON.parse(header.trim().startsWith('{') ? header : Buffer.from(header, 'base64').toString('utf8')); } catch { return next(); }
    if (!await verifyPaymentOwnership(payload)) { res.status(402).json({ error: 'invalid_payment_ownership' }); return; }
    const key = paymentIdentity(payload);
    const bodyHash = fingerprint({ method: req.method, path: req.path, input: req.method === 'POST' ? req.body : req.query });
    const previous = inFlight.get(key);
    if (previous) {
      if (previous.bodyHash !== bodyHash) { res.status(409).json({ error: 'payment_request_conflict' }); return; }
      await previous.done;
    }
    const cached = receipts.get(key);
    if (cached && cached.expires <= Date.now()) remove(key);
    else if (cached) {
      if (cached.bodyHash !== bodyHash) { res.status(409).json({ error: 'payment_request_conflict' }); return; }
      receipts.delete(key); receipts.set(key, cached);
      res.set(cached.headers).set('Idempotency-Replayed', 'true').status(200).end(cached.body); return;
    }
    // An unsuccessful concurrent attempt must not be independently settled again.
    if (previous) { res.status(503).json({ error: 'retry_original_payment_later' }); return; }
    if (journal) {
      try {
        const saved = journal.get(key);
        if (saved) {
          if (saved.request_hash !== bodyHash) { res.status(409).json({ error: 'payment_request_conflict' }); return; }
          if (saved.phase !== 'completed' || !saved.result) { res.status(503).json({ error: 'payment_reconciliation_required', retry: 'Do not authorize another payment' }); return; }
          const result = JSON.parse(saved.result);
          res.set(result.headers).set('Idempotency-Replayed','true').status(result.status).end(Buffer.from(result.body,'base64')); return;
        }
      } catch { res.status(503).json({ error: 'payment_journal_unavailable' }); return; }
    }
    res.locals.paymentJournal = journal;
    res.locals.paymentOperationId = key;
    res.locals.claimPaymentOperation = () => {
      if (journal?.claim(key,bodyHash)) throw new Error('payment_operation_already_claimed');
      res.locals.paymentOperationClaimed = true;
    };
    if (inFlight.size >= 64) { res.status(429).json({ error: 'payment_capacity_exceeded' }); return; }
    let complete!: () => void;
    const done = new Promise<void>(resolve => { complete = resolve; });
    const row = { bodyHash, done };
    inFlight.set(key, row);
    const chunks: Buffer[] = [];
    let length = 0;
    const remember = (chunk: unknown, encoding?: unknown) => {
      if (chunk == null || typeof chunk === 'function') return;
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof encoding === 'string' ? encoding as BufferEncoding : 'utf8');
      length += buffer.length; if (length <= 1024 * 1024) chunks.push(buffer);
    };
    const write = res.write.bind(res); const end = res.end.bind(res);
    let finished = false;
    // Closing the client connection does not cancel a facilitator request. Keep
    // the authorization locked until the payment middleware flushes its settled
    // response. The bound exceeds verify + settle + the SDK's pending retry.
    let cleanup: NodeJS.Timeout;
    const release = () => {
      clearTimeout(cleanup);
      if (inFlight.get(key) === row) inFlight.delete(key);
      complete();
    };
    const finish = () => {
      if (finished) return; finished = true;
      const responseHeader = res.getHeader('PAYMENT-RESPONSE');
      let settled = false;
      try { settled = typeof responseHeader === 'string' && decodePaymentResponseHeader(responseHeader).success === true; } catch { /* An invalid receipt is never replayable. */ }
      if (res.statusCode === 200 && settled && length <= 1024 * 1024) {
        const headers: Record<string, string> = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
        for (const name of ['PAYMENT-RESPONSE', 'EXTENSION-RESPONSES']) { const value = res.getHeader(name); if (typeof value === 'string') headers[name] = value; }
        const body = Buffer.concat(chunks);
        remove(key);
        receipts.set(key, { bodyHash, headers, body, expires: Date.now() + 10 * 60 * 1000 }); bytes += body.length;
        while (receipts.size > limit || bytes > maxBytes) remove(receipts.keys().next().value!);
      }
      if (journal && res.locals.paymentOperationClaimed && res.statusCode === 200 && settled && length <= 1024*1024) {
        const headers: Record<string,string> = { 'Content-Type':'application/json','Cache-Control':'no-store' };
        for (const name of ['PAYMENT-RESPONSE','EXTENSION-RESPONSES']) { const value=res.getHeader(name); if(typeof value==='string') headers[name]=value; }
        try { journal.complete(key,{status:res.statusCode,headers,body:Buffer.concat(chunks).toString('base64'),prepared:res.locals.acquiredResult}); }
        catch { /* The pending durable claim remains locked; never authorize a replacement charge. */ }
      }
      release();
    };
    cleanup = setTimeout(release, inFlightTimeoutMs); cleanup.unref();
    res.write = ((chunk: unknown, ...args: unknown[]) => { remember(chunk, args[0]); return (write as Function)(chunk, ...args); }) as typeof res.write;
    res.end = ((chunk?: unknown, ...args: unknown[]) => {
      remember(chunk, args[0]);
      try { return (end as Function)(chunk, ...args); } finally { finish(); }
    }) as typeof res.end;
    res.once('finish', finish);
    res.once('close', () => { if (res.writableFinished) finish(); });
    next();
  };
}
