import { Request, Response, NextFunction } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { ENDPOINT_MAP } from './config.js';

export interface DeliveryRecord {
  timestamp_utc: string;
  req_id?: string;
  settled: boolean;
  tx_hash?: string | null;
  payer_wallet: string;
  amount_usdc: number;
  endpoint: string;
  method: string;
  user_agent: string;
  client_ip: string;
  referer: string;
  request_input: any;
  http_status: number;
  latency_ms: number;
  response_preview: string;
}

const MAX_MEMORY_RECORDS = 200;
const memoryStore: DeliveryRecord[] = [];
const paidMemoryStore: DeliveryRecord[] = [];
const logFilePath = path.join(process.cwd(), 'state', 'deliveries.jsonl');

function decodePayerFromHeader(rawHeader?: string, defaultUsd = 0.008): { payer: string; amount: number } {
  if (!rawHeader) return { payer: 'unpaid_probe', amount: 0.0 };
  try {
    let jsonStr = rawHeader;
    if (!rawHeader.trim().startsWith('{')) {
      jsonStr = Buffer.from(rawHeader, 'base64').toString('utf8');
    }
    const parsed = JSON.parse(jsonStr);
    const auth = parsed.payload?.authorization || parsed.authorization || parsed;
    if (auth && auth.from) {
      const amt = auth.value ? Number(auth.value) / 1e6 : defaultUsd;
      return { payer: String(auth.from).toLowerCase(), amount: amt };
    }
    if (parsed.payer) {
      return { payer: String(parsed.payer).toLowerCase(), amount: Number(parsed.amount || defaultUsd) };
    }
  } catch {}
  return { payer: 'unknown_signer', amount: defaultUsd };
}

export function recordDeliveryMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.path === '/health' || req.path === '/ping' || req.path === '/favicon.ico') {
    return next();
  }

  const startTime = Date.now();
  const spec = ENDPOINT_MAP.get(req.path);
  const defaultUsd = spec ? Number(spec.priceUsd) : 0.008;
  const rawPaymentHdr = (req.headers['payment-signature'] || req.headers['x-payment']) as string | undefined;
  const { payer, amount } = decodePayerFromHeader(rawPaymentHdr, defaultUsd);

  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);
  let capturedBody = '';

  res.json = function (body: any) {
    try {
      capturedBody = typeof body === 'string' ? body : JSON.stringify(body);
    } catch {
      capturedBody = String(body);
    }
    res.locals.responsePreview = '[content withheld]';
    return originalJson(body);
  };

  res.send = function (body: any) {
    if (!capturedBody) {
      try {
        capturedBody = typeof body === 'string' ? body : JSON.stringify(body);
      } catch {
        capturedBody = String(body);
      }
      res.locals.responsePreview = '[content withheld]';
    }
    return originalSend(body);
  };

  res.on('finish', () => {
    const latency_ms = Date.now() - startTime;
    const client_ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || 'unknown';

    let resolvedPayer = payer;
    let resolvedAmount = amount;
    let settled = false;
    let txHash: string | null = null;

    const payRespHeader = res.getHeader('PAYMENT-RESPONSE') || res.getHeader('X-PAYMENT-RESPONSE');
    if (payRespHeader && typeof payRespHeader === 'string') {
      try {
        const parsedResp = JSON.parse(Buffer.from(payRespHeader, 'base64').toString('utf8'));
        if (parsedResp.success === true) {
          settled = true;
          txHash = parsedResp.transaction || parsedResp.txHash || null;
        }
        if (parsedResp.payer) resolvedPayer = String(parsedResp.payer).toLowerCase();
        if (parsedResp.amount) resolvedAmount = Number(parsedResp.amount) / 1e6;
      } catch {}
    }

    const reqInputObj = req.method === 'POST' ? (req.body ?? {}) : (req.query ?? {});
    let reqInputTruncated: any = reqInputObj;
    try {
      const s = JSON.stringify(reqInputObj);
      if (s.length > 500) reqInputTruncated = s.slice(0, 500);
    } catch {}

    const record: DeliveryRecord = {
      timestamp_utc: new Date().toISOString(),
      req_id: (res.getHeader('X-Request-Id') as string) || undefined,
      settled,
      tx_hash: txHash,
      payer_wallet: resolvedPayer,
      amount_usdc: settled && !res.getHeader('Idempotency-Replayed') ? (resolvedAmount || defaultUsd) : 0.0,
      endpoint: req.path,
      method: req.method,
      user_agent: req.get('user-agent') || 'none',
      client_ip: '[withheld]',
      referer: '[withheld]',
      request_input: { withheld: true },
      http_status: res.statusCode,
      latency_ms,
      response_preview: '[withheld]',
    };

    memoryStore.unshift(record);
    if (memoryStore.length > MAX_MEMORY_RECORDS) {
      memoryStore.pop();
    }

    if (settled && !res.getHeader('Idempotency-Replayed')) {
      paidMemoryStore.unshift(record);
      if (paidMemoryStore.length > MAX_MEMORY_RECORDS) {
        paidMemoryStore.pop();
      }
    }

    try {
      fs.mkdirSync(path.dirname(logFilePath),{recursive:true,mode:0o700});
      fs.appendFileSync(logFilePath, JSON.stringify(record) + '\n', 'utf8');
    } catch {}
  });

  next();
}

export function getRecentDeliveries(): DeliveryRecord[] {
  return [...memoryStore];
}

export function getPaidDeliveries(): DeliveryRecord[] {
  return [...paidMemoryStore];
}
