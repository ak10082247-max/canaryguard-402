import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request, RequestHandler, Response } from 'express';
import { ENDPOINT_MAP, DESCRIPTION } from './config.js';
import { ExecutionError, executeEndpoint } from './execution.js';

export const DEFAULT_STRIPE_PROFILE_ID = 'profile_61VnzdDTGkNiFINqdA6VnzdDR1E92xUACS0Twn2zoUBE';
export const DEFAULT_STRIPE_MPP_VERIFY_URL = 'https://agentfuel402.ak10082247.workers.dev/internal/mpp/stripe/verify';
export const STRIPE_MIN_USD_CENTS = 50;

const MAX_AUTHORIZATION_LENGTH = 64 * 1024;
const usedChallengeIds = new Set<string>();
const MAX_USED_CHALLENGES = 10_000;

export function resolveStripeProfileId(env: NodeJS.ProcessEnv = process.env): string {
  const configured = typeof env.STRIPE_PROFILE_ID === 'string' ? env.STRIPE_PROFILE_ID.trim() : '';
  return configured || DEFAULT_STRIPE_PROFILE_ID;
}

export function resolveStripeVerifyUrl(env: NodeJS.ProcessEnv = process.env): string {
  const configured = typeof env.STRIPE_MPP_VERIFY_URL === 'string' ? env.STRIPE_MPP_VERIFY_URL.trim() : '';
  return configured || DEFAULT_STRIPE_MPP_VERIFY_URL;
}

export function computeMppAmountCents(amountMicro?: string | number): number {
  return Math.max(STRIPE_MIN_USD_CENTS, Math.round(Number(amountMicro || 10_000) / 10_000));
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => (item === undefined ? 'null' : canonicalJson(item))).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export function encodeCanonicalRequest(requestObj: Record<string, unknown>): string {
  return Buffer.from(canonicalJson(requestObj), 'utf8').toString('base64url');
}

function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(String(a || ''), 'utf8');
  const bufB = Buffer.from(String(b || ''), 'utf8');
  if (bufA.length === 0 || bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

function rememberUsedChallenge(id: string): void {
  if (!id) return;
  if (usedChallengeIds.size >= MAX_USED_CHALLENGES) {
    const oldest = usedChallengeIds.values().next().value;
    if (oldest) usedChallengeIds.delete(oldest);
  }
  usedChallengeIds.add(id);
}

export function computeChallengeIdSync(
  challenge: {
    realm: string;
    method: string;
    intent: string;
    request: Record<string, unknown> | string;
    expires?: string;
    digest?: string;
    header?: string;
    opaque?: string;
    meta?: Record<string, string>;
  },
  secretKey: string,
): string {
  const encodedReq = typeof challenge.request === 'string'
    ? challenge.request
    : encodeCanonicalRequest(challenge.request || {});
  const values = [
    String(challenge.realm || ''),
    String(challenge.method || ''),
    String(challenge.intent || ''),
    encodedReq,
    challenge.expires ? String(challenge.expires) : '',
    challenge.digest ? String(challenge.digest) : '',
  ];
  if (challenge.header && /^payment-authorization$/i.test(challenge.header)) {
    values.push(challenge.header);
  }
  const encodedOpaque = challenge.opaque
    ? String(challenge.opaque)
    : challenge.meta
      ? encodeCanonicalRequest(challenge.meta)
      : '';
  values.push(encodedOpaque);
  return createHmac('sha256', secretKey).update(values.join('|'), 'utf8').digest('base64url');
}

function authParam(name: string, value: string): string {
  const str = String(value ?? '');
  if (/[\r\n]/.test(str)) {
    throw new Error(`Invalid quoted-string header value for ${name}`);
  }
  const escaped = str
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/[\u0100-\uffff]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
  return `${name}="${escaped}"`;
}

export interface BuiltStripeMppChallenge {
  challenge: {
    id: string;
    realm: string;
    method: 'stripe';
    intent: 'charge';
    request: Record<string, unknown>;
    description?: string;
    expires: string;
  };
  requestEncoded: string;
  headerValue: string;
}

/**
 * Synchronously constructs an mppx@0.21.1-compatible Stripe MPP challenge & WWW-Authenticate header.
 */
export function buildStripeChargeChallengeSync(params: {
  realm: string;
  amountCents?: number;
  description?: string;
  networkId?: string;
  secretKey?: string;
  expiresIso?: string;
}): BuiltStripeMppChallenge {
  const safeAmount = Math.max(STRIPE_MIN_USD_CENTS, Math.round(Number(params.amountCents) || STRIPE_MIN_USD_CENTS));
  const safeExpires = params.expiresIso || new Date(Date.now() + 5 * 60 * 1000).toISOString();
  const safeRealm = String(params.realm || 'canaryguard-402.onrender.com');
  const safeDesc = params.description ? String(params.description).slice(0, 440) : undefined;
  const networkId = String(params.networkId || resolveStripeProfileId());

  const request: Record<string, unknown> = {
    amount: String(safeAmount),
    currency: 'usd',
    ...(safeDesc ? { description: safeDesc } : {}),
    methodDetails: {
      networkId,
      paymentMethodTypes: ['card'],
    },
  };

  const base = {
    realm: safeRealm,
    method: 'stripe' as const,
    intent: 'charge' as const,
    request,
    ...(safeDesc ? { description: safeDesc } : {}),
    expires: safeExpires,
  };

  const secret = typeof params.secretKey === 'string' ? params.secretKey.trim() : '';
  const id = secret.length >= 16
    ? computeChallengeIdSync(base, secret)
    : `dev_${randomBytes(16).toString('base64url')}`;

  const challenge = { id, ...base };
  const requestEncoded = encodeCanonicalRequest(request);
  const parts = [
    authParam('id', challenge.id),
    authParam('realm', challenge.realm),
    authParam('method', challenge.method),
    authParam('intent', challenge.intent),
    authParam('request', requestEncoded),
  ];
  if (challenge.description) parts.push(authParam('description', challenge.description));
  if (challenge.expires) parts.push(authParam('expires', challenge.expires));

  return {
    challenge,
    requestEncoded,
    headerValue: `Payment ${parts.join(', ')}`,
  };
}

export function extractPaymentSchemeHeader(req: Pick<Request, 'header'>): string | null {
  for (const hdrName of ['Payment-Authorization', 'Authorization']) {
    const raw = req.header(hdrName);
    if (!raw || raw.length > MAX_AUTHORIZATION_LENGTH) continue;
    const schemes = raw.split(',').map((s) => s.trim());
    const match = schemes.find((s) => /^Payment\s+\S+/i.test(s));
    if (match) return match;
  }
  return null;
}

export interface NormalizedMppCredential {
  challenge: Record<string, any> & { _rawRequestB64?: string };
  payload: Record<string, any>;
  source?: string;
}

export function normalizeMppCredential(rawCred: any): NormalizedMppCredential {
  if (!rawCred || typeof rawCred !== 'object' || !rawCred.challenge || typeof rawCred.challenge !== 'object') {
    throw new ExecutionError(402, 'invalid_payment_credential', 'Credential missing challenge object');
  }
  const rawChallenge = rawCred.challenge;
  let decodedRequest = rawChallenge.request;
  let rawRequestB64: string | undefined;
  if (typeof rawChallenge.request === 'string') {
    rawRequestB64 = rawChallenge.request;
    try {
      decodedRequest = JSON.parse(Buffer.from(rawChallenge.request, 'base64url').toString('utf8'));
    } catch {
      throw new ExecutionError(402, 'invalid_payment_credential', 'Invalid base64url challenge.request');
    }
  }
  if (!decodedRequest || typeof decodedRequest !== 'object') {
    throw new ExecutionError(402, 'invalid_payment_credential', 'Invalid challenge.request payload');
  }
  const challenge = {
    ...rawChallenge,
    request: decodedRequest,
    ...(rawRequestB64 ? { _rawRequestB64: rawRequestB64 } : {}),
  };
  return {
    challenge,
    payload: rawCred.payload || {},
    ...(rawCred.source ? { source: rawCred.source } : {}),
  };
}

export function parsePaymentCredentialToken(rawHeader: string): NormalizedMppCredential {
  if (!rawHeader || rawHeader.length > MAX_AUTHORIZATION_LENGTH) {
    throw new ExecutionError(402, 'invalid_payment_credential', 'Missing or oversized Payment credential');
  }
  const m = rawHeader.trim().match(/^Payment\s+([A-Za-z0-9_-]+)$/i);
  if (!m?.[1]) {
    throw new ExecutionError(402, 'invalid_payment_credential', 'Malformed Payment credential scheme');
  }
  let parsed: any;
  try {
    parsed = JSON.parse(Buffer.from(m[1], 'base64url').toString('utf8'));
  } catch {
    throw new ExecutionError(402, 'invalid_payment_credential', 'Invalid base64url JSON Payment credential');
  }
  return normalizeMppCredential(parsed);
}

export function verifyStripeChallengePreFlight(
  cred: NormalizedMppCredential,
  secretKey: string | undefined,
  expectedRealms: string[],
  minAmountCents = STRIPE_MIN_USD_CENTS,
): { challenge: Record<string, any>; spt: string; amountCents: number } {
  if (!secretKey || secretKey.trim().length < 16) {
    throw new ExecutionError(503, 'stripe_mpp_unavailable', 'MPP challenge verification secret not configured');
  }
  const { challenge, payload } = cred;
  if (!challenge.id || !challenge.realm) {
    throw new ExecutionError(402, 'invalid_payment_credential', 'Challenge missing id or realm');
  }
  if (challenge.method !== 'stripe' || challenge.intent !== 'charge') {
    throw new ExecutionError(402, 'unsupported_payment_method', 'Expected method=stripe, intent=charge');
  }
  const allowedSet = new Set(expectedRealms.map((r) => String(r).toLowerCase().replace(/\.$/, '')));
  const realmNorm = String(challenge.realm).toLowerCase().replace(/\.$/, '');
  if (!allowedSet.has(realmNorm)) {
    throw new ExecutionError(402, 'challenge_realm_mismatch', `Challenge realm mismatch: ${challenge.realm}`);
  }
  const expMs = Date.parse(String(challenge.expires || ''));
  if (!Number.isFinite(expMs) || expMs <= Date.now()) {
    throw new ExecutionError(402, 'challenge_expired', 'Payment challenge expired');
  }
  if (challenge.header && !/^payment-authorization$/i.test(String(challenge.header))) {
    throw new ExecutionError(402, 'unsupported_credential_header', 'Unsupported challenge header');
  }
  const expectedId = computeChallengeIdSync(
    {
      ...challenge,
      realm: challenge.realm,
      method: challenge.method,
      intent: challenge.intent,
      request: challenge._rawRequestB64 || challenge.request,
    },
    secretKey.trim(),
  );
  if (!constantTimeEqual(String(challenge.id), expectedId)) {
    throw new ExecutionError(402, 'invalid_challenge_signature', 'Invalid Payment challenge signature');
  }
  if (usedChallengeIds.has(String(challenge.id))) {
    throw new ExecutionError(402, 'challenge_replayed', 'Payment challenge already redeemed');
  }

  const amountStr = String(challenge.request?.amount || '');
  if (!/^\d+$/.test(amountStr)) {
    throw new ExecutionError(402, 'invalid_amount', 'Invalid integer amount in Stripe challenge');
  }
  const amountCents = Number(amountStr);
  const currency = String(challenge.request?.currency || '').toLowerCase();
  if (currency !== 'usd' || amountCents < Math.max(STRIPE_MIN_USD_CENTS, minAmountCents)) {
    throw new ExecutionError(402, 'insufficient_amount', `Stripe MPP requires currency='usd' and amount >= ${minAmountCents} cents`);
  }
  const spt = typeof payload?.spt === 'string' ? payload.spt.trim() : '';
  if (!spt || spt.length < 6) {
    throw new ExecutionError(402, 'missing_spt', 'Invalid credential payload: missing or malformed spt');
  }
  const reqExt = challenge.request?.externalId !== undefined ? String(challenge.request.externalId) : undefined;
  const credExt = payload?.externalId !== undefined ? String(payload.externalId) : undefined;
  if (reqExt !== undefined && credExt !== reqExt) {
    throw new ExecutionError(402, 'external_id_mismatch', 'Credential externalId does not match challenge');
  }
  return { challenge, spt, amountCents };
}

export interface StripeMppRelaySettlement {
  ok: true;
  paymentIntentId: string;
  amountCents: number;
  currency: string;
  sku: string;
  tier: string;
  receipt: Record<string, unknown>;
  receiptHeader: string;
  apiKey: string;
  apiKeyExpiresAt: string;
}

/**
 * Signs & dispatches Stripe MPP settlement to AgentFuel402's /internal/mpp/stripe/verify relay
 * using the existing shared KUROX_SIGNING_SECRET (Option A: zero Render secret duplication).
 */
export async function settleViaAgentFuelRelay(params: {
  service: string;
  expectedRealm: string;
  credential: NormalizedMppCredential;
  minAmountCents?: number;
  secretKey: string;
  verifyUrl?: string;
  requestFn?: typeof fetch;
}): Promise<StripeMppRelaySettlement> {
  const {
    service,
    expectedRealm,
    credential,
    minAmountCents = STRIPE_MIN_USD_CENTS,
    secretKey,
    verifyUrl = resolveStripeVerifyUrl(),
    requestFn = fetch,
  } = params;

  const wireCredential = {
    challenge: {
      ...credential.challenge,
      request: credential.challenge._rawRequestB64 || encodeCanonicalRequest(credential.challenge.request),
    },
    payload: credential.payload,
    ...(credential.source ? { source: credential.source } : {}),
  };
  delete (wireCredential.challenge as any)._rawRequestB64;

  const rawBody = JSON.stringify({
    service,
    expectedRealm,
    minAmountCents,
    credential: wireCredential,
  });

  const ts = String(Math.floor(Date.now() / 1000));
  const sig = createHmac('sha256', secretKey.trim())
    .update(`${ts}.${service}.${rawBody}`, 'utf8')
    .digest('base64url');

  const res = await requestFn(verifyUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Kurox-Internal-Timestamp': ts,
      'X-Kurox-Internal-Service': service,
      'X-Kurox-Internal-Signature': sig,
    },
    body: rawBody,
    signal: AbortSignal.timeout(25_000),
  });

  const data: any = await res.json().catch(() => null);
  if (res.status === 402 || (data && data.ok === false && res.status < 500)) {
    throw new ExecutionError(402, 'stripe_mpp_verification_failed', data?.message || 'Stripe MPP verification rejected');
  }
  if (!res.ok || !data?.ok) {
    throw new Error(data?.message || `Stripe MPP relay error HTTP ${res.status}`);
  }
  rememberUsedChallenge(String(credential.challenge.id));
  return data as StripeMppRelaySettlement;
}

export function resolveRequestRealm(req: Pick<Request, 'hostname' | 'get'>, publicUrl?: string): string {
  const rawHost = (req.hostname || req.get('host') || '').split(':')[0]?.trim().toLowerCase();
  if (rawHost) return rawHost;
  if (publicUrl) {
    try {
      return new URL(publicUrl).hostname.toLowerCase();
    } catch {}
  }
  return 'canaryguard-402.onrender.com';
}

export function stripeMppGate(
  publicUrl: string,
  requestFn: typeof fetch = fetch,
  execute: typeof executeEndpoint = executeEndpoint,
  verifyUrlOverride?: string,
): RequestHandler {
  return async (req: Request, res: Response, next) => {
    if ((res.locals as any)?.kuroxBearerAuth) return next();
    const spec = ENDPOINT_MAP.get(req.path);
    const paymentSchemeHdr = extractPaymentSchemeHeader(req);
    if (!spec || !paymentSchemeHdr) return next();

    if (!['POST', 'GET'].includes(req.method)) {
      res.status(405).json({ error: 'paid_method_not_supported', charged: false });
      return;
    }

    const secretKey = process.env.KUROX_SIGNING_SECRET;
    const realm = resolveRequestRealm(req, publicUrl);
    const minCents = computeMppAmountCents(spec.amountMicro);

    let credential: NormalizedMppCredential;
    try {
      credential = parsePaymentCredentialToken(paymentSchemeHdr);
      verifyStripeChallengePreFlight(credential, secretKey, [realm, 'canaryguard-402.onrender.com'], minCents);
    } catch (err) {
      if (err instanceof ExecutionError) {
        res.status(err.status).json({ error: err.code, message: err.message, charged: false });
        return;
      }
      res.status(402).json({ error: 'invalid_payment_credential', message: 'Invalid Payment credential', charged: false });
      return;
    }

    // Acquisition-before-settlement invariant: execute endpoint BEFORE charging Stripe SPT.
    const input: any = req.method === 'POST' ? req.body : { ...req.query };
    if (req.method !== 'POST' && input.strict_mode !== undefined) {
      if (!['true', 'false', '1', '0'].includes(String(input.strict_mode))) {
        res.status(400).json({ error: 'invalid_strict_mode', charged: false });
        return;
      }
      input.strict_mode = ['true', '1'].includes(String(input.strict_mode));
    }

    let result: any;
    try {
      result = await execute(spec.path, input);
    } catch (error) {
      if (error instanceof ExecutionError) {
        res.status(error.status).json({ error: error.code, message: error.message, charged: false });
        return;
      }
      res.status(503).json({ error: 'analysis_unavailable', charged: false });
      return;
    }

    let settled: StripeMppRelaySettlement;
    try {
      res.locals.settlementStarted = true;
      settled = await settleViaAgentFuelRelay({
        service: 'canaryguard-402',
        expectedRealm: realm,
        credential,
        minAmountCents: minCents,
        secretKey: secretKey!,
        verifyUrl: verifyUrlOverride || resolveStripeVerifyUrl(),
        requestFn,
      });
    } catch (err) {
      if (err instanceof ExecutionError) {
        res.status(err.status).json({ error: err.code, message: err.message, charged: false });
        return;
      }
      res.status(503).json({ error: 'payment_verification_unavailable', charged: 'unknown' });
      return;
    }

    res.setHeader('Payment-Receipt', settled.receiptHeader);
    res.setHeader('X-Kurox-Auth', 'stripe-mpp');
    res.setHeader('X-Kurox-Tier', settled.tier || 'mpp_pass');
    res.setHeader('X-Kurox-Api-Key', settled.apiKey);
    res.setHeader('X-Kurox-Api-Key-Expires', settled.apiKeyExpiresAt);
    res.locals.sanitized = true;
    res.json(result);
  };
}

export function buildCanaryMppChallengeDescription(desc?: string): string {
  return `${(desc || DESCRIPTION).slice(0, 340)} ($0.50 USD Stripe MPP pass includes 7d Unified Kurox API Key)`;
}
