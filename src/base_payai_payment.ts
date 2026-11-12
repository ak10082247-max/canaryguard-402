import type { NextFunction, Request, Response } from 'express';
import { getAddress } from 'viem';
import {
  ASSET,
  ENDPOINT_MAP,
  type EndpointSpec,
  inputJsonSchema,
  isRetiredBaseRecipient,
  NETWORK,
  PAYAI_FACILITATOR,
  RECIPIENT,
} from './config.js';
import { executeEndpoint, ExecutionError } from './execution.js';
import { verifyPaymentOwnership } from './payment_auth.js';

export function basePaymentRequirements(amount = '10000', payTo: string = RECIPIENT) {
  return {
    scheme: 'exact' as const,
    network: NETWORK,
    amount,
    asset: ASSET,
    payTo: getAddress(payTo),
    maxTimeoutSeconds: 300,
    extra: { name: 'USD Coin', version: '2' },
  };
}

export function buildBaseBazaarExtension(spec: EndpointSpec) {
  return {
    info: {
      input: {
        type: 'http',
        method: 'POST',
        bodyType: 'json',
        body: spec.inputExample,
      },
      output: {
        type: 'json',
        example: spec.outputExample,
      },
    },
    schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: {
        input: {
          type: 'object',
          properties: {
            type: { type: 'string', const: 'http' },
            method: { type: 'string', enum: ['POST', 'GET'] },
            bodyType: { type: 'string', enum: ['json'] },
            body: spec.inputSchema || inputJsonSchema,
          },
          required: ['type', 'method', 'bodyType', 'body'],
          additionalProperties: false,
        },
        output: {
          type: 'object',
          properties: {
            type: { type: 'string' },
            example: { type: 'object', additionalProperties: true },
          },
          required: ['type'],
        },
      },
      required: ['input'],
    },
  };
}

export function shouldUsePayaiForBase(req: Request, payment: any, env: NodeJS.ProcessEnv = process.env): boolean {
  const header = (req.header('x-x402-facilitator') || req.header('x-facilitator') || '').trim().toLowerCase();
  if (header === 'payai') return true;
  if (header === 'cdp' || header === 'coinbase') return false;
  const queryFac = String(req.query?.facilitator || '').trim().toLowerCase();
  if (queryFac === 'payai') return true;
  if (queryFac === 'cdp' || queryFac === 'coinbase') return false;
  if (String(payment?.accepted?.extra?.facilitator || '').trim().toLowerCase() === 'payai') return true;
  if (String(payment?.extensions?.facilitator || '').trim().toLowerCase() === 'payai') return true;
  return String(env.BASE_FACILITATOR || '').trim().toLowerCase() === 'payai';
}

function decodePaymentHeader(req: Request): any | null {
  const raw = req.header('payment-signature') || req.header('x-payment');
  if (typeof raw !== 'string' || !raw.trim()) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw.trim(), 'base64').toString('utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function setBase402Header(res: Response, spec: EndpointSpec, publicUrl: string, payTo: string) {
  const resource = {
    url: `${publicUrl}${spec.path}`,
    description: spec.description,
    mimeType: 'application/json',
  };
  const payload = {
    x402Version: 2,
    resource,
    accepts: [basePaymentRequirements(spec.amountMicro, payTo)],
    extensions: {
      discoverable: true,
      bazaar: buildBaseBazaarExtension(spec),
    },
  };
  res.setHeader('PAYMENT-REQUIRED', Buffer.from(JSON.stringify(payload)).toString('base64'));
}

/**
 * Dual-facilitator Base (eip155:8453) payment gate using PayAI `/verify` and `/settle`.
 * Preserves CanaryGuard's execution-before-settlement contract, retired-recipient blocking,
 * PaymentJournal/retry preparation flags, and attaches Bazaar discovery schemas on `/settle`.
 */
export function basePayaiPaymentGate(
  publicUrl: string,
  payTo: string = RECIPIENT,
  request: typeof fetch = fetch,
  execute: typeof executeEndpoint = executeEndpoint,
  now: () => number = Date.now,
) {
  const expectedPayTo = getAddress(payTo);

  return async (req: Request, res: Response, next: NextFunction) => {
    if (res.getHeader('PAYMENT-RESPONSE')) return next();
    if (req.method !== 'POST') return next();
    const spec = ENDPOINT_MAP.get(req.path);
    if (!spec) return next();

    const payment = decodePaymentHeader(req);
    if (!payment || payment?.accepted?.network !== NETWORK) return next();
    if (!shouldUsePayaiForBase(req, payment)) return next();

    if (
      isRetiredBaseRecipient(payment.accepted?.payTo) ||
      isRetiredBaseRecipient(payment.payload?.authorization?.to)
    ) {
      setBase402Header(res, spec, publicUrl, expectedPayTo);
      res.status(402).json({ error: 'retired_recipient_authorization', charged: false });
      return;
    }

    const accepted = payment.accepted;
    const auth = payment.payload?.authorization;
    let termsValid = false;
    try {
      const nowSec = Math.floor(now() / 1000);
      termsValid =
        accepted?.scheme === 'exact' &&
        accepted?.network === NETWORK &&
        String(accepted?.amount) === spec.amountMicro &&
        typeof accepted?.asset === 'string' &&
        accepted.asset.toLowerCase() === ASSET.toLowerCase() &&
        typeof accepted?.payTo === 'string' &&
        getAddress(accepted.payTo) === expectedPayTo &&
        Boolean(auth && typeof auth === 'object') &&
        getAddress(auth.to) === expectedPayTo &&
        /^\d+$/.test(String(auth.value)) &&
        BigInt(auth.value) === BigInt(spec.amountMicro) &&
        /^\d+$/.test(String(auth.validAfter)) &&
        /^\d+$/.test(String(auth.validBefore)) &&
        nowSec >= Number(auth.validAfter) &&
        nowSec < Number(auth.validBefore);
    } catch {
      termsValid = false;
    }

    if (!termsValid) {
      setBase402Header(res, spec, publicUrl, expectedPayTo);
      res.status(402).json({ error: 'payment_terms_mismatch', charged: false });
      return;
    }

    if (payment.resource?.url !== undefined) {
      try {
        if (new URL(String(payment.resource.url)).pathname !== spec.path) {
          setBase402Header(res, spec, publicUrl, expectedPayTo);
          res.status(402).json({ error: 'payment_resource_mismatch', charged: false });
          return;
        }
      } catch {
        setBase402Header(res, spec, publicUrl, expectedPayTo);
        res.status(402).json({ error: 'payment_resource_mismatch', charged: false });
        return;
      }
    }

    if (!(await verifyPaymentOwnership(payment))) {
      setBase402Header(res, spec, publicUrl, expectedPayTo);
      res.status(402).json({ error: 'invalid_payment_signature', charged: false });
      return;
    }

    const resourceUrl = `${publicUrl}${spec.path}`;
    const paymentRequirements = basePaymentRequirements(spec.amountMicro, expectedPayTo);
    const extensions: Record<string, unknown> = {
      discoverable: true,
      bazaar: buildBaseBazaarExtension(spec),
      ...(payment.extensions && typeof payment.extensions === 'object' ? payment.extensions : {}),
    };
    const normalizedPayment = {
      x402Version: 2,
      resource:
        payment.resource && typeof payment.resource === 'object'
          ? payment.resource
          : { url: resourceUrl, description: spec.description, mimeType: 'application/json' },
      accepted: paymentRequirements,
      payload: payment.payload,
      extensions,
    };

    let verifyResponse: globalThis.Response;
    try {
      verifyResponse = await request(`${PAYAI_FACILITATOR}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ x402Version: 2, paymentPayload: normalizedPayment, paymentRequirements }),
        signal: AbortSignal.timeout(15000),
      });
    } catch {
      res.status(503).json({
        error: 'facilitator_unavailable',
        message: 'PayAI Base verification unavailable; no payment settled.',
        charged: false,
      });
      return;
    }

    let verified: any = null;
    try {
      verified = await verifyResponse.json();
    } catch {}
    if (!verifyResponse.ok || verified?.isValid !== true) {
      setBase402Header(res, spec, publicUrl, expectedPayTo);
      res.status(402).json({
        error: 'payment_verification_failed',
        reason: verified?.invalidReason || 'verification_failed',
        charged: false,
      });
      return;
    }

    let acquired = res.locals.acquiredResult;
    if (acquired === undefined) {
      try {
        acquired = await execute(spec.path, req.body);
      } catch (error) {
        if (error instanceof ExecutionError) {
          res.status(error.status).json({ error: error.code, message: error.message, charged: false });
          return;
        }
        res.status(503).json({
          error: 'execution_failed',
          message: 'Service execution failed before settlement.',
          charged: false,
        });
        return;
      }
      res.locals.acquiredResult = acquired;
    }

    let settleResponse: globalThis.Response;
    try {
      settleResponse = await request(`${PAYAI_FACILITATOR}/settle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ x402Version: 2, paymentPayload: normalizedPayment, paymentRequirements }),
        signal: AbortSignal.timeout(20000),
      });
    } catch {
      res.status(503).json({
        error: 'settlement_unconfirmed',
        message: 'PayAI settlement status uncertain; retry with the identical request and authorization to recover without double charge.',
        charged: 'unknown',
      });
      return;
    }

    let settled: any = null;
    try {
      settled = await settleResponse.json();
    } catch {}
    if (!settleResponse.ok || settled?.success !== true) {
      // Confirmed non-settlement: clear uncharged prepared marker so retry journal can cleanly release.
      res.locals.acquiredResult = undefined;
      const reason = settled?.errorReason || 'settlement_failed';
      res.setHeader(
        'PAYMENT-RESPONSE',
        Buffer.from(
          JSON.stringify({
            success: false,
            errorReason: reason,
            transaction: settled?.transaction || '',
            network: NETWORK,
          }),
        ).toString('base64'),
      );
      setBase402Header(res, spec, publicUrl, expectedPayTo);
      res.status(402).json({ error: reason, charged: false });
      return;
    }

    const receipt = {
      success: true,
      payer: settled.payer || verified.payer || auth.from,
      transaction: settled.transaction || settled.txHash || '',
      network: settled.network || NETWORK,
      amount: spec.amountMicro,
      resource: { url: resourceUrl },
    };
    res.setHeader('PAYMENT-RESPONSE', Buffer.from(JSON.stringify(receipt)).toString('base64'));
    if (spec.path === '/v1/sanitize') {
      res.locals.sanitized = true;
    }
    res.status(200).json(acquired);
  };
}
