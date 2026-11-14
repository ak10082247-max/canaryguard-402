import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { wrapFetchWithPayment } from '@x402/fetch';
import { privateKeyToAccount } from 'viem/accounts';
import type { CanaryGuardConfig, SanitizeResult } from './types.js';

export const CANARYGUARD_DEFAULT_URL = 'https://canaryguard-402.onrender.com';
const EXPECTED_MERCHANT = '0x80e0ae84679b7f11be171daadd492fbecf628cd6';
const BASE_USDC = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const MAX_PER_CALL_MICRO_USDC = 50_000n; // $0.050 USDC cap for /v1/sanitize

export const X402_UPGRADE_HINT =
  'Evaluated via free /v1/sanitize/preview. Set X402_PRIVATE_KEY (or CANARYGUARD_PRIVATE_KEY / config.privateKey) funded with Base USDC (0 ETH gas required) to automatically sign EIP-3009 x402 payments against /v1/sanitize.';

function readSetting(runtime: any, keys: string[]): string | undefined {
  for (const key of keys) {
    const runtimeVal = typeof runtime?.getSetting === 'function' ? runtime.getSetting(key) : undefined;
    if (typeof runtimeVal === 'string' && runtimeVal.trim()) return runtimeVal.trim();
    const envVal = typeof process !== 'undefined' ? process.env?.[key] : undefined;
    if (typeof envVal === 'string' && envVal.trim()) return envVal.trim();
  }
  return undefined;
}

function normalizeHexKey(raw?: string): `0x${string}` | undefined {
  if (!raw) return undefined;
  const cleaned = raw.trim().replace(/^0x/i, '');
  if (!/^[a-fA-F0-9]{64}$/.test(cleaned)) {
    throw new Error('Invalid EVM private key format: expected 32-byte hex string for x402 signing');
  }
  return `0x${cleaned}`;
}

export function resolveCanaryGuardConfig(config?: CanaryGuardConfig, runtime?: any) {
  const serviceUrl = (
    config?.serviceUrl ||
    readSetting(runtime, ['CANARYGUARD_URL', 'CANARYGUARD_SERVICE_URL']) ||
    CANARYGUARD_DEFAULT_URL
  ).replace(/\/$/, '');

  const rawPrivateKey =
    config?.privateKey ||
    readSetting(runtime, ['X402_PRIVATE_KEY', 'CANARYGUARD_PRIVATE_KEY', 'EVM_PRIVATE_KEY', 'BASE_PRIVATE_KEY']);
  const privateKey = normalizeHexKey(rawPrivateKey);

  const paymentHeader =
    config?.paymentHeader ||
    readSetting(runtime, ['CANARYGUARD_PAYMENT_HEADER', 'PAYMENT_SIGNATURE']);

  return {
    serviceUrl,
    privateKey,
    paymentHeader,
    strictMode: config?.strictMode ?? false,
    customFetch: config?.customFetch ?? fetch,
  };
}

export function createCanaryGuardPayingFetch(privateKey: `0x${string}`, baseFetch: typeof fetch = fetch): typeof fetch {
  const account = privateKeyToAccount(privateKey);
  const client = new x402Client();
  client.register('eip155:8453', new ExactEvmScheme(account));
  client.onBeforePaymentCreation(async (context) => {
    const req = context.selectedRequirements;
    if (req.network !== 'eip155:8453') {
      throw new Error(`Rejected x402 network ${req.network}: Base mainnet (eip155:8453) required`);
    }
    if (req.asset.toLowerCase() !== BASE_USDC) {
      throw new Error(`Rejected x402 asset ${req.asset}: Base USDC required`);
    }
    if (req.payTo.toLowerCase() !== EXPECTED_MERCHANT) {
      throw new Error(`Rejected x402 payTo ${req.payTo}: Unauthorized recipient`);
    }
    if (BigInt(req.amount) > MAX_PER_CALL_MICRO_USDC) {
      throw new Error(`Rejected x402 amount ${req.amount}: exceeds ${MAX_PER_CALL_MICRO_USDC} micro-USDC cap`);
    }
  });
  return wrapFetchWithPayment(baseFetch, client);
}

/**
 * Call live CanaryGuard 402 HTTP service (/v1/sanitize with x402 payment, or /v1/sanitize/preview when unconfigured).
 */
export async function sanitizeWithCanaryGuard(
  content: string,
  config?: CanaryGuardConfig,
  runtime?: any,
): Promise<SanitizeResult> {
  const resolved = resolveCanaryGuardConfig(config, runtime);
  const body = JSON.stringify({
    content,
    strict_mode: resolved.strictMode,
  });

  if (resolved.privateKey) {
    const payingFetch = createCanaryGuardPayingFetch(resolved.privateKey, resolved.customFetch);
    const res = await payingFetch(`${resolved.serviceUrl}/v1/sanitize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`CanaryGuard x402 HTTP ${res.status}: ${errText}`);
    }
    const data = (await res.json()) as SanitizeResult;
    return {
      ...data,
      payment_mode: 'x402_paid',
      payment_response: res.headers.get('PAYMENT-RESPONSE') ?? res.headers.get('X-PAYMENT-RESPONSE') ?? null,
    };
  }

  if (resolved.paymentHeader) {
    const res = await resolved.customFetch(`${resolved.serviceUrl}/v1/sanitize`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'PAYMENT-SIGNATURE': resolved.paymentHeader,
        'X-PAYMENT': resolved.paymentHeader,
      },
      body,
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`CanaryGuard paid header HTTP ${res.status}: ${errText}`);
    }
    const data = (await res.json()) as SanitizeResult;
    return {
      ...data,
      payment_mode: 'x402_header',
      payment_response: res.headers.get('PAYMENT-RESPONSE') ?? res.headers.get('X-PAYMENT-RESPONSE') ?? null,
    };
  }

  const res = await resolved.customFetch(`${resolved.serviceUrl}/v1/sanitize/preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`CanaryGuard preview HTTP ${res.status}: ${errText}`);
  }
  const data = (await res.json()) as SanitizeResult;
  return {
    ...data,
    payment_mode: 'free_preview',
    x402_upgrade_hint: X402_UPGRADE_HINT,
  };
}
