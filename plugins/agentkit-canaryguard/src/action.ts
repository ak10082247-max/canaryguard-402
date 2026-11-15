import { performance } from "node:perf_hooks";
import { z } from "zod";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { sanitizeContentLocal } from "./local_sanitizer.js";

export { sanitizeContentLocal, type LocalSanitizeResponse } from "./local_sanitizer.js";

const EXPECTED_MERCHANT = "0x80e0ae84679b7f11be171daadd492fbecf628cd6";
const BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const MAX_PER_CALL_MICRO_USDC = 50_000n;
const LOCAL_UPGRADE_HINT =
  "Executed locally in-process (<1ms). Omit localFast (and pass { privateKey } or an EvmWalletProvider with { useFreePreview: false }) for cloud verification and smart-contract honeypot telemetry.";

export interface AgentKitWalletProviderLike {
  getAddress?: () => string;
  getNetwork?: () => { protocolFamily?: string; networkId?: string; chainId?: string };
  toSigner?: () => any;
}

export type X402EvmSignerLike = ConstructorParameters<typeof ExactEvmScheme>[0];

export const CanaryGuardSanitizeInputSchema = z.object({
  content: z
    .string()
    .min(1)
    .max(50_000)
    .describe(
      "Untrusted text, scraped HTML, email, or third-party tool output to sanitize before placing into agent context (max 50,000 characters)"
    ),
  strictMode: z
    .boolean()
    .optional()
    .default(true)
    .describe("When true, blocks detected instruction overrides and wallet-draining commands"),
});

export type CanaryGuardSanitizeInput = z.infer<typeof CanaryGuardSanitizeInputSchema>;

export interface CanaryGuardSanitizeOutput {
  status: "clean" | "sanitized" | "blocked";
  riskScore: number;
  injectionDetected: boolean;
  threatsNeutralized: string[];
  cryptoAddresses: Array<{ address: string; risk_score: number; reasons: string[] }>;
  sanitizedContent: string;
  safetyReceipt: string;
  recommendedActions?: Array<{
    service: string;
    description: string;
    url: string;
    price: string;
  }>;
  inspection: {
    method: string;
    guaranteed_safe: boolean;
    risk_score_semantics: string;
    limitations: string[];
  };
  paymentMode?: "x402_paid" | "x402_header" | "free_preview" | "local_fast";
  executionMode?: "local_in_process" | "cloud_api";
  latencyMs?: number;
  x402UpgradeHint?: string;
}

export interface CanaryGuardActionProviderConfig {
  hostUrl?: string;
  paymentHeader?: string;
  privateKey?: `0x${string}` | string;
  signer?: X402EvmSignerLike;
  useWalletSigner?: boolean;
  useFreePreview?: boolean;
  localFast?: boolean;
  executionMode?: "local_fast" | "cloud_api";
  outputFormat?: "json" | "object";
  customFetch?: typeof fetch;
}

function resolvePrivateKey(explicitKey?: string): `0x${string}` | undefined {
  const candidates = [
    explicitKey,
    typeof process !== "undefined" ? process.env?.X402_PRIVATE_KEY : undefined,
    typeof process !== "undefined" ? process.env?.CANARYGUARD_PRIVATE_KEY : undefined,
    typeof process !== "undefined" ? process.env?.EVM_PRIVATE_KEY : undefined,
    typeof process !== "undefined" ? process.env?.BASE_PRIVATE_KEY : undefined,
  ];
  for (const raw of candidates) {
    if (typeof raw !== "string") continue;
    const cleaned = raw.trim().replace(/^0x/i, "");
    if (/^[a-fA-F0-9]{64}$/.test(cleaned)) return `0x${cleaned}`;
  }
  return undefined;
}

function createPayingFetchFromSigner(signer: X402EvmSignerLike, baseFetch: typeof fetch = fetch): typeof fetch {
  const client = new x402Client();
  client.register("eip155:8453", new ExactEvmScheme(signer));
  client.onBeforePaymentCreation(async (context) => {
    const req = context.selectedRequirements;
    if (req.network !== "eip155:8453") {
      throw new Error(`Rejected x402 network ${req.network}`);
    }
    if (req.asset.toLowerCase() !== BASE_USDC) {
      throw new Error(`Rejected x402 asset ${req.asset}`);
    }
    if (req.payTo.toLowerCase() !== EXPECTED_MERCHANT) {
      throw new Error(`Rejected x402 payTo ${req.payTo}`);
    }
    if (BigInt(req.amount) > MAX_PER_CALL_MICRO_USDC) {
      throw new Error(`Rejected x402 amount ${req.amount}`);
    }
  });
  return wrapFetchWithPayment(baseFetch, client);
}

/**
 * Deterministic sub-millisecond local sanitization (zero network, zero wallet needed).
 */
export function executeCanaryGuardSanitizeLocal(params: CanaryGuardSanitizeInput): CanaryGuardSanitizeOutput {
  const parsed = CanaryGuardSanitizeInputSchema.parse(params);
  const res = sanitizeContentLocal(parsed.content, parsed.strictMode !== false);
  const recommendedActions =
    res.crypto_addresses.length > 0
      ? [
          {
            service: "rugshield-402",
            description:
              "Run on-chain honeypot simulation and tax verification for extracted EVM addresses before signing transactions.",
            url: "https://rugshield-402.onrender.com/v1/honeypot",
            price: "0.010 USDC",
          },
        ]
      : undefined;

  return {
    status: res.status,
    riskScore: res.risk_score,
    injectionDetected: res.injection_detected,
    threatsNeutralized: res.threats_neutralized,
    cryptoAddresses: res.crypto_addresses.map((addr) => ({
      address: addr.address,
      risk_score: addr.risk_score,
      reasons: addr.reasons,
    })),
    sanitizedContent: res.sanitized_content,
    safetyReceipt: res.safety_receipt,
    recommendedActions,
    inspection: res.inspection,
    paymentMode: "local_fast",
    executionMode: "local_in_process",
    latencyMs: res.latency_ms,
    x402UpgradeHint: LOCAL_UPGRADE_HINT,
  };
}

/**
 * Execute prompt-injection inspection and sanitization via CanaryGuard 402 (local sub-1ms or microservice on Base).
 */
export async function executeCanaryGuardSanitize(
  params: CanaryGuardSanitizeInput,
  options?: CanaryGuardActionProviderConfig
): Promise<CanaryGuardSanitizeOutput> {
  const privateKey = resolvePrivateKey(options?.privateKey);
  const signer = options?.signer ?? (privateKey ? privateKeyToAccount(privateKey) : undefined);
  const paymentHeader =
    options?.paymentHeader ||
    (typeof process !== "undefined" ? process.env?.CANARYGUARD_PAYMENT_HEADER : undefined);
  const envLocalFast =
    typeof process !== "undefined" && process.env?.CANARYGUARD_LOCAL_FAST === "1";

  const shouldRunLocal =
    options?.localFast === true ||
    options?.executionMode === "local_fast" ||
    (envLocalFast && options?.useFreePreview !== true && !signer && !paymentHeader);

  if (shouldRunLocal) {
    return executeCanaryGuardSanitizeLocal(params);
  }

  const startedAt = performance.now();
  const host = (
    options?.hostUrl ||
    (typeof process !== "undefined" ? process.env?.CANARYGUARD_URL : undefined) ||
    "https://canaryguard-402.onrender.com"
  ).replace(/\/$/, "");

  const baseFetch = options?.customFetch ?? fetch;
  const usePreview =
    options?.useFreePreview === true ||
    (!signer && !paymentHeader && options?.useFreePreview !== false);

  const url = `${host}${usePreview ? "/v1/sanitize/preview" : "/v1/sanitize"}`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (paymentHeader && !signer && !usePreview) {
    headers["PAYMENT-SIGNATURE"] = paymentHeader;
    headers["X-PAYMENT"] = paymentHeader;
  }

  const caller = signer && !usePreview ? createPayingFetchFromSigner(signer, baseFetch) : baseFetch;
  const res = await caller(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      content: params.content,
      strict_mode: params.strictMode !== false,
    }),
  });

  if (res.status === 402) {
    throw new Error(
      `CanaryGuard 402 Payment Required ($0.010 USDC via x402). Pass options.privateKey, an AgentKit EvmWalletProvider with { useFreePreview: false }, or set X402_PRIVATE_KEY (Base USDC, 0 ETH gas) for automatic /v1/sanitize signing, or omit useFreePreview: false to evaluate via /v1/sanitize/preview.`
    );
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`CanaryGuard 402 error (${res.status}): ${text}`);
  }

  const data: any = await res.json();
  return {
    status: data.status,
    riskScore: data.risk_score,
    injectionDetected: data.injection_detected,
    threatsNeutralized: data.threats_neutralized || [],
    cryptoAddresses: data.crypto_addresses || [],
    sanitizedContent: data.sanitized_content,
    safetyReceipt: data.safety_receipt,
    recommendedActions: data.recommended_actions,
    inspection: data.inspection,
    paymentMode: usePreview ? "free_preview" : signer ? "x402_paid" : "x402_header",
    executionMode: "cloud_api",
    latencyMs: Number((performance.now() - startedAt).toFixed(3)),
    x402UpgradeHint: usePreview
      ? "Evaluated via free /v1/sanitize/preview. Set X402_PRIVATE_KEY or pass { privateKey } (Base USDC, 0 ETH gas) to run full paid /v1/sanitize."
      : undefined,
  };
}

/**
 * Creates a Coinbase AgentKit ActionProvider for CanaryGuard 402.
 */
export function canaryGuardActionProvider(config?: CanaryGuardActionProviderConfig) {
  const buildActions = (walletProvider?: AgentKitWalletProviderLike) => {
    let resolvedOptions: CanaryGuardActionProviderConfig | undefined = config;
    const canAttachWalletSigner =
      Boolean(walletProvider && typeof walletProvider.toSigner === "function") &&
      !config?.signer &&
      !resolvePrivateKey(config?.privateKey) &&
      !config?.paymentHeader &&
      !config?.localFast &&
      config?.executionMode !== "local_fast" &&
      config?.useFreePreview !== true &&
      (config?.useWalletSigner === true || config?.useFreePreview === false);

    if (canAttachWalletSigner && walletProvider?.toSigner) {
      resolvedOptions = {
        ...config,
        signer: walletProvider.toSigner(),
      };
    }

    const action = {
      name: "canary_sanitize",
      description:
        "Deterministic prompt-injection firewall and honeypot scrubber (<1ms local mode with { localFast: true }, free /v1/sanitize/preview, or paid Base x402 via EvmWalletProvider / X402_PRIVATE_KEY).",
      schema: CanaryGuardSanitizeInputSchema,
      invoke: async (argsOrWallet: CanaryGuardSanitizeInput, maybeArgs?: CanaryGuardSanitizeInput): Promise<string> => {
        const parsedArgs = (maybeArgs !== undefined ? maybeArgs : argsOrWallet) as CanaryGuardSanitizeInput;
        const result = await executeCanaryGuardSanitize(parsedArgs, resolvedOptions);
        if (config?.outputFormat === "object") {
          return result as unknown as string;
        }
        return JSON.stringify(result, null, 2);
      },
    };

    return [action];
  };

  const defaultActions = buildActions(undefined);

  return {
    name: "canaryguard",
    actionProviderName: "canaryguard",
    actionProviders: [] as never[],
    supportsNetwork: (_network?: { protocolFamily?: string; networkId?: string; chainId?: string }) => true,
    getActions: (walletProvider?: AgentKitWalletProviderLike) => buildActions(walletProvider),
    actions: defaultActions,
  };
}
