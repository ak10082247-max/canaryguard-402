import { z } from "zod";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const EXPECTED_MERCHANT = "0x80e0ae84679b7f11be171daadd492fbecf628cd6";
const BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const MAX_PER_CALL_MICRO_USDC = 50_000n;

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
  paymentMode?: "x402_paid" | "x402_header" | "free_preview";
  x402UpgradeHint?: string;
}

export interface CanaryGuardActionProviderConfig {
  hostUrl?: string;
  paymentHeader?: string;
  privateKey?: `0x${string}` | string;
  useFreePreview?: boolean;
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

function createPayingFetch(privateKey: `0x${string}`, baseFetch: typeof fetch = fetch): typeof fetch {
  const account = privateKeyToAccount(privateKey);
  const client = new x402Client();
  client.register("eip155:8453", new ExactEvmScheme(account));
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
 * Execute prompt-injection inspection and sanitization via CanaryGuard 402 microservice on Base.
 */
export async function executeCanaryGuardSanitize(
  params: CanaryGuardSanitizeInput,
  options?: CanaryGuardActionProviderConfig
): Promise<CanaryGuardSanitizeOutput> {
  const host = (
    options?.hostUrl ||
    process.env.CANARYGUARD_URL ||
    "https://canaryguard-402.onrender.com"
  ).replace(/\/$/, "");

  const baseFetch = options?.customFetch ?? fetch;
  const privateKey = resolvePrivateKey(options?.privateKey);
  const paymentHeader = options?.paymentHeader || process.env.CANARYGUARD_PAYMENT_HEADER;
  const usePreview =
    options?.useFreePreview === true ||
    (!privateKey && !paymentHeader && options?.useFreePreview !== false);

  const url = `${host}${usePreview ? "/v1/sanitize/preview" : "/v1/sanitize"}`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (paymentHeader && !privateKey && !usePreview) {
    headers["PAYMENT-SIGNATURE"] = paymentHeader;
    headers["X-PAYMENT"] = paymentHeader;
  }

  const caller = privateKey && !usePreview ? createPayingFetch(privateKey, baseFetch) : baseFetch;
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
      `CanaryGuard 402 Payment Required ($0.010 USDC via x402). Pass options.privateKey or set X402_PRIVATE_KEY (Base USDC, 0 ETH gas) for automatic /v1/sanitize signing, or omit useFreePreview: false to evaluate via /v1/sanitize/preview.`
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
    paymentMode: usePreview ? "free_preview" : privateKey ? "x402_paid" : "x402_header",
    x402UpgradeHint: usePreview
      ? "Evaluated via free /v1/sanitize/preview. Set X402_PRIVATE_KEY or pass { privateKey } (Base USDC, 0 ETH gas) to run full paid /v1/sanitize."
      : undefined,
  };
}

/**
 * Creates a Coinbase AgentKit ActionProvider for CanaryGuard 402.
 */
export function canaryGuardActionProvider(config?: CanaryGuardActionProviderConfig) {
  const action = {
    name: "canary_sanitize",
    description:
      "Deterministic prompt-injection firewall and honeypot scrubber on Base via x402 (0.010 USDC). Auto-pays via @x402/fetch when X402_PRIVATE_KEY is set, or evaluates via /v1/sanitize/preview.",
    schema: CanaryGuardSanitizeInputSchema,
    invoke: async (args: CanaryGuardSanitizeInput) => {
      return await executeCanaryGuardSanitize(args, config);
    },
  };

  return {
    name: "canaryguard",
    actionProviderName: "canaryguard",
    supportsNetwork: () => true,
    getActions: () => [action],
    actions: [action],
  };
}
