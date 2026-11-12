import { z } from "zod";

export const CanaryGuardSanitizeInputSchema = z.object({
  content: z
    .string()
    .min(1)
    .max(50_000)
    .describe("Untrusted text, scraped HTML, email, or third-party tool output to sanitize before placing into agent context (max 50,000 characters)"),
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
  recommendedActions?: Array<{ service: string; description: string; url: string; price: string }>;
  inspection: {
    method: string;
    guaranteed_safe: boolean;
    risk_score_semantics: string;
    limitations: string[];
  };
}

/**
 * Execute prompt-injection inspection and sanitization via CanaryGuard 402 microservice on Base.
 */
export async function executeCanaryGuardSanitize(
  params: CanaryGuardSanitizeInput,
  options?: { hostUrl?: string; paymentHeader?: string; useFreePreview?: boolean }
): Promise<CanaryGuardSanitizeOutput> {
  const host = (
    options?.hostUrl ||
    process.env.CANARYGUARD_URL ||
    "https://canaryguard-402.onrender.com"
  ).replace(/\/$/, "");

  const usePreview =
    options?.useFreePreview === true ||
    (!options?.paymentHeader && process.env.CANARYGUARD_FREE_PREVIEW === "true");

  const url = `${host}${usePreview ? "/v1/sanitize/preview" : "/v1/sanitize"}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (options?.paymentHeader) {
    headers["PAYMENT-SIGNATURE"] = options.paymentHeader;
    headers["X-PAYMENT"] = options.paymentHeader;
  }

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      content: params.content,
      strict_mode: params.strictMode !== false,
    }),
  });

  if (res.status === 402) {
    throw new Error(
      `CanaryGuard 402 Payment Required ($0.010 USDC via x402). Pass options.paymentHeader (from @x402/fetch) for production /v1/sanitize, or set { useFreePreview: true } / CANARYGUARD_FREE_PREVIEW=true to evaluate via free /v1/sanitize/preview.`
    );
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`CanaryGuard 402 error (${res.status}): ${text}`);
  }

  const data = (await res.json()) as any;
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
  };
}

export interface CanaryGuardActionProviderConfig {
  hostUrl?: string;
  paymentHeader?: string;
  useFreePreview?: boolean;
}

/**
 * Creates a Coinbase AgentKit ActionProvider for CanaryGuard 402.
 */
export function canaryGuardActionProvider(config?: CanaryGuardActionProviderConfig) {
  return {
    name: "canaryguard",
    actionProviderName: "canaryguard",
    getActions: () => [
      {
        name: "canary_sanitize",
        description: "Deterministic prompt-injection firewall and honeypot scrubber on Base via x402 (0.010 USDC). Sanitizes untrusted text and blocks detected instruction overrides or wallet-draining commands.",
        schema: CanaryGuardSanitizeInputSchema,
        invoke: async (args: CanaryGuardSanitizeInput) => {
          return await executeCanaryGuardSanitize(args, config);
        },
      },
    ],
    actions: [
      {
        name: "canary_sanitize",
        description: "Deterministic prompt-injection firewall and honeypot scrubber on Base via x402 (0.010 USDC). Sanitizes untrusted text and blocks detected instruction overrides or wallet-draining commands.",
        schema: CanaryGuardSanitizeInputSchema,
        invoke: async (args: CanaryGuardSanitizeInput) => {
          return await executeCanaryGuardSanitize(args, config);
        },
      },
    ],
  };
}
