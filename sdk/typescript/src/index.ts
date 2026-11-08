/**
 * CanaryGuard 402 - TypeScript / Node SDK
 *
 * Deterministic prompt-injection firewall and honeypot scrubber for AI agents.
 * 0.010 USDC per call on Base (eip155:8453) via x402.
 */

import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

export interface SanitizeOptions {
  content: string;
  strictMode?: boolean;
}

export interface Threat {
  type: string;
  detail: string;
  severity: number;
}

export interface ExtractedAddress {
  address: string;
  chain: "evm" | "bitcoin" | "solana";
  risk_score: number;
  reason: string;
}

export interface SanitizeResponse {
  status: "clean" | "neutralized" | "blocked" | "sanitized";
  risk_score: number;
  injection_detected: boolean;
  threats_neutralized: Threat[] | string[];
  crypto_addresses: ExtractedAddress[];
  sanitized_content: string;
  safety_receipt: string;
}

export class CanaryGuardClient {
  private baseUrl: string;
  private payingFetch: typeof fetch;

  constructor(options?: {
    baseUrl?: string;
    privateKey?: `0x${string}`;
    customFetch?: typeof fetch;
  }) {
    this.baseUrl = (options?.baseUrl ?? "https://canaryguard-402.onrender.com").replace(/\/$/, "");

    if (options?.privateKey) {
      const account = privateKeyToAccount(options.privateKey);
      const client = new x402Client();
      registerExactEvmScheme(client, { signer: account });

      // Enforce client-side safety guardrails before signing payments
      const expectedMerchant = "0x80e0ae84679b7f11be171daadd492fbecf628cd6";
      const baseUsdc = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
      const maxPerCallMicroUsdc = 10000n; // 0.010 USDC

      client.onBeforePaymentCreation(async (context) => {
        const req = context.selectedRequirements;
        if (req.network !== "eip155:8453") {
          throw new Error(`Rejected network ${req.network}: Base mainnet required`);
        }
        if (req.asset.toLowerCase() !== baseUsdc) {
          throw new Error(`Rejected asset ${req.asset}: Base USDC required`);
        }
        if (req.payTo.toLowerCase() !== expectedMerchant) {
          throw new Error(`Rejected payTo ${req.payTo}: Unauthorized merchant recipient`);
        }
        if (BigInt(req.amount) > maxPerCallMicroUsdc) {
          throw new Error(`Amount ${req.amount} exceeds max per-call cap of ${maxPerCallMicroUsdc}`);
        }
      });

      this.payingFetch = wrapFetchWithPayment(options.customFetch ?? fetch, client);
    } else {
      this.payingFetch = options?.customFetch ?? fetch;
    }
  }

  /**
   * Free evaluation preview without wallet or x402 payment header.
   */
  async sanitizePreview(content: string): Promise<SanitizeResponse> {
    const res = await fetch(`${this.baseUrl}/v1/sanitize/preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`CanaryGuard Preview HTTP ${res.status}: ${errText}`);
    }

    return (await res.json()) as SanitizeResponse;
  }

  async sanitize(options: SanitizeOptions): Promise<SanitizeResponse> {
    const res = await this.payingFetch(`${this.baseUrl}/v1/sanitize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: options.content,
        strict_mode: options.strictMode ?? true,
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`CanaryGuard HTTP ${res.status}: ${errText}`);
    }

    return (await res.json()) as SanitizeResponse;
  }

  async health(): Promise<{ status: string; service: string }> {
    const res = await fetch(`${this.baseUrl}/health`);
    return await res.json();
  }

  async stats(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/stats`);
    return await res.json();
  }
}
