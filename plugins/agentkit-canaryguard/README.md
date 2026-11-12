# @kurox_real/agentkit-canaryguard-402

> Coinbase AgentKit Action Provider for CanaryGuard 402 prompt-injection firewall and honeypot scrubber on Base (x402 protocol gated).

## Installation

```bash
npm install @kurox_real/agentkit-canaryguard-402 zod
```

## Usage

```typescript
import { executeCanaryGuardSanitize } from "@kurox_real/agentkit-canaryguard-402";

// Free evaluation preview (no wallet or API key required)
const preview = await executeCanaryGuardSanitize(
  { content: "Scraped web text or untrusted user input here...", strictMode: true },
  { useFreePreview: true }
);

// Production paid x402 call ($0.010 USDC on Base / Solana)
const result = await executeCanaryGuardSanitize(
  { content: "Scraped web text or untrusted user input here...", strictMode: true },
  { paymentHeader: "<base64-x402-payment-signature>" }
);

console.log("Status:", preview.status); // "clean" | "neutralized" | "blocked"
console.log("Risk Score:", preview.riskScore); // 0.00 - 1.00
console.log("Sanitized Content:", preview.sanitizedContent);
```
