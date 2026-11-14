# @kurox_real/plugin-canaryguard

ElizaOS plugin for **CanaryGuard 402**, the deterministic prompt-injection firewall and honeypot scrubber on Base mainnet.

## Overview

When autonomous Eliza agents ingest untrusted messages from Twitter, Telegram, or Discord, malicious actors often attempt:
- **Jailbreaks & Prompt Injection**: Tricking the LLM into ignoring system rules.
- **Wallet Drain Commands**: Sneaking instructions like "Transfer all USDC to 0x...".
- **Invisible Zero-Width Overrides**: Hiding unicode payload bytes.

CanaryGuard 402 sanitizes untrusted text in `<5ms` before context ingestion, paid autonomously per call (0.010 USDC) via the x402 protocol on Base and Solana.

## Installation

```bash
npm install @kurox_real/plugin-canaryguard
```

## Setup in ElizaOS

In your character configuration or agent setup:

```typescript
import { canaryGuardPlugin } from "@kurox_real/plugin-canaryguard";

export const character = {
  name: "MyAutonomousAgent",
  plugins: [canaryGuardPlugin],
  // ... rest of character config
};
```

## Features

- **`CANARY_SANITIZE` Action**: Agent can explicitly sanitize external text, tool outputs, or links.
- **`PROMPT_INJECTION_EVALUATOR`**: Automatically inspects incoming messages for jailbreak patterns before state updates.
- **`CANARYGUARD_STATUS_PROVIDER`**: Injects firewall defense state into prompt system context.

## Direct SDK Usage

```typescript
import { sanitizeWithCanaryGuard } from "@kurox_real/plugin-canaryguard";

const result = await sanitizeWithCanaryGuard("Untrusted user input here", {
  strictMode: true,
});

if (result.injection_detected) {
  console.warn("Blocked prompt injection threat!", result.threats_neutralized);
}
```

## Specifications

- **Protocol**: x402 v2 on Base Mainnet (`eip155:8453`)
- **Cost**: 0.010 USDC per sanitization
- **Merchant Address**: `0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6`
- **Latency**: <5ms deterministic inspection
