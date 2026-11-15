# @kurox_real/plugin-canaryguard

ElizaOS plugin for **CanaryGuard 402** — deterministic prompt-injection firewall, Unicode Tag / Base64 / HTML steganography scrubber, and contextual crypto-command scorer (`<5ms` local evaluator and live `eip155:8453` x402 API integration).

## Install

```bash
npm install @kurox_real/plugin-canaryguard
```

## Quickstart (ElizaOS)

```ts
import { canaryGuardPlugin, inspectContent, sanitizeWithCanaryGuard } from "@kurox_real/plugin-canaryguard";

export const character = {
  name: "AutonomousAgent",
  plugins: [canaryGuardPlugin],
};

// Sub-5ms (<1ms typical) synchronous security evaluator (Unicode Tags, Base64, HTML CSS, wallet drains):
const verdict = inspectContent(untrustedText, true);

// Or action/utility call with explicit localFast (<1ms), free preview, or paid x402 Base USDC:
const localRes = await sanitizeWithCanaryGuard(untrustedText, { localFast: true, strictMode: true });
const previewRes = await sanitizeWithCanaryGuard(untrustedText, { strictMode: true });
const paidRes = await sanitizeWithCanaryGuard(untrustedText, {
  privateKey: process.env.X402_PRIVATE_KEY as `0x${string}`,
  strictMode: true,
});
```

## Components

- **`canaryGuardEvaluator` (`CANARY_GUARD_SECURITY`)**: Pre-warmed V8 JIT local engine (`<5ms`, typically `<1ms`) detecting prompt overrides, role delimiter hijacks, Unicode Tag smuggling (`U+E0000..U+E007F`), Base64/URL/Hex nested attacks, hidden HTML CSS, and contextual wallet transfer addresses with SHA-256 `canary-v1-...` receipts. Preserves original message memory text non-destructively.
- **`sanitizeAction` (`CANARY_SANITIZE`)**: Supports `{ localFast: true }` / `CANARYGUARD_LOCAL_FAST=1`, free `/v1/sanitize/preview`, or automatic Base USDC EIP-3009 settlement via `@x402/fetch`.
- **`canaryGuardProvider`**: Injects latest CanaryGuard evaluation summary into ElizaOS state context.
