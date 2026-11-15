# @kurox_real/agentkit-canaryguard-402

Coinbase AgentKit `ActionProvider` for **CanaryGuard 402** — deterministic prompt-injection firewall, Unicode Tag / Base64 / HTML steganography scrubber, and contextual crypto-command scorer (`eip155:8453`).

## Install

```bash
npm install @kurox_real/agentkit-canaryguard-402 @coinbase/agentkit
```

## Quickstart (`AgentKit.from`)

```ts
import { AgentKit } from "@coinbase/agentkit";
import { canaryGuardActionProvider } from "@kurox_real/agentkit-canaryguard-402";

const agentKit = await AgentKit.from({
  walletProvider,
  actionProviders: [
    // Zero-wallet cloud evaluation (/v1/sanitize/preview):
    canaryGuardActionProvider({ useFreePreview: true }),

    // Or sub-millisecond (<1ms) offline/in-process mode (zero network):
    // canaryGuardActionProvider({ localFast: true }),

    // Or automatic Base USDC EIP-3009 payment via your AgentKit EvmWalletProvider:
    // canaryGuardActionProvider({ useFreePreview: false }),
  ],
});
```

## Execution Modes

| Option | Endpoint / Runtime | Cost | Typical Latency |
| --- | --- | --- | --- |
| `{ localFast: true }` or `CANARYGUARD_LOCAL_FAST=1` | In-process V8 JIT engine | Free (zero network) | `< 1 ms` |
| `{ useFreePreview: true }` (default when no key) | `POST /v1/sanitize/preview` | Free evaluation | HTTP RTT (`~0.2 ms` engine) |
| `{ useFreePreview: false }` + `EvmWalletProvider` / `privateKey` | `POST /v1/sanitize` (x402 V2) | `0.010 USDC` (Base) | Paid on-chain receipt |

`canary_sanitize` returns a JSON string (`Promise<string>`) matching `@coinbase/agentkit` `Action` requirements. Pass `{ outputFormat: "object" }` if you invoke `getActions()[0].invoke(...)` directly and prefer a JS object, or call `executeCanaryGuardSanitize()` / `executeCanaryGuardSanitizeLocal()` directly for typed `CanaryGuardSanitizeOutput`.
