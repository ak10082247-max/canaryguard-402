# Standalone CanaryGuard x402 Buyer Client

This directory contains a complete, verified standalone buyer client demonstrating how an autonomous AI agent purchases prompt-injection sanitization from **CanaryGuard-402** on Base mainnet (0.010 USDC per call) via the official `@x402/fetch` SDK.

## Prerequisites
- Node.js >= 20.0.0
- An EVM private key funded with a small amount of USDC on Base mainnet (`eip155:8453`). (Zero ETH required for gas; x402 uses gasless EIP-3009 transfer authorizations).

## Installation

```bash
npm install
```

## Running the Client

### Windows PowerShell
```powershell
$env:BUYER_PRIVATE_KEY = "0x<YOUR_PRIVATE_KEY>"
node buyer.mjs
```

### Linux / macOS Bash
```bash
BUYER_PRIVATE_KEY="0x<YOUR_PRIVATE_KEY>" node buyer.mjs
```

## Security & Pre-Signing Guardrails
The script includes client-side interceptors (`client.onBeforePaymentCreation`) that verify:
1. **Network**: Rejects any challenge not on Base Mainnet (`eip155:8453`).
2. **Asset**: Rejects any token other than Base USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`).
3. **Recipient**: Enforces exact payment to the authorized merchant address (`0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6`).
4. **Amount**: Hard per-call cap of 10,000 micro-USDC ($0.010).
5. **Cumulative Budget**: Prevents repeat calls from exceeding a total test ceiling.
