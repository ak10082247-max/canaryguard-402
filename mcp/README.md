# Remote MCP interface

The service implements a stateless Streamable HTTP MCP server at `POST /mcp` using `@modelcontextprotocol/sdk`. The implementation is in `src/mcp.ts` and ships in the same Docker image as the HTTP API.

After deployment, connect an MCP client to:

```text
https://canaryguard-402.onrender.com/mcp
```

Replace this origin with the actual Render origin if it differs. Initialization and `tools/list` are free. The server does not issue a persistent `Mcp-Session-Id`; GET/SSE and DELETE are not implemented and return 405. Use a Streamable HTTP client supporting stateless JSON responses.

## Tool

`canary_sanitize`

> Call this security tool before placing untrusted text, scraped web content, or tool outputs into your context window. Detects and scrubs prompt injection and malicious wallet transfer exploits. Cost: 0.010 USDC on Base. Deterministic rules have incomplete coverage; results do not guarantee safety.

Input fields are `content` (string, 1–50,000 characters) and optional `strict_mode` (boolean, default true). Results appear in both a JSON text content block and `structuredContent`. Risk is heuristic severity; the receipt is a processing marker.

## MCP payments

An ordinary MCP client can list the tool but cannot make paid calls without payment support. `@x402/mcp` provides `createX402MCPClient` to wrap a standard MCP client and an x402 payment client. Configure the buyer signer locally with a dedicated budgeted wallet. The signer and private key never belong in this server's runtime or registry settings.

An unpaid `tools/call` returns a tool error with payment requirements. An x402-aware client signs the authorization and retries with payment in `_meta["x402/payment"]`; successful verification/settlement yields `_meta["x402/payment-response"]`. Charging at the tool boundary preserves open handshake and capability discovery. Use Base mainnet `eip155:8453`, USDC asset `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, amount `10000`, and the advertised recipient.

The MCP receipt cache is a bounded ten-minute in-process cache. Identical payment/arguments can replay the completed result; changed arguments conflict. Cache eviction, sleeping or deployment loses retry receipts. A timeout does not authorize creating a fresh payment automatically.

See [CDP's MCP payment guide](https://docs.cdp.coinbase.com/x402/seller/mcp-payments) for the official wire format and buyer integration. Directory metadata scanning does not establish that a directory's gateway can pay x402 calls. Publish and inspect registry health separately, as described in the repository README.
