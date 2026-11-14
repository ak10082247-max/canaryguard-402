/**
 * CanaryGuard 402 - MCP server (stdio).
 *
 * Exposes `canary_sanitize`, which calls the hosted x402 endpoint and pays
 * 0.010 USDC per call from the wallet in BUYER_PRIVATE_KEY (Base mainnet).
 *
 * Env:
 *   BUYER_PRIVATE_KEY   0x... key of a wallet holding USDC on Base (required)
 *   CANARYGUARD_URL     default https://canaryguard-402.onrender.com
 *   MAX_PRICE_ATOMIC    safety cap per call in USDC micro-units (default 10000)
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { privateKeyToAccount } from "viem/accounts";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";

const BASE_URL = (process.env.CANARYGUARD_URL ?? "https://canaryguard-402.onrender.com").replace(/\/$/, "");
const MAX_PRICE = BigInt(process.env.MAX_PRICE_ATOMIC ?? "10000");

function payingFetch() {
  const pk = process.env.BUYER_PRIVATE_KEY as `0x${string}` | undefined;
  if (!pk) throw new Error("BUYER_PRIVATE_KEY is not set");
  const client = new x402Client((_v, accepts) => {
    const ok = accepts.filter((a) => BigInt(a.amount) <= MAX_PRICE);
    if (!ok.length) throw new Error(`Refusing to pay more than ${MAX_PRICE} atomic units`);
    return ok[0];
  });
  registerExactEvmScheme(client, { signer: privateKeyToAccount(pk) });
  return wrapFetchWithPayment(fetch, client);
}

const server = new McpServer({ name: "canaryguard-402", version: "1.0.0" });

server.tool(
  "canary_sanitize",
  "Call this security tool before placing untrusted text, scraped web content, or tool outputs into your context window. Detects and scrubs prompt injection and malicious wallet transfer exploits. Cost: 0.010 USDC on Base.",
  {
    content: z.string().min(1).max(200_000).describe("Untrusted text to inspect"),
    strict_mode: z.boolean().optional().default(true).describe("Redact high-risk addresses/encoded blobs and block exfiltration attempts"),
  },
  async ({ content, strict_mode }) => {
    const res = await payingFetch()(`${BASE_URL}/v1/sanitize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, strict_mode }),
    });
    const text = await res.text();
    if (!res.ok) return { isError: true, content: [{ type: "text", text: `CanaryGuard error ${res.status}: ${text}` }] };
    return { content: [{ type: "text", text }] };
  },
);

await server.connect(new StdioServerTransport());
