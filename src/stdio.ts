import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Input, SERVICE_VERSION, MCP_ENDPOINT_SPECS } from './config.js';
import { sanitizeContent } from './sanitize.js';
import { z } from 'zod';

const mcp = new McpServer({ name: 'canaryguard-402', version: SERVICE_VERSION });
// The local sanitizer and protocol handshake do not need the on-chain/provider
// client graph. Load those modules only if an analysis tool is actually called.
let executor: typeof import('./execution.js') | undefined;

const CANARY_TOOL_DESC = 'Screen untrusted text for known prompt injection patterns. Returns clean, sanitized, or blocked classification, risk score, and detected threat categories. Local stdio execution has no x402 charge. A clean classification is not a guarantee against every attack.';

mcp.registerTool('canary_sanitize', {
  description: CANARY_TOOL_DESC,
  inputSchema: Input.shape,
  annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
}, async (args) => {
  const result = sanitizeContent(args.content, args.strict_mode);
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(result) }],
    structuredContent: result,
  };
});

for (const spec of MCP_ENDPOINT_SPECS) {
  const toolName = spec.operationId === 'sanitizeContent' ? 'canary_sanitize' : spec.operationId;
  if (toolName === 'canary_sanitize') continue;

  const shape: Record<string, z.ZodTypeAny> = {};
  for (const [k, v] of Object.entries<any>(spec.inputSchema?.properties || {})) {
    let zType: z.ZodTypeAny;
    if (v?.type === 'string') zType = z.string();
    else if (v?.type === 'number' || v?.type === 'integer') zType = z.number();
    else if (v?.type === 'boolean') zType = z.boolean();
    else if (v?.type === 'array') zType = z.array(z.any());
    else zType = z.any();

    const desc = v?.description || (
      k.includes('address') ? `EVM or Solana address (e.g. 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) to audit for security risks` :
      k.includes('token') ? `Token contract or symbol to verify for honeypot and liquidity security` :
      k.includes('chain') ? `Target blockchain ecosystem to analyze ('base' or 'solana')` :
      k.includes('content') || k.includes('prompt') || k.includes('text') ? `Untrusted text content or prompt instructions to sanitize before execution` :
      `Parameter '${k}' for ${spec.summary} security analysis`
    );
    zType = zType.describe(desc);
    shape[k] = spec.inputSchema?.required?.includes(k) ? zType : zType.optional();
  }

  const fullDesc = `${spec.description} Local stdio execution uses the same executor as the hosted API and has no x402 charge. Configured upstream providers may impose their own costs or limits. Unavailable evidence returns an error, not example metrics.`;

  mcp.registerTool(
    toolName,
    {
      description: fullDesc,
      inputSchema: shape,
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
    },
    async args => {
      try {
        executor ||= await import('./execution.js');
        const result = await executor.executeEndpoint(spec.path,args);
        return { content:[{type:'text' as const,text:JSON.stringify(result)}],structuredContent:result };
      } catch(error) {
        const known = executor && error instanceof executor.ExecutionError;
        const failure = {error:known ? error.code : 'analysis_unavailable',
          message:known ? error.message : 'Analysis could not be acquired',charged:false};
        return {isError:true,content:[{type:'text' as const,text:JSON.stringify(failure)}],structuredContent:failure};
      }
    }
  );
}

const transport = new StdioServerTransport();
await mcp.connect(transport);
