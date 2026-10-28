import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createPaymentWrapper, type WrappedToolResult } from '@x402/mcp';
import { declareDiscoveryExtension } from '@x402/extensions/bazaar';
import type { Request, Response } from 'express';
import type { x402ResourceServer } from '@x402/core/server';
import { Input, inputJsonSchema, paymentOption, SERVICE_VERSION, TOOL_DESCRIPTION, MCP_ENDPOINT_SPECS, SOLANA_NETWORK, NETWORK, isRetiredBaseRecipient } from './config.js';
import { sanitizeContent } from './sanitize.js';
import { fingerprint, paymentIdentity } from './retries.js';
import { sendRevenueAlert } from './alerts.js';
import { z } from 'zod';
import { executeEndpoint, ExecutionError } from './execution.js';
import { executeSolanaPurchase, solanaPaymentRequirements } from './solana_payment.js';
import { configuredJournal, type PaymentJournal } from './payment_journal.js';
import { verifyPaymentOwnership } from './payment_auth.js';

export async function mcpHandler(resourceServer: x402ResourceServer, publicUrl: string, payTo: string, solanaRequest: typeof fetch = fetch,
  execute:typeof executeEndpoint = executeEndpoint, journalOverride?:PaymentJournal) {
  const unchargedFailures=new Set<string>();
  const tools = await Promise.all(MCP_ENDPOINT_SPECS.map(async spec => {
    const toolName = spec.operationId === 'sanitizeContent' ? 'canary_sanitize' : spec.operationId;
    const accepts = await resourceServer.buildPaymentRequirements(paymentOption(payTo, spec.amountMicro));
    const paid = createPaymentWrapper(resourceServer, { accepts, resource: { url: publicUrl + '/mcp', description: spec.description, serviceName: 'CanaryGuard 402' },
      extensions: declareDiscoveryExtension({ toolName, description: spec.description, transport: 'streamable-http', inputSchema: spec.inputSchema, example: spec.inputExample }) });
    const wrappedBase = paid(async (args: Record<string, any>, context: any) => {
      const payment = context.meta?.['x402/payment'];
      let executing=false;
      try {
        if(payment && journal && journal.claim('mcp:'+paymentIdentity(payment),fingerprint({toolName,args}))) throw new Error('payment_operation_already_claimed');
        executing=true;
        const result = await execute(spec.path, args);
        if (payment && journal) journal.prepare('mcp:'+paymentIdentity(payment),result);
        return { content: [{ type: 'text' as const, text: JSON.stringify(result) }], structuredContent: result };
      } catch (error) {
        if(executing && payment && error instanceof ExecutionError) {
          journal?.releaseUnacquired('mcp:'+paymentIdentity(payment));
          unchargedFailures.add(paymentIdentity(payment));
        }
        // The payment wrapper does not settle thrown execution failures.
        throw error;
      }
    });
    const wrapped = async (args: Record<string,any>, extra: any): Promise<WrappedToolResult> => {
      const payment = extra._meta?.['x402/payment'];
      if (payment?.accepted?.network === SOLANA_NETWORK) {
        let settling = false, executing = false;
        try {
          const { result, receipt } = await executeSolanaPurchase(payment, publicUrl + '/mcp', spec.amountMicro,
            () => execute(spec.path,args), {
              verified: () => { if (journal?.claim('mcp:'+paymentIdentity(payment),fingerprint({toolName,args}))) throw Error('payment_operation_already_claimed'); executing=true; },
              acquired: result => journal?.prepare('mcp:'+paymentIdentity(payment),result),
              settling: () => { settling = true; },
            }, solanaRequest);
          return { content:[{type:'text',text:JSON.stringify(result)}], structuredContent:result, _meta:{'x402/payment-response':receipt} };
        } catch (error) {
          if(executing && !settling && error instanceof ExecutionError) {
            journal?.releaseUnacquired('mcp:'+paymentIdentity(payment));
            unchargedFailures.add(paymentIdentity(payment));
          }
          const details = error instanceof ExecutionError && !settling
            ? { error:error.code, charged:false }
            : { error:settling ? 'settlement_unconfirmed' : 'payment_verification_unavailable', charged:settling ? 'unknown' : false,
                retry:'Reuse the original authorization; do not authorize another payment while settlement is uncertain' };
          return { isError:true,content:[{type:'text',text:JSON.stringify(details)}],structuredContent:details };
        }
      }
      const result = await wrappedBase(args,extra);
      // Base SDK wrapper supplies the standard MCP challenge envelope. Add the
      // independently verified Solana rail handled above to that same quote.
      if (!payment && result.isError && Array.isArray((result.structuredContent as any)?.accepts)) {
        const existing = result.structuredContent as any;
        const challenge = { ...existing, accepts:[...existing.accepts.filter((quote: any)=>quote.network !== SOLANA_NETWORK),solanaPaymentRequirements(spec.amountMicro)] };
        result.structuredContent = challenge;
        result.content = [{type:'text',text:JSON.stringify(challenge)}];
      }
      return result;
    };
    return { spec, toolName, wrapped };
  }));
  const journal = journalOverride ?? configuredJournal();
  const cache = new Map<string, { argsHash: string; result: Promise<WrappedToolResult>; pending: boolean; expires: number }>();
  return async (req: Request, res: Response) => {
    const mcp = new McpServer({ name: 'canaryguard-402', version: SERVICE_VERSION });
    for (const { spec, toolName, wrapped } of tools) {
      const shape: Record<string, z.ZodTypeAny> = {};
      for (const [key, value] of Object.entries<any>(spec.inputSchema?.properties || {})) {
        let type: z.ZodTypeAny = value.type === 'string' ? z.string() : value.type === 'boolean' ? z.boolean() : value.type === 'number' || value.type === 'integer' ? z.number() : value.type === 'array' ? z.array(z.any()) : z.any();
        if (value.minLength) type = z.string().min(value.minLength);
        if (value.maxLength) type = (type as z.ZodString).max(value.maxLength);
        shape[key] = spec.inputSchema?.required?.includes(key) ? type : type.optional();
      }
      mcp.registerTool(toolName, { description: `${spec.description} Price: ${spec.priceUsd} USDC on Base or Solana.`, inputSchema: spec.path === '/v1/sanitize' ? Input.shape : shape,
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true } }, async (args: any, extra: any) => {
        const payment = extra._meta?.['x402/payment'];
        if (!payment) return wrapped(args, extra);
        if(!await verifyPaymentOwnership(payment)) return {isError:true,content:[{type:'text' as const,text:'invalid_payment_ownership'}]};
        const key = paymentIdentity(payment), argsHash = fingerprint({ toolName, args });
        const previous = cache.get(key);
        if (previous) {
          if (previous.argsHash !== argsHash) return { isError: true, content: [{ type: 'text' as const, text: 'payment_request_conflict' }] };
          return previous.result;
        }
        if (cache.size >= 512) {
          const completed = [...cache].find(([,row])=>!row.pending);
          if(completed && (journal || completed[1].expires < Date.now())) cache.delete(completed[0]);
        }
        if (cache.size >= 512) return { isError: true, content: [{ type: 'text' as const, text: 'payment_capacity_exceeded' }] };
        if (journal) {
          try {
            const saved = journal.get('mcp:'+key);
            if(saved) {
              if(saved.request_hash !== argsHash) return {isError:true,content:[{type:'text' as const,text:'payment_request_conflict'}]};
              if(saved.phase !== 'completed' || !saved.result) return {isError:true,content:[{type:'text' as const,text:'payment_reconciliation_required'}]};
              return JSON.parse(saved.result);
            }
          } catch { return {isError:true,content:[{type:'text' as const,text:'payment_journal_unavailable'}]}; }
        }
        if(payment.accepted?.network===NETWORK&&(isRetiredBaseRecipient(payment.accepted?.payTo)||isRetiredBaseRecipient(payment.payload?.authorization?.to))) {
          return {isError:true,content:[{type:'text' as const,text:'retired_recipient_authorization'}],structuredContent:{error:'retired_recipient_authorization',charged:false}};
        }
        const result = Promise.resolve(wrapped(args, extra));
        const row = { argsHash, result, pending: true, expires: Date.now() + 600000 };
        cache.set(key, row);
        result.then(value => {
          row.pending = false;
          if(unchargedFailures.delete(key)) { if(cache.get(key)===row) cache.delete(key); return; }
          const receipt = value._meta?.['x402/payment-response'] as any;
          if (!value.isError && receipt?.success === true) {
            if (journal) { try { journal.complete('mcp:'+key,value); } catch { /* Pending claim remains locked. */ } }
            if (receipt.transaction) sendRevenueAlert(receipt.payer || 'mcp-client', receipt.transaction);
          }
          // Keep unsuccessful/uncertain attempts in memory cache too: a timeout is not permission to charge again.
        }, () => { row.pending = false; if(unchargedFailures.delete(key)&&cache.get(key)===row) cache.delete(key); });
        return result;
      });
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.once('close', () => { void transport.close(); void mcp.close(); });
    await mcp.connect(transport);
    await transport.handleRequest(req, res, req.body);
  };
}
