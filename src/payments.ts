import { createFacilitatorConfig } from '@coinbase/x402';
import { HTTPFacilitatorClient, x402ResourceServer, x402HTTPResourceServer, type FacilitatorClient } from '@x402/core/server';
import { paymentMiddlewareFromHTTPServer } from '@x402/express';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { bazaarResourceServerExtension, declareDiscoveryExtension } from '@x402/extensions/bazaar';
import {
  configuration,
  ENDPOINT_SPECS,
  NETWORK,
  paymentOption,
  ASSET,
  SOLANA_NETWORK,
  SOLANA_USDC_MINT,
  SOLANA_RECIPIENT,
  SOLANA_FEE_PAYER,
} from './config.js';
import { sanitizeContent } from './sanitize.js';

function buildCanary402Teaser(spec: (typeof ENDPOINT_SPECS)[number], config: ReturnType<typeof configuration>) {
  return {
    error: 'payment_required', x402Version: 2, endpoint: spec.path,
    message: 'No analysis has been performed. Supply an exact x402 payment authorization; execution failures are not charged.',
    resource: { url: config.publicUrl + spec.path, description: spec.description, mimeType: 'application/json' },
    accepts: [
      { scheme: 'exact', network: NETWORK, asset: ASSET, amount: spec.amountMicro, maxTimeoutSeconds: 300, payTo: config.payTo, extra: { name: 'USD Coin', version: '2' } },
      { scheme: 'exact', network: SOLANA_NETWORK, asset: SOLANA_USDC_MINT, amount: spec.amountMicro, maxTimeoutSeconds: 300, payTo: SOLANA_RECIPIENT, extra: { name: 'USD Coin (Solana)', version: '2', feePayer: SOLANA_FEE_PAYER } },
    ],
  };
}

export async function createPayments(env = process.env, provided?: FacilitatorClient) {
  const config = configuration(env);
  if (!provided && (!env.CDP_API_KEY_ID || !env.CDP_API_KEY_SECRET)) {
    throw new Error('CDP_API_KEY_ID and CDP_API_KEY_SECRET are required');
  }
  const facilitator = provided || new HTTPFacilitatorClient({
    ...createFacilitatorConfig(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET),
    timeoutMs: 60000,
  });

  const server = new x402ResourceServer(facilitator)
    .register(NETWORK, new ExactEvmScheme())
    .registerExtension(bazaarResourceServerExtension)
    .onAfterSettle(async ({ result, requirements, paymentPayload }) => {
      const r = result as any;
      if (r && typeof r === 'object') {
        r.amount ??= requirements.amount;
        r.resource ??= paymentPayload.resource || { url: config.publicUrl };
      }
    });

  const routesConfig: Record<string, any> = {};
  let primaryDiscovery: any = undefined;

  for (const spec of ENDPOINT_SPECS) {
    const outputSample = spec.path === '/v1/sanitize'
      ? sanitizeContent('Example external text')
      : spec.outputExample;

    const discoveryPost = declareDiscoveryExtension({
      bodyType: 'json',
      input: spec.inputExample,
      inputSchema: spec.inputSchema,
      output: { example: outputSample },
    });

    const discoveryGet = declareDiscoveryExtension({
      input: spec.inputExample,
      inputSchema: spec.inputSchema,
      output: { example: outputSample },
    });

    if (spec.path === '/v1/sanitize') {
      primaryDiscovery = discoveryPost;
    }

    const baseRoute = {
      accepts: [paymentOption(config.payTo, spec.amountMicro)],
      resource: config.publicUrl + spec.path,
      description: spec.description.slice(0, 440),
      mimeType: 'application/json',
      serviceName: 'CanaryGuard 402',
      tags: spec.tags,
      unpaidResponseBody: () => ({
        contentType: 'application/json',
        body: buildCanary402Teaser(spec, config),
      }),
    };

    routesConfig[`POST ${spec.path}`] = { ...baseRoute, extensions: discoveryPost };
    routesConfig[`GET ${spec.path}`] = { ...baseRoute, extensions: discoveryGet };
    routesConfig[`HEAD ${spec.path}`] = { ...baseRoute, extensions: discoveryGet };
  }

  const httpServer = new x402HTTPResourceServer(server, routesConfig);
  await httpServer.initialize();
  const gate = paymentMiddlewareFromHTTPServer(httpServer, undefined, undefined, false);
  return { server, facilitator, config, gate, discovery: primaryDiscovery };
}
