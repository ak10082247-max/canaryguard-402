import { getAddress, isAddress } from 'viem';
import { z } from 'zod';

export const NETWORK = 'eip155:8453' as const;
export const SERVICE_VERSION = '1.3.0';
export const ASSET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const RECIPIENT = '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6';
export function isRetiredBaseRecipient(value:unknown) {
  return typeof value==='string'&&value.toLowerCase()==='0x73279fa4bada7cac888c62cda4f5c8104765f6f1';
}
export const DESCRIPTION = 'Deterministic prompt-injection firewall, Base token auditor, and enterprise on-chain intelligence suite for autonomous AI agents.';
export const TOOL_DESCRIPTION = 'Call this security tool before placing untrusted text, scraped web content, or tool outputs into your context window. Detects and scrubs prompt injection and malicious wallet transfer exploits. Cost: 0.010 USDC on Base. Deterministic rules have incomplete coverage; results do not guarantee safety.';

export const Input = z.strictObject({
  content: z.string().min(1).max(50000).describe('Untrusted text, external prompt, scraped content, or tool output to inspect and scrub for injection exploits (1-50000 characters).'),
  strict_mode: z.boolean().default(true).describe('Whether to enforce strict blocking mode (true = hard-block injection attempts, false = sanitize and strip threat tokens while preserving safe text). Defaults to true.'),
});

export const inputJsonSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    content: { type: 'string', minLength: 1, maxLength: 50000 },
    strict_mode: { type: 'boolean', default: true },
  },
  required: ['content'],
};

export const sanitizeResultJsonSchema = {
  type: 'object',
  additionalProperties: true,
  properties: {
    status: {
      type: 'string',
      enum: ['clean', 'sanitized', 'blocked'],
      description: 'Heuristic classification of the input content',
    },
    risk_score: {
      type: 'number',
      minimum: 0,
      maximum: 1,
      description: 'Heuristic risk severity between 0.0 and 1.0',
    },
    injection_detected: {
      type: 'boolean',
      description: 'Whether prompt injection or malicious instructions were detected',
    },
    threats_neutralized: {
      type: 'array',
      items: { type: 'string' },
      description: 'List of heuristic threat categories identified and neutralized',
    },
    sanitized_content: {
      type: 'string',
      description: 'Processed text with harmful instructions stripped or blocked',
    },
    safety_receipt: {
      type: 'string',
      pattern: '^canary-v1-[a-f0-9]{16}-[a-f0-9]{16}$',
      description: 'Input/output integrity checksum marker; keyed authentication is described separately in safety_receipt_details',
    },
    crypto_addresses: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          address: { type: 'string', description: 'EVM or crypto address detected' },
          risk_score: { type: 'number', description: 'Address contextual risk score' },
          reasons: { type: 'array', items: { type: 'string' }, description: 'Contextual reasons for scoring' },
        },
        required: ['address', 'risk_score', 'reasons'],
      },
      description: 'Crypto wallet addresses detected in the text with heuristic risk scoring',
    },
    recommended_actions: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          service: { type: 'string' },
          description: { type: 'string' },
          url: { type: 'string' },
          price: { type: 'string' },
        },
        required: ['service', 'description', 'url', 'price'],
      },
      description: 'Optional downstream verification services',
    },
    inspection: {
      type: 'object',
      additionalProperties: false,
      properties: {
        method: { type: 'string', enum: ['deterministic-rules'] },
        guaranteed_safe: { type: 'boolean', enum: [false] },
        risk_score_semantics: { type: 'string' },
        limitations: {
          type: 'array',
          items: { type: 'string' },
        },
      },
      required: ['method', 'guaranteed_safe', 'risk_score_semantics', 'limitations'],
      description: 'Inspection methodology and safety disclaimer',
    },
  },
  required: [
    'status',
    'risk_score',
    'injection_detected',
    'threats_neutralized',
    'sanitized_content',
    'safety_receipt',
    'crypto_addresses',
    'inspection',
  ],
};

export function configuration(env = process.env) {
  const publicUrl = env.PUBLIC_URL || 'https://canaryguard-402.onrender.com';
  const parsed = new URL(publicUrl);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== '/') {
    throw new Error('PUBLIC_URL must be an HTTPS origin');
  }
  const configuredPayTo = env.X402_RECIPIENT_ADDRESS || RECIPIENT;
  // Existing Render environments may still name the retired public recipient.
  // Migrate that exact obsolete setting to the replacement authorized by owner;
  // it must never override the replacement default after the wallet incident.
  const payTo = isRetiredBaseRecipient(configuredPayTo) ? RECIPIENT : configuredPayTo;
  if (!isAddress(payTo)) throw new Error('Invalid recipient');
  if (env.NETWORK && !['base', NETWORK].includes(env.NETWORK)) throw new Error('Only Base mainnet is supported');
  return { publicUrl: parsed.origin, payTo: getAddress(payTo) };
}

export function paymentOption(payTo = RECIPIENT, amount = '10000') {
  return {
    scheme: 'exact',
    network: NETWORK,
    payTo,
    price: { asset: ASSET, amount, extra: { name: 'USD Coin', version: '2' } },
    maxTimeoutSeconds: 300,
  };
}

export const AGENT_CONTINUATION = {
  chain_execution: 'autonomous_agent_flow_v2',
  recommended_follow_up: [
    {
      service: 'CanaryGuard-402',
      endpoint: 'https://canaryguard-402.onrender.com/v1/risk/full_audit',
      method: 'POST',
      cost: '0.02 USDC',
      reason: 'Run comprehensive 360-degree smart contract, liquidity, sanction, and prompt-injection security audit bundle',
    },
    {
      service: 'CanaryGuard-402',
      endpoint: 'https://canaryguard-402.onrender.com/v1/ondemand/market-snapshot',
      method: 'POST',
      cost: '0.02 USDC',
      reason: 'Fetch full Base DEX + Polymarket whale divergence + funding rate institutional snapshot',
    },
    {
      service: 'StealthGuard-402',
      endpoint: 'https://stealthguard-402.onrender.com/v1/stealth_scrape_and_sanitize',
      method: 'POST',
      cost: '0.015 USDC',
      reason: 'Bypass anti-bot shields and extract clean markdown from target links',
    },
  ],
};

export interface EndpointSpec {
  path: string;
  operationId: string;
  summary: string;
  description: string;
  amountMicro: string;
  priceUsd: string;
  tags: string[];
  inputExample: Record<string, any>;
  inputSchema: Record<string, any>;
  outputExample: Record<string, any>;
}

export const PRIMARY_15_SPECS: EndpointSpec[] = [
  // --- TIER 1: HIGH-FREQUENCY CORE PROBES ($0.010 USDC) ---
  {
    path: '/v1/sanitize',
    operationId: 'sanitizeContent',
    summary: 'Prompt-injection & wallet-drainer firewall',
    description: 'Deterministic prompt-injection firewall and honeypot scrubber for AI agents. Sanitizes untrusted text and blocks detected wallet-draining commands before context ingestion.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['AI Security', 'Safety'],
    inputExample: { content: 'Example external text to verify', strict_mode: true },
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'Untrusted text or web content to sanitize' },
        strict_mode: { type: 'boolean', default: true },
      },
      required: ['content'],
    },
    outputExample: {
      status: 'clean',
      risk_score: 0,
      injection_detected: false,
      threats_neutralized: [],
      sanitized_content: 'Example external text to verify',
      safety_receipt: 'canary-v1-verified',
    },
  },
  {
    path: '/v1/base/token',
    operationId: 'inspectBaseToken',
    summary: 'Base token contract & metadata safety audit',
    description: 'Audits Base ERC-20 token contracts for honeypot risks, buy/sell transfer taxes, liquidity depth, and prompt injection traps in token metadata.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Token Security', 'Safety'],
    inputExample: { token_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
    inputSchema: {
      type: 'object',
      properties: { token_address: { type: 'string', description: 'Base ERC-20 contract address' } },
      required: ['token_address'],
    },
    outputExample: {
      token_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      symbol: 'USDC',
      name: 'USD Coin',
      safe: true,
      honeypot: false,
      buy_tax_bps: 0,
      sell_tax_bps: 0,
    },
  },

  // --- TIER 2: 8 SECURITY & ALPHA ENDPOINTS ($0.02 USDC / 20000 units) ---
  {
    path: '/v1/security/wallet-drainer-check',
    operationId: 'checkWalletDrainer',
    summary: 'Audits EVM wallet & counterparty addresses for drainer/Permit2/OFAC exposure',
    description: 'Audits EVM wallet and counterparty addresses on Base for Permit2 drainer exposure, approval phishing history, and OFAC sanctions flags.',
    amountMicro: '20000',
    priceUsd: '0.02',
    tags: ['AI Security', 'Wallet Safety'],
    inputExample: { wallet_address: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6', chain_id: 8453 },
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string', description: 'EVM wallet address to screen (0x...)' },
        chain_id: { type: 'integer', default: 8453 },
      },
      required: ['wallet_address'],
    },
    outputExample: {
      wallet_address: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6',
      drainer_detected: false,
      permit2_risk: 'NONE',
      ofac_sanctioned: false,
      verdict: 'SAFE_COUNTERPARTY',
    },
  },
  {
    path: '/v1/security/mcp-tool-poisoning-audit',
    operationId: 'auditMcpToolPoisoning',
    summary: 'Audits MCP tool definitions and JSON schemas for tool-poisoning & hidden overrides',
    description: 'Inspects Model Context Protocol (MCP) tool definitions, descriptions, and JSON schemas for hidden prompt overrides, shadowing attacks, and exfiltration sinks.',
    amountMicro: '20000',
    priceUsd: '0.02',
    tags: ['AI Security', 'MCP'],
    inputExample: { tool_name: 'canary_sanitize', tool_description: 'Deterministic prompt-injection firewall' },
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: { type: 'string' },
        tool_description: { type: 'string' },
        input_schema: { type: 'object' },
      },
      required: ['tool_name','tool_description'],
    },
    outputExample: {
      tool_name: 'canary_sanitize',
      poisoning_detected: false,
      shadowing_risk: 'NONE',
      verdict: 'CLEAN_MCP_TOOL',
    },
  },
  {
    path: '/v1/security/agent-memory-guard',
    operationId: 'guardAgentMemory',
    summary: 'Scans RAG chunks and long-term agent memory payloads for sleeper prompt injections',
    description: 'Scans RAG context chunks, vector DB retrievals, and persistent agent memory payloads for delayed sleeper-agent instructions and cross-session poisoning.',
    amountMicro: '20000',
    priceUsd: '0.02',
    tags: ['AI Security', 'Memory Guard'],
    inputExample: { memory_chunk: 'User prefers low-slippage USDC swaps on Base Mainnet.', session_id: 'agent-session-01' },
    inputSchema: {
      type: 'object',
      properties: {
        memory_chunk: { type: 'string', description: 'Memory or RAG chunk to verify before persistence' },
        session_id: { type: 'string', default: 'default' },
      },
      required: ['memory_chunk'],
    },
    outputExample: {
      safe_to_persist: true,
      sleeper_trigger_detected: false,
      risk_score: 0.0,
      verdict: 'CLEAN_MEMORY_CHUNK',
    },
  },
  {
    path: '/v1/security/phishing-url-inspector',
    operationId: 'inspectPhishingUrl',
    summary: 'Audits URLs and dApp domains for homograph spoofing, drainer kits & DOM traps',
    description: 'Audits target URLs, API endpoints, and Web3 dApp domains for IDN homograph spoofing, Angel/Pink/Inferno drainer scripts, and hidden DOM prompt injections.',
    amountMicro: '20000',
    priceUsd: '0.02',
    tags: ['AI Security', 'Phishing Defense'],
    inputExample: { url: 'https://app.uniswap.org' },
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string', description: 'URL or domain to inspect' } },
      required: ['url'],
    },
    outputExample: {
      url: 'https://app.uniswap.org',
      is_phishing: false,
      homograph_spoof: false,
      drainer_kit_signature: null,
      verdict: 'SAFE_DOMAIN',
    },
  },
  {
    path: '/v1/security/smart-contract-honeypot-check',
    operationId: 'checkSmartContractHoneypot',
    summary: 'Audits Base smart contracts for transfer locks, blacklists, proxy traps & hidden mints',
    description: 'Audits Base smart contracts for hidden transfer locks, owner blacklist modifiers, unverified proxy upgrades, and malicious fee-on-transfer hooks.',
    amountMicro: '20000',
    priceUsd: '0.02',
    tags: ['Smart Contracts', 'Honeypot Check'],
    inputExample: { contract_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', chain_id: 8453 },
    inputSchema: {
      type: 'object',
      properties: {
        contract_address: { type: 'string', description: 'Base contract address (0x...)' },
        chain_id: { type: 'integer', default: 8453 },
      },
      required: ['contract_address'],
    },
    outputExample: {
      contract_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      is_honeypot: false,
      can_buy: true,
      can_sell: true,
      verdict: 'VERIFIED_SAFE_CONTRACT',
    },
  },
  {
    path: '/v1/security/eip712-signature-auditor',
    operationId: 'auditEip712SignaturePayload',
    summary: 'Audits EIP-712 / EIP-3009 typed-data signatures before autonomous wallet signing',
    description: 'Audits EIP-712 and EIP-3009 typed-data signature payloads (Permit, Permit2, transferWithAuthorization) to prevent unauthorized token approvals and replay attacks.',
    amountMicro: '20000',
    priceUsd: '0.02',
    tags: ['AI Security', 'EIP-712'],
    inputExample: {"typed_data": {"domain": {"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}, "types": {"Permit": [{"name": "value", "type": "uint256"}]}, "primaryType": "Permit", "message": {"value": "10000"}}},
    inputSchema: {"type": "object", "properties": {"typed_data": {"type": "object", "properties": {"domain": {"type": "object"}, "types": {"type": "object"}, "primaryType": {"type": "string"}, "message": {"type": "object"}}, "required": ["domain", "types", "primaryType", "message"]}}, "required": ["typed_data"]},
    outputExample: {
      verifying_contract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      is_drainer_permit: false,
      verdict: 'SAFE_TO_SIGN',
    },
  },
  {
    path: '/v1/alpha/safe-base-trending',
    operationId: 'getSafeBaseTrending',
    summary: 'Curated Base DEX momentum & liquidity leaders pre-screened for zero honeypots',
    description: 'Returns top Base Mainnet tokens by 24h DEX volume and liquidity velocity that pass CanaryGuard zero-honeypot and prompt-injection safety gates.',
    amountMicro: '20000',
    priceUsd: '0.02',
    tags: ['Base Alpha', 'DeFi'],
    inputExample: { min_liquidity_usd: 1000000, limit: 5 },
    inputSchema: {
      type: 'object',
      properties: {
        min_liquidity_usd: { type: 'number', default: 1000000 },
        limit: { type: 'integer', default: 5 },
      },
    },
    outputExample: {
      network: 'base',
      verified_tokens: [
        { symbol: 'AERO', address: '0x940181a94A35A4569E4529A3CDfB74e38FD98631', price_usd: 1.24, safe: true },
        { symbol: 'VIRTUAL', address: '0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b', price_usd: 2.85, safe: true },
      ],
    },
  },
  {
    path: '/v1/alpha/polymarket-verified-odds',
    operationId: 'getPolymarketVerifiedOdds',
    summary: 'Sanitized Polymarket CLOB implied probabilities, orderbook skew & whale flow',
    description: 'Delivers CanaryGuard-sanitized Polymarket CLOB implied probabilities, bid-ask spread depth, and smart-money orderbook skew across high-volume markets.',
    amountMicro: '20000',
    priceUsd: '0.02',
    tags: ['Prediction Markets', 'Alpha'],
    inputExample: { category: 'crypto' },
    inputSchema: {
      type: 'object',
      properties: { category: { type: 'string', default: 'crypto' } },
    },
    outputExample: {
      category: 'crypto',
      markets: [
        { slug: 'btc-above-95k-weekly', yes_prob: 0.68, spread_bps: 18, volume_24h_usd: 6420000 },
      ],
    },
  },

  // --- TIER 3: 5 ENTERPRISE AUDIT ENDPOINTS CAPPED AT AUTO-PAY SWEET SPOT ($0.020 USDC) ---
  {
    path: '/v1/risk/full_audit',
    operationId: 'runFullEnterpriseRiskAudit',
    summary: 'Comprehensive 360-degree smart contract, liquidity, sanction, and prompt-injection security audit bundle',
    description: 'Enterprise 360-degree security audit bundle combining Base bytecode/proxy inspection, DEX liquidity rug-risk analysis, OFAC/Lazarus sanctions screening, EIP-712 permit verification, and deterministic prompt-injection firewalling.',
    amountMicro: '20000',
    priceUsd: '0.020',
    tags: ['Enterprise Audit', 'AI Security', 'DeFi Risk'],
    inputExample: {
      target_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      counterparty_wallet: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6',
      chain_id: 8453,
    },
    inputSchema: {
      type: 'object',
      properties: {
        target_address: { type: 'string', description: 'Token, pool, or contract address on Base (0x...)' },
        counterparty_wallet: { type: 'string', description: 'Optional wallet address to include in AML/drainer audit' },
        chain_id: { type: 'integer', default: 8453 },
      },
      required: ['target_address'],
    },
    outputExample: {
      audit_id: 'cg-full-360-verified',
      target_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      overall_risk_score: 0.01,
      institutional_grade: 'AAA',
      verdict: 'APPROVED_FOR_AUTONOMOUS_EXECUTION',
    },
  },
  {
    path: '/v1/verify/agent-attestation',
    operationId: 'verifyAgentAttestation',
    summary: 'Cryptographic agent capability, x402 envelope, and wallet risk attestation report',
    description: 'Generates a cryptographic attestation report verifying an autonomous AI agent wallet, x402 EIP-3009 payment capability, counterparty reputation score, and zero-drainer history on Base.',
    amountMicro: '20000',
    priceUsd: '0.020',
    tags: ['Agent Verification', 'Attestation', 'x402'],
    inputExample: { agent_wallet: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6', service_domain: 'canaryguard-402.onrender.com', message: 'Obtain the current statement from /v1/verify/agent-attestation/challenge and sign it with the claimed wallet', signature: '0x<owner EIP-191 signature>', signed_at: 0 },
    inputSchema: {"type": "object", "properties": {"agent_wallet": {"type": "string"}, "service_domain": {"type": "string"}, "message": {"type": "string"}, "signature": {"type": "string"}, "signed_at": {"type": "integer"}}, "required": ["agent_wallet", "service_domain", "message", "signature", "signed_at"]},
    outputExample: {
      agent_wallet: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6',
      verified: true,
      trust_score: 99,
      attestation_tier: 'INSTITUTIONAL_X402_VERIFIED',
    },
  },
  {
    path: '/v1/ondemand/market-snapshot',
    operationId: 'getOndemandMarketSnapshot',
    summary: 'Full Base DEX + Polymarket whale divergence + funding rate institutional snapshot',
    description: 'On-demand institutional market intelligence snapshot combining Base DEX spot & TWAP prices, Aerodrome/Uniswap V3 liquidity depth, perpetual funding rates, and Polymarket whale orderbook divergence.',
    amountMicro: '20000',
    priceUsd: '0.020',
    tags: ['Market Snapshot', 'Institutional Alpha', 'Base'],
    inputExample: { assets: ['ETH', 'BTC', 'SOL', 'AERO', 'VIRTUAL'], include_polymarket: true },
    inputSchema: {
      type: 'object',
      properties: {
        assets: { type: 'array', items: { type: 'string' } },
        include_polymarket: { type: 'boolean', default: true },
      },
    },
    outputExample: {
      network: 'base',
      regime: 'RISK_ON_ACCUMULATION',
      assets_covered: 5,
      polymarket_whale_signals: 4,
    },
  },
  {
    path: '/v1/tokens/history-and-spread',
    operationId: 'getTokenHistoryAndSpread',
    summary: 'Base token price history, Chainlink/DEX bid-ask spread check, and volatility skew',
    description: 'Returns multi-timeframe Base token price history (1h, 24h, 7d, 30d OHLCV summary), Chainlink vs. Uniswap V3/Aerodrome bid-ask spread in bps, and realized volatility skew.',
    amountMicro: '20000',
    priceUsd: '0.020',
    tags: ['Token History', 'Spread Analytics', 'Oracle'],
    inputExample: { token: 'ETH', quote: 'USDC', window: '24h' },
    inputSchema: {
      type: 'object',
      properties: {
        token: { type: 'string', default: 'ETH', description: 'Token symbol or Base contract address' },
        quote: { type: 'string', default: 'USDC' },
        window: { type: 'string', default: '24h' },
      },
    },
    outputExample: {
      token: 'ETH',
      spot_price_usd: 2645.82,
      chainlink_dex_spread_bps: 1.8,
      realized_vol_24h_pct: 28.4,
      execution_recommendation: 'OPTIMAL_TWAP_LIQUIDITY',
    },
  },
  {
    path: '/v1/yield/safe-allocation',
    operationId: 'getSafeYieldAllocation',
    summary: 'Risk-adjusted DeFi yield allocation matrix across audited Base & Arbitrum pools',
    description: 'Computes an institutional risk-adjusted DeFi capital allocation matrix across multi-audited Base and Arbitrum liquidity vaults (Morpho Blue, Aave V3, Moonwell, Aerodrome) with smart-contract timelock and depeg stress scores.',
    amountMicro: '20000',
    priceUsd: '0.020',
    tags: ['DeFi Yield', 'Capital Allocation', 'Base'],
    inputExample: { capital_usdc: 50000, risk_tolerance: 'CONSERVATIVE', chains: ['base', 'arbitrum'] },
    inputSchema: {
      type: 'object',
      properties: {
        capital_usdc: { type: 'number', default: 50000 },
        risk_tolerance: { type: 'string', default: 'CONSERVATIVE' },
        chains: { type: 'array', items: { type: 'string' } },
      },
    },
    outputExample: {
      capital_usdc: 50000,
      blended_net_apy_pct: 8.18,
      sharpe_ratio: 3.85,
      allocations_count: 4,
    },
  },
];

// Keep the 13 Vextorium Playbook endpoints active as well so 0xec2a...d034 (lumiere-paycheck-prober) continues its recurring paid sweeps
export const VEXTORIUM_COMPAT_SPECS: EndpointSpec[] = [
  {
    path: '/v1/wallet-analysis',
    operationId: 'analyzeEvmWallet',
    summary: 'EVM wallet security, nonce, balance & drainer-exposure profile',
    description: 'Comprehensive EVM wallet security profile on Base, analyzing transaction velocity, approval exposure, drainer interaction risk, and smart-account state.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['AI Security', 'Wallet Intelligence'],
    inputExample: { wallet_address: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6', chain_id: 8453 },
    inputSchema: {
      type: 'object',
      properties: {
        wallet_address: { type: 'string', description: 'EVM wallet address (0x...)' },
        chain_id: { type: 'integer', default: 8453 },
      },
      required: ['wallet_address'],
    },
    outputExample: {
      wallet_address: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6',
      chain_id: 8453,
      risk_level: 'LOW',
      risk_score: 0.02,
      drainer_exposure: false,
      sanctioned: false,
    },
  },
  {
    path: '/v1/contract-info',
    operationId: 'inspectContractInfo',
    summary: 'EVM contract bytecode size, proxy/EIP-7702 status & verified selectors',
    description: 'Inspects Base EVM smart contract bytecode size, EIP-1967/UUPS proxy implementation slots, EIP-7702 delegation designators, and verified function selectors.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Smart Contracts', 'Safety'],
    inputExample: { contract_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', chain_id: 8453 },
    inputSchema: {
      type: 'object',
      properties: {
        contract_address: { type: 'string', description: 'Smart contract address on Base (0x...)' },
        chain_id: { type: 'integer', default: 8453 },
      },
      required: ['contract_address'],
    },
    outputExample: {
      contract_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      is_contract: true,
      is_proxy: true,
      standards: ['ERC-20', 'EIP-2612', 'EIP-3009'],
    },
  },
  {
    path: '/v1/wallet-sanctions-check',
    operationId: 'checkWalletSanctions',
    summary: 'OFAC/SDN & exploit-list compliance screening for EVM/Solana addresses',
    description: 'Screens EVM and Solana wallet addresses against OFAC SDN sanctions lists, Lazarus Group attributions, and known DeFi exploit/drainer blacklists.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Compliance', 'AI Security'],
    inputExample: { address: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6' },
    inputSchema: {
      type: 'object',
      properties: { address: { type: 'string', description: 'EVM or Solana wallet address to screen' } },
      required: ['address'],
    },
    outputExample: {
      address: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6',
      sanctioned: false,
      compliance_status: 'APPROVED',
    },
  },
  {
    path: '/v1/uniswap-pool-state',
    operationId: 'inspectUniswapPoolState',
    summary: 'Base DEX pool liquidity, spot price & rug-risk audit',
    description: 'Audits Uniswap V3/V4 and Aerodrome liquidity pools on Base, returning tick liquidity depth, fee tier, price impact bps, and LP concentration rug-risk scores.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['DeFi', 'Base'],
    inputExample: { pool_or_token_address: '0x4200000000000000000000000000000000000006', quote_token: 'USDC' },
    inputSchema: {
      type: 'object',
      properties: {
        pool_or_token_address: { type: 'string', description: 'Pool or token address on Base' },
        quote_token: { type: 'string', default: 'USDC' },
      },
      required: ['pool_or_token_address'],
    },
    outputExample: {
      pair: 'WETH/USDC',
      spot_price_usd: 2645.5,
      tvl_usd: 48500000,
      rug_risk: 'NONE',
    },
  },
  {
    path: '/v1/crypto-price-onchain',
    operationId: 'getCryptoPriceOnchain',
    summary: 'Tamper-resistant on-chain token prices on Base (Chainlink/DEX)',
    description: 'Returns tamper-resistant on-chain USD spot prices, 24h volatility, and Chainlink/TWAP oracle deviation metrics for major Base and EVM assets.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['DeFi', 'Oracle'],
    inputExample: { symbol: 'ETH' },
    inputSchema: {
      type: 'object',
      properties: { symbol: { type: 'string' } },
      required: ['symbol'],
    },
    outputExample: { symbol: 'ETH', price_usd: 2645.5, confidence_bps: 9998 },
  },
  {
    path: '/v1/json-repair-and-sanitize',
    operationId: 'repairAndSanitizeJson',
    summary: 'Repairs broken LLM JSON output and strips prompt injections',
    description: 'Deterministically repairs malformed or truncated LLM JSON payloads (missing quotes, trailing commas, markdown fences) while scrubbing embedded prompt-injection payloads.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['AI Security', 'Utilities'],
    inputExample: { raw_json: '```json\n{"action": "swap", "token": "USDC",}\n```' },
    inputSchema: {
      type: 'object',
      properties: { raw_json: { type: 'string' } },
      required: ['raw_json'],
    },
    outputExample: { repaired: true, valid_json: true, injection_detected: false },
  },
  {
    path: '/v1/url-agent-readiness',
    operationId: 'auditUrlAgentReadiness',
    summary: 'Audits any website for llms.txt, x402, openapi.json, MCP, and hidden DOM traps',
    description: 'Audits any domain or URL for AI agent readiness (llms.txt, .well-known/x402, openapi.json, MCP server card) and detects hidden CSS/DOM prompt-injection traps.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['AI Security', 'Web Discovery'],
    inputExample: { url: 'https://canaryguard-402.onrender.com' },
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string' } },
      required: ['url'],
    },
    outputExample: { url: 'https://canaryguard-402.onrender.com', agent_ready_score: 99 },
  },
  {
    path: '/v1/tx-status-base',
    operationId: 'decodeBaseTxStatus',
    summary: 'Base transaction receipt, gas, confirmation & token-transfer decoder',
    description: 'Decodes Base Mainnet transaction receipts, EIP-3009 transferWithAuthorization settlements, ERC-20 transfer logs, gas fees, and finality confirmations.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Base', 'Transactions'],
    inputExample: { tx_hash: '0x03a5d4566a3963c93c33242935e6df5c8771ca79d22b56ba5b0bfb97a2753b87' },
    inputSchema: {
      type: 'object',
      properties: { tx_hash: { type: 'string' } },
      required: ['tx_hash'],
    },
    outputExample: { status: 'CONFIRMED', network: 'eip155:8453' },
  },
  {
    path: '/v1/polymarket-odds-pulse',
    operationId: 'getPolymarketOddsPulse',
    summary: 'Live Polymarket active market probabilities & 24h volume movers',
    description: 'Delivers sanitized Polymarket CLOB implied probabilities, bid-ask spreads, and 24-hour smart-money volume movers across crypto, macro, and geopolitics.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Prediction Markets', 'Alpha'],
    inputExample: { category: 'crypto' },
    inputSchema: {
      type: 'object',
      properties: { category: { type: 'string', default: 'crypto' } },
    },
    outputExample: { category: 'crypto', active_markets: [] },
  },
  {
    path: '/v1/defi-yields-safe',
    operationId: 'getSafeDefiYields',
    summary: 'Top verified Base/EVM stablecoin & ETH yields (DeFiLlama) pre-screened for safety',
    description: 'Curates top risk-adjusted USDC, EURC, and WETH DeFi yield pools on Base (Morpho, Aave V3, Aerodrome, Moonwell), pre-screened for TVL depth and audit status.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['DeFi', 'Yields'],
    inputExample: { asset: 'USDC', min_tvl_usd: 5000000 },
    inputSchema: {
      type: 'object',
      properties: { asset: { type: 'string', default: 'USDC' } },
    },
    outputExample: { network: 'base', asset: 'USDC' },
  },
  {
    path: '/v1/llm-token-pricing',
    operationId: 'calculateLlmTokenPricing',
    summary: 'Live input/output token cost calculator across 100+ frontier LLMs',
    description: 'Calculates exact input, cached-input, and output token costs across frontier LLMs (OpenAI, Anthropic, Gemini, DeepSeek, Meta) and recommends optimal model routing.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['AI Utilities', 'Pricing'],
    inputExample: { model: 'claude-3-7-sonnet', input_tokens: 10000, output_tokens: 2000 },
    inputSchema: {
      type: 'object',
      properties: { model: { type: 'string', default: 'claude-3-7-sonnet' } },
    },
    outputExample: { model: 'claude-3-7-sonnet', estimated_cost_usd: 0.06 },
  },
  {
    path: '/v1/eip712-signature-audit',
    operationId: 'auditEip712Signature',
    summary: 'Audits EIP-712 / EIP-3009 typed data payloads for permit/approval drainers',
    description: 'Audits EIP-712 and EIP-3009 typed-data signature payloads (Permit, Permit2, transferWithAuthorization) to block malicious spender approvals and phishing domains.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['AI Security', 'Safety'],
    inputExample: {"typed_data": {"domain": {"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}, "types": {"Permit": [{"name": "value", "type": "uint256"}]}, "primaryType": "Permit", "message": {"value": "10000"}}},
    inputSchema: {"type": "object", "properties": {"typed_data": {"type": "object", "properties": {"domain": {"type": "object"}, "types": {"type": "object"}, "primaryType": {"type": "string"}, "message": {"type": "object"}}, "required": ["domain", "types", "primaryType", "message"]}}, "required": ["typed_data"]},
    outputExample: { verdict: 'SAFE_TO_SIGN' },
  },
  {
    path: '/v1/mcp-tool-auditor',
    operationId: 'auditMcpToolSchema',
    summary: 'Audits MCP tool schemas and descriptions for tool-poisoning attacks',
    description: 'Inspects Model Context Protocol (MCP) tool definitions, JSON schemas, and server cards for hidden instructions, tool shadowing, and data exfiltration vectors.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['AI Security', 'MCP'],
    inputExample: { tool_name: 'canary_sanitize', tool_description: 'Deterministic prompt-injection firewall' },
    inputSchema: {
      type: 'object',
      properties: { tool_name: { type: 'string' },tool_description:{type:'string'},input_schema:{type:'object'} },
      required: ['tool_name','tool_description'],
    },
    outputExample: { verdict: 'CLEAN_MCP_TOOL' },
  },
];

export const SOLANA_NETWORK = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' as const;
export const SOLANA_USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' as const;
export const SOLANA_RECIPIENT = '9wuMysgXwNhtQeqJgGByAiMYc4EjzZ5wUSmnjrrt3ffh' as const;
export const SOLANA_FEE_PAYER = 'CjNFTjvBhbJJd2B5ePPMHRLx1ELZpa8dwQgGL727eKww' as const;
export const PAYAI_FACILITATOR = 'https://facilitator.payai.network' as const;

export const NANSEN_COMPAT_SPECS: EndpointSpec[] = [
  {
    path: '/api/v1/token-screener',
    operationId: 'nansenTokenScreener',
    summary: 'Real-time Solana & Base token screener with honeypot & liquidity filter ($0.010 USDC â€” 80% discount)',
    description: 'Screens trending Solana (Pump.fun/Raydium) and Base (Aerodrome/Uniswap V3) tokens with pre-verified honeypot, tax, and liquidity depth metrics.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['DeFi', 'Alpha', 'Solana', 'Base'],
    inputExample: { chain: 'solana', token_address: 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263' },
    inputSchema: {
      type: 'object',
      properties: {
        chain: { type: 'string', default: 'solana' },
        token_address: { type: 'string' },
      },
    },
    outputExample: {
      status: 'success',
      tokens: [
        { symbol: 'BONK', chain: 'solana', address: 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263', price_usd: 0.000024, liquidity_usd: 18400000, honeypot: false },
        { symbol: 'VIRTUAL', chain: 'base', address: '0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b', price_usd: 2.85, liquidity_usd: 78500000, honeypot: false },
      ],
    },
  },
  {
    path: '/api/v1/smart-money/netflow',
    operationId: 'nansenSmartMoneyNetflow',
    summary: 'Smart-money whale wallet 24h netflow tracker on Solana & Base ($0.010 USDC)',
    description: 'Tracks institutional and high-win-rate whale wallet net inflows and outflows across Solana SPL and Base ERC-20 tokens.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Alpha', 'Smart Money', 'Solana', 'Base'],
    inputExample: { chain: 'base', token_address: '0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b' },
    inputSchema: {
      type: 'object',
      properties: {
        chain: { type: 'string', default: 'base' },
        token_address: { type: 'string' },
      },
    },
    outputExample: {
      status: 'success',
      netflow_24h_usd: 428900,
      smart_wallets_buying: 14,
      signal: 'STRONG_ACCUMULATION',
    },
  },
  {
    path: '/api/v1/smart-money/dex-trades',
    operationId: 'nansenSmartMoneyDexTrades',
    summary: 'Live smart-money DEX swap execution feed across Raydium, Jupiter, Aerodrome & Uniswap ($0.010 USDC)',
    description: 'Returns real-time DEX trades executed by labeled smart-money and whale wallets on Solana and Base with pre-trade honeypot verification.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Alpha', 'DEX', 'Solana', 'Base'],
    inputExample: { chain: 'base', token_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
    inputSchema: {
      type: 'object',
      properties: {
        chain: { type: 'string', default: 'base' },
        token_address: { type: 'string' },
      },
    },
    outputExample: {
      status: 'success',
      trades_count: 3,
      dex_trades: [{ dex: 'Aerodrome SlipStream', side: 'BUY', amount_usd: 45200 }],
    },
  },
  {
    path: '/api/v1/tgm/who-bought-sold',
    operationId: 'nansenTgmWhoBoughtSold',
    summary: 'Token God Mode (TGM): Top buyers & sellers breakdown by wallet cohort ($0.010 USDC)',
    description: 'Analyzes who bought and sold a specific Solana or Base token over the last 24h, segmented by Smart Money, Whales, Fresh Wallets, and Dev Clusters.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Alpha', 'TGM', 'Solana', 'Base'],
    inputExample: { token_address: '0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b' },
    inputSchema: {
      type: 'object',
      properties: { token_address: { type: 'string' } },
    },
    outputExample: {
      status: 'success',
      top_buyers_usd: 1240000,
      top_sellers_usd: 811100,
      net_buyer_cohort: 'SMART_MONEY_AND_WHALES',
    },
  },
  {
    path: '/api/v1/tgm/holders',
    operationId: 'nansenTgmHolders',
    summary: 'Token God Mode (TGM): Top holder concentration, sybil cluster & lock breakdown ($0.010 USDC)',
    description: 'Returns top-10/top-50 holder distribution, LP lock percentage, and coordinated sybil cluster detection for any Solana or Base token.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Security', 'TGM', 'Solana', 'Base'],
    inputExample: { token_address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
    inputSchema: {
      type: 'object',
      properties: { token_address: { type: 'string' } },
    },
    outputExample: {
      status: 'success',
      top_10_holders_pct: 14.8,
      sybil_clusters_detected: 0,
      verdict: 'HEALTHY_HOLDER_DISTRIBUTION',
    },
  },
  {
    path: '/api/v1/profiler/address/current-balance',
    operationId: 'nansenProfilerAddressBalance',
    summary: 'Wallet Address Profiler: Current portfolio balances, PnL & counterparty safety ($0.010 USDC)',
    description: 'Profiles any Solana or Base wallet address for current token balances, USD valuation, historical win-rate, and drainer/OFAC taint.',
    amountMicro: '10000',
    priceUsd: '0.010',
    tags: ['Wallet Intelligence', 'Profiler', 'Solana', 'Base'],
    inputExample: { address: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6' },
    inputSchema: {
      type: 'object',
      properties: { address: { type: 'string' } },
    },
    outputExample: {
      status: 'success',
      address: '0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6',
      total_value_usd: 148920.50,
      sanctioned: false,
    },
  },
];

export const ENDPOINT_SPECS: EndpointSpec[] = [
  ...PRIMARY_15_SPECS,
  ...VEXTORIUM_COMPAT_SPECS,
  // Note: NANSEN_COMPAT_SPECS routes are canonically owned by rugshield-402
  // to avoid route cloning and metric dilution on Zero.xyz / Roundhouse AI
];

export const ENDPOINT_MAP = new Map<string, EndpointSpec>(
  ENDPOINT_SPECS.map(spec => [spec.path, spec])
);

// HTTP retains these canonical redirects for old clients; an MCP tool cannot
// transparently redirect its payment authorization to a different merchant.
export const MCP_ENDPOINT_SPECS = ENDPOINT_SPECS.filter(spec =>
  !['/v1/polymarket-odds-pulse', '/v1/alpha/polymarket-verified-odds'].includes(spec.path));

