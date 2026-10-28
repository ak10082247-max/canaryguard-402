import { createHash } from 'node:crypto';
import { resolvePublic, fetchPublicPage } from './public_fetch.js';
import { hashTypedData, decodeAbiParameters, parseAbiParameters, verifyMessage, type Address } from 'viem';
import { simulateBuySell } from './swap_simulation.js';
import { Input, ASSET, AGENT_CONTINUATION } from './config.js';
import { sanitizeContent } from './sanitize.js';

export class ExecutionError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}
export type Dependencies = { fetch?: typeof fetch; rpcUrl?: string; now?: () => number };
const unavailable = (message: string): never => { throw new ExecutionError(503, 'analysis_unavailable', message); };
const invalid = (message: string): never => { throw new ExecutionError(400, 'invalid_input', message); };
const text = (raw: any, ...keys: string[]): string => {
  for (const key of keys) if (raw[key] !== undefined) {
    if (typeof raw[key] !== 'string' || !raw[key].trim() || raw[key].length > 50000) invalid(`${key} must be a nonempty string of at most 50000 characters`);
    return raw[key].trim();
  }
  return invalid(`${keys[0]} is required`);
};
const address = (raw: any, ...keys: string[]) => {
  const value = text(raw, ...keys);
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) invalid(`${keys[0]} must be an EVM address`);
  return value;
};
function positive(value: unknown, fallback: number, maximum = 1e12) {
  const n = value === undefined ? fallback : Number(value);
  if (!Number.isFinite(n) || n < 0 || n > maximum) invalid('Invalid numeric input');
  return n;
}
export async function executeEndpoint(path: string, raw: any, deps: Dependencies = {}): Promise<Record<string, any>> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) invalid('JSON object required');
  if (raw.chain_id !== undefined && Number(raw.chain_id) !== 8453) invalid('This endpoint supports Base chain_id 8453');
  const request = deps.fetch || fetch;
  const now = deps.now || Date.now;
  const timestamp = Math.floor(now() / 1000);
  const evidence: any[] = [];
  const json = async (url: string, init: RequestInit = {}) => {
    try {
      const response = await request(url, { ...init, signal: AbortSignal.timeout(12000), redirect: 'error' });
      if (!response.ok) return unavailable(`Upstream returned HTTP ${response.status}`);
      const body = await response.text();
      if (body.length > 16 * 1024 * 1024) return unavailable('Upstream response exceeds size limit');
      const result = JSON.parse(body);
      evidence.push({ source: new URL(url).origin, fetched_at: new Date(now()).toISOString(), sha256: createHash('sha256').update(body).digest('hex') });
      return result;
    } catch (error) {
      if (error instanceof ExecutionError) throw error;
      return unavailable('Provider request failed; no analysis was acquired');
    }
  };
  const rpc = async (method: string, params: unknown[]) => {
    // A failed provider is not evidence that an address, mint, or transaction is absent.
    for (const url of [...new Set([deps.rpcUrl || process.env.BASE_RPC_URL || 'https://mainnet.base.org', 'https://base-rpc.publicnode.com'])]) {
      try {
        const result = await json(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
        if (result.error || !Object.hasOwn(result, 'result')) continue;
        return result.result;
      } catch { /* Try the independent mainnet provider. */ }
    }
    return unavailable(`Base RPC ${method} failed on all providers`);
  };
  const baseBlock = async () => {
    if (await rpc('eth_chainId', []) !== '0x2105') return unavailable('RPC network is not Base mainnet');
    const block = await rpc('eth_blockNumber', []);
    if (typeof block !== 'string' || !/^0x[0-9a-f]+$/i.test(block)) return unavailable('Invalid block evidence');
    return block;
  };
  const call = (to: string, data: string, block: string) => rpc('eth_call', [{ to, data }, block]);
  const tokenDetails = async (token: string, block: string) => {
    const code = await rpc('eth_getCode', [token, block]);
    if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(code)) return unavailable('Invalid bytecode response');
    if (code === '0x') throw new ExecutionError(404, 'contract_not_found', 'No contract code at this Base block');
    const decimalsRaw = await call(token, '0x313ce567', block);
    let decimals: number;
    try { decimals = Number(BigInt(decimalsRaw)); } catch { return unavailable('Token decimals could not be read'); }
    if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) return unavailable('Invalid token decimals');
    const symbolRaw = await call(token, '0x95d89b41', block);
    let symbol: string;
    try { symbol = decodeAbiParameters(parseAbiParameters('string'), symbolRaw)[0]; }
    catch { try { symbol = Buffer.from(symbolRaw.slice(2), 'hex').toString('utf8').replace(/\0/g, ''); } catch { return unavailable('Token symbol could not be read'); } }
    return { code, decimals, symbol };
  };
  const pools = async (token: string) => {
    const result = await json(`https://api.dexscreener.com/token-pairs/v1/base/${token}`);
    if (!Array.isArray(result)) return unavailable('DEX provider returned an invalid pool list');
    return result.filter((p: any) => p.chainId === 'base' && [p.baseToken?.address, p.quoteToken?.address, p.pairAddress].some((a: any) => typeof a === 'string' && a.toLowerCase() === token.toLowerCase()));
  };
  let result: Record<string, any>;
  if (path === '/v1/sanitize') {
    const input = Input.safeParse(raw);
    if (!input.success) invalid('content field is required and must be between 1 and 50000 characters; strict_mode must be boolean');
    result = sanitizeContent(input.data!.content, input.data!.strict_mode);
  } else if (['/v1/mcp-tool-auditor', '/v1/security/mcp-tool-poisoning-audit'].includes(path)) {
    const name = text(raw, 'tool_name'); const description = text(raw, 'tool_description');
    if(raw.input_schema!==undefined&&(!raw.input_schema||typeof raw.input_schema!=='object'||Array.isArray(raw.input_schema))) invalid('input_schema must be a JSON object');
    const schemaText=raw.input_schema===undefined?'{}':JSON.stringify(raw.input_schema);
    if(schemaText.length>50000) invalid('input_schema exceeds 50000 characters');
    const inspections={tool_name:sanitizeContent(name,true),tool_description:sanitizeContent(description,true),input_schema:sanitizeContent(schemaText,true)};
    const sources=Object.entries(inspections).filter(([,inspection])=>inspection.injection_detected).map(([source])=>source);
    result = { tool_name:name,poisoning_detected:sources.length>0,poisoning_sources:sources,
      threats_neutralized:[...new Set(Object.values(inspections).flatMap(inspection=>inspection.threats_neutralized))],
      sanitized_description:inspections.tool_description.sanitized_content,
      sanitized_input_schema:inspections.input_schema.injection_detected?null:raw.input_schema??null,
      verdict:sources.length?'BLOCK_MALICIOUS_MCP_TOOL':'NO_PATTERN_DETECTED',
      coverage:'tool name, description and supplied schema text heuristics; tool execution and schema behavior not attested' };
  } else if (path === '/v1/security/agent-memory-guard') {
    const inspection = sanitizeContent(text(raw, 'memory_chunk', 'content'), true);
    result = { session_id: raw.session_id ?? null, safe_to_persist: inspection.injection_detected ? false : null, sleeper_trigger_detected: inspection.injection_detected,
      threats_neutralized: inspection.threats_neutralized, sanitized_chunk: inspection.sanitized_content, risk_score: inspection.risk_score, verdict: inspection.injection_detected ? 'QUARANTINE_MEMORY_CHUNK' : 'NO_PATTERN_DETECTED' };
  } else if (path === '/v1/json-repair-and-sanitize') {
    const input = text(raw, 'raw_json', 'json', 'content');
    const clean = input.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').replace(/,\s*([}\]])/g, '$1');
    let parsed: any;
    try { parsed = JSON.parse(clean); } catch { return invalid('JSON cannot be repaired by the supported fence/trailing-comma repair'); }
    const inspection = sanitizeContent(JSON.stringify(parsed), true);
    if (inspection.injection_detected) result = { repaired: input !== clean, valid_json: false, injection_detected: true, threats_neutralized: inspection.threats_neutralized, parsed: null, repaired_json_string: '', verdict: 'BLOCKED' };
    else result = { repaired: input !== clean, valid_json: true, injection_detected: false, threats_neutralized: [], parsed, repaired_json_string: JSON.stringify(parsed) };
  } else if (['/v1/eip712-signature-audit', '/v1/security/eip712-signature-auditor'].includes(path)) {
    const payload = raw.typed_data ?? raw;
    if (!payload.domain || !payload.types || !payload.message || typeof payload.primaryType !== 'string') invalid('Complete typed_data with domain, types, primaryType and message is required');
    let digest: string;
    try { digest = hashTypedData(payload); } catch { return invalid('Invalid EIP-712 typed data'); }
    const problems: string[] = [];
    if (Number(payload.domain.chainId) !== 8453) problems.push('wrong_or_missing_chain_id');
    if (!/^0x[0-9a-fA-F]{40}$/.test(payload.domain.verifyingContract || '')) problems.push('missing_verifying_contract');
    for (const field of ['value', 'amount', 'allowed']) {
      const value = payload.message[field];
      if (value === true || (typeof value === 'string' && /^\d+$/.test(value) && BigInt(value) >= (1n << 160n))) problems.push('unlimited_allowance_risk');
    }
    const deadline = payload.message.validBefore ?? payload.message.deadline;
    if (deadline !== undefined && (!/^\d+$/.test(String(deadline)) || Number(deadline) <= timestamp)) problems.push('expired_or_invalid_authorization');
    result = { typed_data_hash: digest, primary_type: payload.primaryType, verifying_contract: payload.domain.verifyingContract ?? null, chain_id: payload.domain.chainId ?? null,
      findings: problems, unlimited_allowance_risk: problems.includes('unlimited_allowance_risk'), domain_separator_authentic: null, verdict: problems.length ? 'REVIEW_REQUIRED' : 'NO_STRUCTURAL_ISSUE_DETECTED', coverage: 'typed-data structure and limits only; signer intent, contract behavior and domain authenticity require separate verification' };
  } else if (['/v1/base/token', '/v1/contract-info', '/v1/wallet-analysis'].includes(path)) {
    const target = path === '/v1/base/token' ? address(raw, 'token_address', 'address', 'token') : path === '/v1/contract-info' ? address(raw, 'contract_address', 'address') : address(raw, 'wallet_address', 'address', 'wallet');
    const block = await baseBlock();
    const code = await rpc('eth_getCode', [target, block]);
    if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(code)) return unavailable('Malformed bytecode response');
    const isContract = code !== '0x';
    if (path === '/v1/wallet-analysis') {
      const [balance, count] = await Promise.all([rpc('eth_getBalance', [target, block]), rpc('eth_getTransactionCount', [target, block])]);
      result = { wallet_address: target, chain_id: 8453, network: 'eip155:8453', block_number: block, balance_wei: balance, transaction_count_hex: count, account_type: isContract ? 'CONTRACT' : 'EOA_OR_EMPTY', risk_score: null, security_profile: null, safety_status: 'NOT_ASSESSED' };
    } else if (path === '/v1/contract-info') {
      const slot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
      const implementation = isContract ? await rpc('eth_getStorageAt', [target, slot, block]) : null;
      const selectors = new Set<string>(); const opcodes: number[] = []; const bytes = Buffer.from(code.slice(2), 'hex');
      for (let i = 0; i < bytes.length; i++) { const op = bytes[i]; opcodes.push(op); if (op === 0x63 && i + 4 < bytes.length) selectors.add('0x' + bytes.subarray(i + 1, i + 5).toString('hex')); if (op >= 0x60 && op <= 0x7f) i += op - 0x5f; }
      result = { contract_address: target, chain_id: 8453, network: 'base', block_number: block, is_contract: isContract, bytecode_size_bytes: bytes.length, bytecode_sha256: createHash('sha256').update(bytes).digest('hex'),
        eip1967_implementation_slot: implementation, proxy_implementation: typeof implementation === 'string' && !/^0x0+$/.test(implementation) ? '0x' + implementation.slice(-40) : null,
        detected_push4_selectors: [...selectors], selfdestruct_opcode_present: opcodes.includes(0xff), delegatecall_opcode_present: opcodes.includes(0xf4), safety_status: 'NOT_ASSESSED' };
    } else {
      const token = await tokenDetails(target, block); const rows = await pools(target);
      result = { token_address: target, network: 'base', chain_id: 8453, block_number: block, symbol: token.symbol, decimals: token.decimals, is_contract: true,
        pools: rows.map((p: any) => ({ address: p.pairAddress, dex: p.dexId, base_token: p.baseToken, quote_token: p.quoteToken, liquidity_usd: p.liquidity?.usd ?? null, base_token_price_usd: p.priceUsd ?? null })), safe: null, honeypot: null, buy_tax_bps: null, sell_tax_bps: null, risk_score: null, safety_status: 'SIMULATION_NOT_PERFORMED' };
    }
  } else if (path === '/v1/tx-status-base') {
    const hash = text(raw, 'tx_hash', 'hash', 'transaction');
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) invalid('tx_hash must be a 32-byte hash');
    await baseBlock(); const receipt = await rpc('eth_getTransactionReceipt', [hash]);
    if (receipt === null) result = { tx_hash: hash, network: 'eip155:8453', status: 'NOT_MINED_OR_NOT_FOUND', finality: null };
    else {
      if (!receipt || receipt.transactionHash?.toLowerCase() !== hash.toLowerCase() || !['0x0', '0x1'].includes(receipt.status)) return unavailable('Malformed transaction receipt');
      result = { tx_hash: hash, network: 'eip155:8453', status: receipt.status === '0x1' ? 'CONFIRMED' : 'REVERTED', finality: 'MINED_L2', block_number: receipt.blockNumber, receipt };
    }
  } else if (path === '/v1/crypto-price-onchain') {
    const symbol = text(raw, 'symbol', 'asset', 'token').toUpperCase();
    const feeds: Record<string, string> = { ETH: '0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70', WETH: '0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70', BTC: '0x64c911996D3c6aC71f9b455B1E8E7266BcbD848F', CBBTC: '0x64c911996D3c6aC71f9b455B1E8E7266BcbD848F' };
    const feed = feeds[symbol]; if (!feed) invalid('No configured on-chain feed for this asset');
    const block = await baseBlock(); const data = await call(feed, '0xfeaf968c', block); const decimals = Number(BigInt(await call(feed, '0x313ce567', block)));
    let round: readonly [bigint, bigint, bigint, bigint, bigint];
    try { round = decodeAbiParameters(parseAbiParameters('uint80,int256,uint256,uint256,uint80'), data); } catch { return unavailable('Invalid oracle round response'); }
    const [roundId, answer, , updatedAt, answeredInRound] = round;
    if (answer <= 0n || updatedAt <= 0n || updatedAt > BigInt(timestamp + 60) || BigInt(timestamp) - updatedAt > 7200n || answeredInRound < roundId || decimals > 36) return unavailable('Oracle round is stale or invalid');
    result = { symbol, network: 'base', oracle_feed: feed, block_number: block, round_id: String(roundId), raw_answer: String(answer), decimals, updated_at: String(updatedAt), price_usd: Number(answer) / 10 ** decimals };
  } else if (path === '/v1/uniswap-pool-state') {
    const target = address(raw, 'pool_or_token_address', 'address', 'token'); const block = await baseBlock();
    const candidatePools = await pools(target);
    let pool = candidatePools.find((p: any) => p.dexId === 'uniswap' && p.labels?.includes('v3'))?.pairAddress;
    // The address may itself be a pool. RPC method success, rather than a registry guess, determines this.
    pool ||= target;
    const [token0Raw, token1Raw, slot0, liquidity, fee] = await Promise.all(['0x0dfe1681','0xd21220a7','0x3850c7bd','0x1a686502','0xddca3f43'].map(selector => call(pool, selector, block)));
    try {
      const token0 = decodeAbiParameters(parseAbiParameters('address'), token0Raw)[0]; const token1 = decodeAbiParameters(parseAbiParameters('address'), token1Raw)[0];
      const state = decodeAbiParameters(parseAbiParameters('uint160,int24,uint16,uint16,uint16,uint8,bool'), slot0);
      result = { pool_address: pool, token0, token1, chain_id: 8453, block_number: block, sqrt_price_x96: String(state[0]), tick: state[1], liquidity_raw: String(BigInt(liquidity)), fee_pips: String(BigInt(fee)), lp_locked_pct: null, risk_verdict: 'NOT_ASSESSED' };
    } catch { return unavailable('Requested address is not a supported Uniswap V3 pool'); }
  } else if (['/v1/defi-yields-safe', '/v1/yield/safe-allocation'].includes(path)) {
    const asset = typeof raw.asset === 'string' ? raw.asset.toUpperCase() : 'USDC'; const minimum = positive(raw.min_tvl_usd, 5000000);
    const chainMap:Record<string,string>={base:'Base',arbitrum:'Arbitrum',ethereum:'Ethereum',solana:'Solana'};
    const chains=path.includes('allocation')?(raw.chains??['base']):['base'];
    if(!Array.isArray(chains)||!chains.length||chains.length>4||chains.some((v:any)=>typeof v!=='string'||!chainMap[v.toLowerCase()])) invalid('chains must contain supported chain names');
    const risk=String(raw.risk_tolerance??'CONSERVATIVE').toUpperCase();if(!['CONSERVATIVE','MODERATE','AGGRESSIVE'].includes(risk)) invalid('Unsupported risk_tolerance');
    const response = await json('https://yields.llama.fi/pools');
    if (response.status !== 'success' || !Array.isArray(response.data)) return unavailable('Invalid yields provider response');
    const candidates = response.data.filter((p: any) => chains.some((v:string)=>chainMap[v.toLowerCase()]===p.chain) && p.symbol === asset && (risk!=='CONSERVATIVE' || (p.stablecoin===true && p.ilRisk==='no')) && typeof p.apy === 'number' && p.apy >= 0 && p.apy <= 1000 && typeof p.tvlUsd === 'number' && p.tvlUsd >= minimum).sort((a: any, b: any) => b.apy - a.apy).slice(0,10);
    result = { chains, filter_asset: asset, pools: candidates.map((p: any) => ({ pool: p.pool, chain: p.chain, protocol: p.project, asset: p.symbol, apy_pct: p.apy, tvl_usd: p.tvlUsd, measured_at: response.timestamp ?? null })), safety_status: 'PROVIDER_YIELDS_ONLY_NOT_A_SECURITY_AUDIT' };
    if (path.includes('allocation')) { const capital = positive(raw.capital_usdc, 0); if (!capital) invalid('capital_usdc must be positive'); if (!candidates.length) return unavailable('No matching pools acquired'); result.allocations = candidates.slice(0,3).map((p: any) => ({ pool: p.pool, amount_usdc: capital / Math.min(3, candidates.length) })); result.risk_tolerance = risk; result.risk_model = 'equal exposure among top three yield candidates; safety not certified'; }
  } else if (['/v1/wallet-sanctions-check','/v1/security/wallet-drainer-check'].includes(path)) {
    const target = address(raw,'address','wallet_address','wallet');
    const response = await json(`https://api.gopluslabs.io/api/v1/address_security/${target}?chain_id=8453`);
    if(response.code !== 1 || !response.result || typeof response.result !== 'object') return unavailable('Address intelligence provider did not return evidence');
    const fields = path.includes('sanctions') ? ['sanctioned'] : ['stealing_attack','phishing_activities','honeypot_related_address','blacklist_doubt'];
    if(fields.some(k=>!['0','1'].includes(response.result[k]))) return unavailable('Address provider omitted required risk fields');
    const findings = Object.fromEntries(fields.map(k=>[k,response.result[k]==='1']));
    result={address:target,chain_id:8453,provider:'GoPlus',provider_findings:findings,provider_data_source:response.result.data_source??null,
      sanctioned:path.includes('sanctions')?findings.sanctioned:undefined,drainer_detected:path.includes('drainer')?Object.values(findings).some(Boolean):undefined,
      verdict:Object.values(findings).some(Boolean)?'PROVIDER_FLAGGED':'NO_PROVIDER_FLAG',coverage:'Provider intelligence only; not independent screening of all sanctions lists or complete transaction history',lists_checked:['GoPlus supplied intelligence (underlying lists not independently verified)']};
  } else if (path === '/v1/tokens/history-and-spread') {
    const symbols:Record<string,string>={ETH:'0x4200000000000000000000000000000000000006',WETH:'0x4200000000000000000000000000000000000006',BTC:'0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf',CBBTC:'0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf',AERO:'0x940181a94a35a4569e4529a3cdfb74e38fd98631',USDC:ASSET};
    const tokenInput=text(raw,'token','token_address'); const token=symbols[tokenInput.toUpperCase()]||address({token:tokenInput},'token');
    if(raw.window && raw.window!=='24h') invalid('Supported history window is 24h');
    if(raw.quote && raw.quote.toUpperCase()!=='USDC') invalid('Supported quote is USDC');
    const rows=(await pools(token)).filter((p:any)=>/^0x[0-9a-fA-F]{40}$/.test(p.pairAddress)&&p.baseToken?.address?.toLowerCase()===token.toLowerCase()).sort((a:any,b:any)=>(b.liquidity?.usd??0)-(a.liquidity?.usd??0));
    if(!rows.length) return unavailable('No matching pool acquired');
    const pool=rows[0];const response=await json(`https://api.geckoterminal.com/api/v2/networks/base/pools/${pool.pairAddress}/ohlcv/hour?aggregate=1&limit=24&currency=usd&token=${token}`);
    const candles=response.data?.attributes?.ohlcv_list;
    if(!Array.isArray(candles)||!candles.length||candles.some((c:any)=>!Array.isArray(c)||c.length!==6||c.some((v:any)=>typeof v!=='number'||!Number.isFinite(v)))) return unavailable('OHLCV provider did not return valid measured candles');
    if(timestamp-candles[0][0]>7200 || candles[0][0]>timestamp+60) return unavailable('Historical market data is stale');
    const prices=rows.map((p:any)=>Number(p.priceUsd)).filter((n:number)=>Number.isFinite(n)&&n>0);
    result={token:tokenInput,token_address:token,network:'base',pool_address:pool.pairAddress,window:'24h',currency:'USD',ohlcv: candles,
      venue_prices:rows.map((p:any)=>({pool:p.pairAddress,dex:p.dexId,price_usd:p.priceUsd??null})),indicative_price_dispersion_bps:prices.length>1?(Math.max(...prices)-Math.min(...prices))/Math.min(...prices)*10000:null,
      executable_spread_bps:null,coverage:'Historical OHLCV and indicative USD prices; no executable swap/profit claim',attribution:'GeckoTerminal / DexScreener'};
  } else if (path === '/v1/ondemand/market-snapshot') {
    if(!Array.isArray(raw.assets)||!raw.assets.length||raw.assets.length>10||raw.assets.some((v:any)=>typeof v!=='string')) invalid('assets must contain 1 to 10 symbols');
    const assetMap:Record<string,{chain:string,address:string}>={
      ETH:{chain:'base',address:'0x4200000000000000000000000000000000000006'},WETH:{chain:'base',address:'0x4200000000000000000000000000000000000006'},
      BTC:{chain:'base',address:'0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf'},CBBTC:{chain:'base',address:'0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf'},
      SOL:{chain:'solana',address:'So11111111111111111111111111111111111111112'},AERO:{chain:'base',address:'0x940181a94a35a4569e4529a3cdfb74e38fd98631'},
      VIRTUAL:{chain:'base',address:'0x0b3e328455c4059eeb9e3f84b5543f74e24e7e1b'},USDC:{chain:'base',address:ASSET}};
    const snapshots=await Promise.all(raw.assets.map(async(symbol:string)=>{
      const asset=assetMap[symbol.toUpperCase()];if(!asset) invalid('Unknown asset symbol');
      const rows=await json(`https://api.dexscreener.com/token-pairs/v1/${asset.chain}/${asset.address}`);
      if(!Array.isArray(rows)) return unavailable('Malformed market snapshot response');
      const pool=rows.filter((p:any)=>p.chainId===asset.chain&&p.baseToken?.address?.toLowerCase()===asset.address.toLowerCase()&&Number(p.priceUsd)>0).sort((a:any,b:any)=>(b.liquidity?.usd??0)-(a.liquidity?.usd??0))[0];
      if(!pool) return unavailable('No measured price acquired for '+symbol);
      return {symbol,chain:asset.chain,token_address:asset.address,pool_address:pool.pairAddress,price_usd:pool.priceUsd,liquidity_usd:pool.liquidity?.usd??null,provider:'DexScreener'};
    }));
    let markets=null;
    if(raw.include_polymarket !== false) {
      const data=await json('https://gamma-api.polymarket.com/markets?active=true&closed=false&limit=10');
      if(!Array.isArray(data)) return unavailable('Prediction market provider returned invalid data');
      markets=data.map((m:any)=>({id:m.id,question:m.question,slug:m.slug,outcomes:m.outcomes,outcome_prices:m.outcomePrices,volume:m.volume,liquidity:m.liquidity,updated_at:m.updatedAt}));
    }
    result={assets:snapshots,polymarket:markets,snapshot_at:new Date(now()).toISOString(),coverage:'Source snapshots acquired during this request; not execution prices'};
  } else if (path === '/v1/security/smart-contract-honeypot-check') {
    const token=address(raw,'contract_address','token_address');const block=await baseBlock();
    const simulation=await simulateBuySell(token as Address,BigInt(block));
    if(simulation.status!=='passed') return unavailable('Complete buy/sell simulation unavailable: '+simulation.reason);
    result={contract_address:token,network:'base',chain_id:8453,block_number:block,can_buy:true,can_sell:true,is_honeypot:false,buy_tax_bps:simulation.buy_tax_bps,sell_tax_bps:simulation.sell_tax_bps,
      verdict:'ROUND_TRIP_EXECUTED_IN_SCOPED_SIMULATION',simulation:simulation.evidence,coverage:'One disclosed size, pool, block and fresh simulated trader; not universal token safety'};
  } else if (path === '/v1/risk/full_audit') {
    const target=address(raw,'target_address','contract_address','token_address');
    const [contract,token,simulation]=await Promise.all([executeEndpoint('/v1/contract-info',{contract_address:target},deps),executeEndpoint('/v1/base/token',{token_address:target},deps),executeEndpoint('/v1/security/smart-contract-honeypot-check',{contract_address:target},deps)]);
    const counterparty=raw.counterparty_wallet?await executeEndpoint('/v1/wallet-sanctions-check',{address:address(raw,'counterparty_wallet')},deps):null;
    result={target_address:target,contract,token,simulation,counterparty,overall_risk_score:null,verdict:'EVIDENCE_REQUIRES_REVIEW',coverage:'Acquired bytecode, token metadata, liquidity and scoped round-trip simulation; provider sanctions flags if a wallet is supplied. No security grade, all-list compliance or future safety certification.'};
  } else if (path === '/v1/verify/agent-attestation') {
    const wallet=address(raw,'agent_wallet');const message=text(raw,'message');const signature=text(raw,'signature');
    const domain=text(raw,'service_domain');let url:URL;try{url=new URL('https://'+domain);}catch{return invalid('service_domain must be a public DNS hostname');}
    if(url.hostname!==domain || url.pathname!=='/' || url.port) invalid('service_domain must be a DNS hostname without path or port');
    const signedAt=Number(raw.signed_at);if(!Number.isSafeInteger(signedAt)||Math.abs(timestamp-signedAt)>300) invalid('signed_at must be a current UTC Unix timestamp within five minutes');
    const expected=`CanaryGuard agent ownership verification\nWallet: ${wallet.toLowerCase()}\nDomain: ${domain}\nTimestamp: ${signedAt}`;
    if(message!==expected) invalid('message must match the documented wallet/domain/timestamp verification statement');
    let verified=false;try{verified=await verifyMessage({address:wallet as Address,message,signature:signature as `0x${string}`});}catch{return invalid('Invalid ownership signature');}
    if(!verified) invalid('Ownership signature did not recover the claimed wallet');
    const cardUrl=await publicUrl(`https://${domain}/.well-known/agent-registration.json`);const response=deps.fetch?await request(cardUrl.href,{signal:AbortSignal.timeout(10000),redirect:'manual'}):await fetchPublicPage(cardUrl.href);
    if(!response.ok) return unavailable('Service domain registration could not be acquired');let card:any;try{card=JSON.parse(await response.text());}catch{return unavailable('Service domain registration is not valid JSON');}
    const advertised=card.provider?.wallet??card.wallet??card.payment_recipient;
    if(typeof advertised!=='string'||advertised.toLowerCase()!==wallet.toLowerCase()) invalid('Domain registration does not advertise the signed wallet');
    result={agent_wallet:wallet,service_domain:domain,verified:true,verification_scope:'ECDSA wallet ownership and matching domain registration only',signed_statement:message,ownership_signature:signature,domain_registration_url:cardUrl.href,
      trust_score:null,zero_drainer_history:null,x402_payment_capability:null,report_sha256:createHash('sha256').update(JSON.stringify({wallet,domain,message,signature,card})).digest('hex'),coverage:'Report checksum is unkeyed; no institution, reputation or future payment capability is attested'};
  } else if (path === '/v1/llm-token-pricing') {
    const model=text(raw,'model');const inTokens=positive(raw.input_tokens,0),outTokens=positive(raw.output_tokens,0);
    const response=await json('https://openrouter.ai/api/v1/models');
    if(!Array.isArray(response.data)) return unavailable('Pricing provider returned an invalid catalogue');
    const matches=response.data.filter((m:any)=>m.id===model || m.id.split('/').pop()===model);
    if(matches.length!==1) invalid('Specify a unique current OpenRouter model id; no default price is substituted');
    const selected=matches[0];const inputPrice=Number(selected.pricing?.prompt),outputPrice=Number(selected.pricing?.completion);
    if(!Number.isFinite(inputPrice)||inputPrice<0||!Number.isFinite(outputPrice)||outputPrice<0) return unavailable('Current per-token price was not provided');
    result={queried_model:model,model_id:selected.id,input_tokens:inTokens,output_tokens:outTokens,input_per_1m_usd:inputPrice*1e6,output_per_1m_usd:outputPrice*1e6,
      estimated_cost_usd:inTokens*inputPrice+outTokens*outputPrice,source_url:'https://openrouter.ai/api/v1/models',as_of:new Date(now()).toISOString(),coverage:'OpenRouter routing prices; direct vendor bills and optional tools may differ'};
  } else if (path === '/v1/security/phishing-url-inspector' || path === '/v1/url-agent-readiness') {
    const target = text(raw, 'url', 'target_url'); const url = await publicUrl(target);
    const response = deps.fetch ? await request(url, { signal: AbortSignal.timeout(10000), redirect: 'manual' }) : await fetchPublicPage(url.href);
    if (response.status >= 300 && response.status < 400) return unavailable('Redirecting URL must be submitted directly after review');
    if (!response.ok) return unavailable(`Requested URL returned HTTP ${response.status}`);
    const body = await response.text(); if (body.length > 2*1024*1024) return unavailable('Page exceeds analysis size limit');
    const inspection = sanitizeContent(body, true); const markers = /claim-airdrop|drainer|free-mint|xn--/i.test(url.href);
    evidence.push({ source: url.href, status: response.status, sha256: createHash('sha256').update(body).digest('hex'), fetched_at: new Date(now()).toISOString() });
    result = { url: target, injection_detected: inspection.injection_detected, url_markers_detected: markers, is_phishing: markers || inspection.injection_detected ? true : null, verdict: markers || inspection.injection_detected ? 'REVIEW_OR_BLOCK' : 'NO_PATTERN_DETECTED', coverage: 'fetched page and URL heuristics; not proof of domain safety' };
    if (path.includes('readiness')) {
      const statuses = await Promise.all(['/llms.txt','/.well-known/x402.json','/openapi.json','/mcp/server-card'].map(async p => {
        try { const target = new URL(p, url.origin).href; const r = deps.fetch ? await request(target, { signal: AbortSignal.timeout(5000), redirect: 'manual' }) : await fetchPublicPage(target); const b = await r.text(); let valid = false; if (r.ok) { if (p.endsWith('.txt')) valid = b.length > 0; else { const j = JSON.parse(b); valid = typeof j === 'object' && j !== null; } } return { path: p, status: r.status, valid }; } catch { return { path: p, status: null, valid: false }; }
      }));
      result.discovery_endpoints = statuses; result.agent_ready_score = 25 * statuses.filter(s => s.valid).length;
    }
  } else if (path === '/v1/alpha/safe-base-trending') {
    const response = await json('https://api.dexscreener.com/token-profiles/latest/v1');
    if (!Array.isArray(response)) return unavailable('Invalid token profiles response');
    const limit = Math.max(1, Math.floor(positive(raw.limit, 5, 10))); const minimum = positive(raw.min_liquidity_usd, 1000000);
    const profiles = response.filter((p: any) => p.chainId === 'base' && /^0x[0-9a-fA-F]{40}$/.test(p.tokenAddress)).slice(0,10);
    const lists = await Promise.all(profiles.map(async (p: any) => ({ token_address: p.tokenAddress, pools: (await pools(p.tokenAddress)).filter((v: any) => typeof v.liquidity?.usd === 'number' && v.liquidity.usd >= minimum) })));
    result = { network: 'base', tokens: lists.filter(p => p.pools.length).slice(0,limit), safety_status: 'TREND_AND_LIQUIDITY_ONLY_SAFETY_NOT_ASSESSED' };
  } else if (path === '/v1/alpha/polymarket-verified-odds' || path === '/v1/polymarket-odds-pulse') {
    const limit = Math.max(1, Math.floor(positive(raw.limit, 10, 25)));
    const data = await json(`https://gamma-api.polymarket.com/markets?active=true&closed=false&limit=${limit}`);
    if (!Array.isArray(data)) return unavailable('Prediction market provider returned invalid data');
    const markets = data.map((m: any) => ({
      id: m.id,
      question: m.question,
      slug: m.slug,
      outcomes: m.outcomes,
      outcome_prices: m.outcomePrices,
      volume: m.volume,
      liquidity: m.liquidity,
      updated_at: m.updatedAt,
    }));
    result = {
      markets,
      count: markets.length,
      snapshot_at: new Date(now()).toISOString(),
      coverage: 'Polymarket Gamma API active market snapshots acquired during this request',
    };
  } else {
    return unavailable(`No complete evidence-backed implementation is configured for ${path}; payment will not be collected`);
  }
  return { ...result, timestamp, provenance: evidence, agent_continuation: AGENT_CONTINUATION };
}

export async function publicUrl(value: string): Promise<URL> {
  try { return (await resolvePublic(value)).url; }
  catch { return invalid('Target must be a public HTTPS URL resolving only to public addresses'); }
}
