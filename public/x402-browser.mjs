// Recover the original authorization and request after a lost response.
const NETWORK = 'eip155:8453';
const ASSET = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const MERCHANT = '0x73279fa4BadA7CAC888c62CDa4f5c8104765f6f1';
const STORAGE_KEY = 'canary_x402_pending_v1';
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const encode = value => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(value))));
const decode = value => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(value), character => character.charCodeAt(0))));
export const usdc = amount => `${BigInt(amount) / 1000000n}.${(BigInt(amount) % 1000000n).toString().padStart(6, '0')}`;

export function createBasePurchase({ origin, wallet, request = fetch, storage = sessionStorage, random = crypto,
  now = () => Date.now(), confirmQuote = async () => false, status = () => {}, maxAmountMicro = '20000' }) {
  let busy = false;
  const pending = () => { const value = storage.getItem(STORAGE_KEY); return value ? JSON.parse(value) : null; };
  const clear = () => storage.removeItem(STORAGE_KEY);
  const send = (path, body, authorization) => request(new URL(path, origin).href, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...(authorization ? { 'PAYMENT-SIGNATURE': authorization } : {}) },
    body, signal: AbortSignal.timeout(65000),
  });
  function terms(challenge, path) {
    if (challenge?.x402Version !== 2 || challenge.resource?.url !== new URL(path, origin).href) throw Error('The quote does not match this endpoint. Nothing signed.');
    const quote = challenge.accepts?.find(value => value.network === NETWORK);
    if (!quote || quote.scheme !== 'exact' || String(quote.asset).toLowerCase() !== ASSET.toLowerCase() ||
      String(quote.payTo).toLowerCase() !== MERCHANT.toLowerCase() || !/^[1-9]\d*$/.test(quote.amount) ||
      BigInt(quote.amount) > BigInt(maxAmountMicro) || !Number.isInteger(quote.maxTimeoutSeconds) || quote.maxTimeoutSeconds < 1 ||
      quote.extra?.name !== 'USD Coin' || quote.extra?.version !== '2') throw Error('Unsupported or out-of-budget quote. Nothing signed.');
    return quote;
  }
  async function deliver(operation) {
    status('Submitting the original authorization. A network failure can be recovered without another signature.');
    const response = await send(operation.path, operation.body, operation.authorization);
    const data = await response.json();
    if (!response.ok) {
      if (data.charged === false) clear();
      throw Error(`${data.error || 'Request failed'} (${response.status}). ${data.charged === false ? 'The server reports no charge.' : 'Payment status is uncertain. Use Recover original payment; do not authorize another purchase.'}`);
    }
    let receipt;
    try { receipt = decode(response.headers.get('PAYMENT-RESPONSE') || ''); } catch { /* Keep original proof for recovery. */ }
    if (receipt?.success !== true || receipt.network !== NETWORK || receipt.amount !== operation.amount ||
      String(receipt.payer).toLowerCase() !== operation.payer.toLowerCase() ||
      (receipt.resource?.url ?? receipt.resource) !== new URL(operation.path, origin).href || !/^0x[0-9a-fA-F]{64}$/.test(receipt.transaction || '')) {
      throw Error('The response has no matching settlement receipt. Payment status is uncertain; recover the original payment.');
    }
    clear();
    return { data, receipt, request:JSON.parse(operation.body), paid: true, replayed: response.headers.get('Idempotency-Replayed') === 'true' };
  }
  async function exclusive(work) {
    if (busy) throw Error('A payment request is already running.');
    busy = true;
    try { return await work(); } finally { busy = false; }
  }
  return {
    hasPending: () => !!pending(),
    recover: () => exclusive(async () => {
      const operation = pending();
      if (!operation) throw Error('No original payment is pending in this browser tab.');
      if (new URL(operation.path, origin).origin !== origin || !operation.authorization || !operation.body || !ADDRESS.test(operation.payer)) throw Error('Invalid saved payment. Do not sign another purchase until reconciled.');
      return deliver(operation);
    }),
    buy: (path, input) => exclusive(async () => {
      if (pending()) throw Error('An original payment needs recovery. Use Recover original payment before starting another purchase.');
      if (new URL(path, origin).origin !== origin || !path.startsWith('/v1/')) throw Error('Invalid purchase endpoint.');
      const body = JSON.stringify(input);
      status('Requesting the exact price from this endpoint…');
      const challengeResponse = await send(path, body);
      if (challengeResponse.ok) return { data: await challengeResponse.json(), receipt: null, paid: false };
      if (challengeResponse.status !== 402) throw Error(`The endpoint is unavailable (${challengeResponse.status}). Nothing signed.`);
      const challenge = decode(challengeResponse.headers.get('PAYMENT-REQUIRED') || '');
      const quote = terms(challenge, path);
      if (!await confirmQuote({ amountUsdc: usdc(quote.amount), recipient: quote.payTo, resource: challenge.resource.url, maxAuthorizationSeconds: Math.min(60, quote.maxTimeoutSeconds) })) throw Error('Purchase cancelled. Nothing signed.');
      if (!wallet?.request) throw Error('A Base-compatible browser wallet is required.');
      const accounts = await wallet.request({ method: 'eth_requestAccounts' });
      const from = accounts?.[0];
      if (!ADDRESS.test(from || '')) throw Error('No wallet account selected.');
      await wallet.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0x2105' }] });
      if (BigInt(await wallet.request({ method: 'eth_chainId' })) !== 8453n) throw Error('Wallet must be connected to Base mainnet. Nothing signed.');
      const nonce = '0x' + Array.from(random.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
      const authorization = { from, to: quote.payTo, value: quote.amount, validAfter: '0', validBefore: String(Math.floor(now()/1000) + Math.min(60, quote.maxTimeoutSeconds)), nonce };
      const types = { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
        TransferWithAuthorization: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] };
      status(`Review ${usdc(quote.amount)} USDC on Base in your wallet.`);
      const signature = await wallet.request({ method: 'eth_signTypedData_v4', params: [from, JSON.stringify({ types, primaryType: 'TransferWithAuthorization', domain: { name: quote.extra.name, version: quote.extra.version, chainId: 8453, verifyingContract: quote.asset }, message: authorization })] });
      if (!/^0x[0-9a-fA-F]{130}$/.test(signature || '')) throw Error('Wallet returned an invalid signature. Nothing submitted.');
      const payload = { x402Version: 2, resource: challenge.resource, accepted: quote, payload: { signature, authorization }, ...(challenge.extensions ? { extensions: challenge.extensions } : {}) };
      const operation = { path, body, authorization: encode(payload), amount: quote.amount, payer: from };
      // Save before transmission so a lost response cannot silently cause another signature.
      storage.setItem(STORAGE_KEY, JSON.stringify(operation));
      return deliver(operation);
    }),
  };
}
