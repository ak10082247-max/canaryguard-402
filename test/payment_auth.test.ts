import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import test from 'node:test';
import { privateKeyToAccount } from 'viem/accounts';
import { canonicalPaymentIdentity, verifyPaymentOwnership } from '../src/payment_auth.js';
import { ASSET, NETWORK, RECIPIENT, SOLANA_NETWORK, SOLANA_USDC_MINT, SOLANA_FEE_PAYER } from '../src/config.js';

// Public deterministic fixture seeds only; no environment, keystore or funded key is read.
const account = privateKeyToAccount(('0x' + '01'.repeat(32)) as `0x${string}`);
const types = { TransferWithAuthorization: [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
] } as const;

async function evm(expired = false, domainChain = 8453) {
  const authorization = { from: account.address, to: RECIPIENT, value: '10000', validAfter: '0', validBefore: expired ? '1' : String(Math.floor(Date.now()/1000)+120), nonce: ('0x' + '03'.repeat(32)) as `0x${string}` };
  const signature = await account.signTypedData({ domain: { name: 'USD Coin', version: '2', chainId: domainChain, verifyingContract: ASSET }, types, primaryType: 'TransferWithAuthorization',
    message: { ...authorization, value: 10000n, validAfter: 0n, validBefore: BigInt(authorization.validBefore) } });
  return { x402Version: 2, accepted: { network: NETWORK, asset: ASSET }, payload: { authorization, signature } };
}

test('genuine EIP3009 buyer proof is independently verified and expired proof still owns recovery', async () => {
  const live = await evm(), expired = await evm(true);
  assert.equal(await verifyPaymentOwnership(live), true);
  assert.equal(await verifyPaymentOwnership(expired), true);
  assert.equal(canonicalPaymentIdentity(live), canonicalPaymentIdentity(expired));
});

test('forged signatures using public payer and nonce never authenticate cached recovery', async () => {
  const genuine = await evm();
  const forged = structuredClone(genuine);
  forged.payload.signature = ('0x' + '11'.repeat(65)) as `0x${string}`;
  // The opaque ID alone is deliberately not proof. Callers must verify ownership first.
  assert.equal(canonicalPaymentIdentity(forged), canonicalPaymentIdentity(genuine));
  assert.equal(await verifyPaymentOwnership(forged), false);
  const substituted = structuredClone(genuine); substituted.payload.authorization.value = '10001';
  assert.equal(await verifyPaymentOwnership(substituted), false);
});

test('EVM identity ignores unsigned keys, decimal spelling, address case and JSON encoding', async () => {
  const original = await evm();
  const changed: any = JSON.parse(JSON.stringify(original));
  changed.payload.authorization.from = '0x' + changed.payload.authorization.from.slice(2).toUpperCase();
  changed.payload.authorization.to = '0x' + changed.payload.authorization.to.slice(2).toUpperCase();
  changed.payload.authorization.value = '00010000';
  changed.payload.authorization.validAfter = 0;
  changed.payload.authorization.nonce = '0x' + changed.payload.authorization.nonce.slice(2).toUpperCase();
  changed.payload.authorization.unsigned_extra = { ignored: true };
  changed.accepted.asset = '0x' + ASSET.slice(2).toUpperCase();
  assert.equal(await verifyPaymentOwnership(changed), true);
  assert.equal(canonicalPaymentIdentity(changed), canonicalPaymentIdentity(original));
});

test('wrong domain, network, asset or malformed values fail local proof', async () => {
  assert.equal(await verifyPaymentOwnership(await evm(false, 1)), false);
  const original = await evm();
  for (const change of [
    { ...original, accepted: { ...original.accepted, network: 'eip155:1' } },
    { ...original, accepted: { ...original.accepted, asset: RECIPIENT } },
    { ...original, payload: { ...original.payload, authorization: { ...original.payload.authorization, value: Number.MAX_SAFE_INTEGER+1 } } },
    { ...original, payload: { ...original.payload, authorization: { ...original.payload.authorization, nonce: '0x01' } } },
    { ...original, payload: { ...original.payload, authorization: { ...original.payload.authorization, validBefore: '-1' } } },
  ]) {
    assert.equal(await verifyPaymentOwnership(change), false);
    assert.equal(canonicalPaymentIdentity(change), null);
  }
  for (const bad of [null, undefined, [], {}, 'not json']) {
    assert.equal(await verifyPaymentOwnership(bad), false);
    assert.equal(canonicalPaymentIdentity(bad), null);
  }
});

function decode58(value: string) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let number = 0n;
  for (const char of value) number = number*58n + BigInt(alphabet.indexOf(char));
  const body = Buffer.from(number.toString(16).padStart(64,'0'),'hex');
  assert.equal(body.length,32);
  return body;
}

function solana() {
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), Buffer.alloc(32, 2)]), format:'der', type:'pkcs8' });
  const buyer = Buffer.from(createPublicKey(privateKey).export({format:'der',type:'spki'})).subarray(-32);
  const message = Buffer.concat([
    Buffer.from([128,2,1,1,3]), decode58(SOLANA_FEE_PAYER), buyer, Buffer.alloc(32,3), Buffer.alloc(32,4),
    // One compiled instruction, program index2, buyer account1, three data bytes; no lookup tables.
    Buffer.from([1,2,1,1,3,5,6,7,0]),
  ]);
  const buyerSignature = sign(null,message,privateKey);
  const bytes = Buffer.concat([Buffer.from([2]), Buffer.alloc(64), buyerSignature, message]);
  return { payment: { x402Version:2, accepted:{network:SOLANA_NETWORK,asset:SOLANA_USDC_MINT}, payload:{transaction:bytes.toString('base64')} }, bytes, message, privateKey };
}

test('genuine Solana buyer proof survives sponsor signature and equivalent base64 padding', async () => {
  const fixture = solana(), original = fixture.payment;
  assert.equal(await verifyPaymentOwnership(original),true);
  const sponsorAdded = Buffer.from(fixture.bytes); sponsorAdded.fill(9,1,65);
  const changed = structuredClone(original); changed.payload.transaction = sponsorAdded.toString('base64').replace(/=+$/,'');
  // Sponsor authenticity is settlement validation; only buyer ownership is authenticated here.
  assert.equal(await verifyPaymentOwnership(changed),true);
  assert.equal(canonicalPaymentIdentity(changed),canonicalPaymentIdentity(original));
});

test('Solana forged buyer signatures and altered messages cannot recover a paid result', async () => {
  const fixture = solana();
  for (const offset of [65, fixture.bytes.length-2]) {
    const forged = Buffer.from(fixture.bytes); forged[offset] ^= 1;
    const payment = structuredClone(fixture.payment); payment.payload.transaction = forged.toString('base64');
    assert.equal(await verifyPaymentOwnership(payment),false);
    assert.equal(canonicalPaymentIdentity(payment),null);
  }
});

test('malformed but signed Solana messages, extra bytes and invalid encoding fail closed', async () => {
  const fixture = solana();
  const malformed = fixture.message.subarray(0,-1); // Missing lookup-table vector.
  const malformedBytes = Buffer.concat([Buffer.from([2]), Buffer.alloc(64),sign(null,malformed,fixture.privateKey),malformed]);
  for (const transaction of [malformedBytes.toString('base64'), Buffer.concat([fixture.bytes,Buffer.from([0])]).toString('base64'), fixture.payment.payload.transaction+'!', 'AAAA']) {
    const payment = structuredClone(fixture.payment); payment.payload.transaction=transaction;
    assert.equal(await verifyPaymentOwnership(payment),false);
    assert.equal(canonicalPaymentIdentity(payment),null);
  }
});
