import { createHash, createPublicKey, verify as verifyEd25519 } from 'node:crypto';
import { verifyTypedData, type Address, type Hex } from 'viem';
import { ASSET, NETWORK, SOLANA_NETWORK, SOLANA_USDC_MINT, SOLANA_FEE_PAYER } from './config.js';

const addressPattern = /^0x[0-9a-fA-F]{40}$/;
const noncePattern = /^0x[0-9a-fA-F]{64}$/;
const maxUint256 = (1n << 256n) - 1n;
const transferTypes = { TransferWithAuthorization: [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
  { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
  { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
] } as const;

function uint256(value: unknown): bigint {
  if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) throw Error('Invalid uint256');
  if (!['string', 'number', 'bigint'].includes(typeof value) || !/^\d+$/.test(String(value))) throw Error('Invalid decimal uint256');
  const number = BigInt(String(value));
  if (number < 0n || number > maxUint256) throw Error('uint256 out of range');
  return number;
}

function evmAuthorization(payment: any) {
  if (payment?.x402Version !== 2 || payment.accepted?.network !== NETWORK ||
      String(payment.accepted?.asset).toLowerCase() !== ASSET.toLowerCase()) throw Error('Wrong payment network or asset');
  const auth = payment.payload?.authorization;
  if (!auth || !addressPattern.test(auth.from) || !addressPattern.test(auth.to) ||
      !noncePattern.test(auth.nonce) || !/^0x[0-9a-fA-F]{130}$/.test(payment.payload?.signature)) throw Error('Invalid authorization');
  return {
    from: auth.from.toLowerCase() as Address, to: auth.to.toLowerCase() as Address,
    value: uint256(auth.value), validAfter: uint256(auth.validAfter), validBefore: uint256(auth.validBefore),
    nonce: auth.nonce.toLowerCase() as Hex,
  };
}

const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes: Buffer): string {
  let number = BigInt('0x' + bytes.toString('hex')), output = '';
  while (number > 0n) { output = alphabet[Number(number % 58n)] + output; number /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; output = '1' + output; }
  return output;
}

function solanaAuthorization(payment: any) {
  if (payment?.x402Version !== 2 || payment.accepted?.network !== SOLANA_NETWORK || payment.accepted?.asset !== SOLANA_USDC_MINT) throw Error('Wrong Solana network or asset');
  const encoded = payment.payload?.transaction;
  if (typeof encoded !== 'string' || encoded.length > 1800 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw Error('Invalid transaction encoding');
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length > 1232 || bytes.toString('base64').replace(/=+$/, '') !== encoded.replace(/=+$/, '')) throw Error('Invalid transaction bytes');
  let cursor = 0;
  const take = (data: Buffer, length: number) => {
    if (!Number.isInteger(length) || length < 0 || cursor + length > data.length) throw Error('Truncated transaction');
    const value = data.subarray(cursor, cursor + length); cursor += length; return value;
  };
  const shortVec = (data: Buffer) => {
    let value = 0, shift = 0;
    for (let i = 0; i < 3; i++) {
      const byte = take(data, 1)[0]; value |= (byte & 127) << shift;
      if (!(byte & 128)) {
        if (i > 0 && byte === 0) throw Error('Noncanonical short vector');
        if (value > 65535) throw Error('Oversized short vector');
        return value;
      }
      shift += 7;
    }
    throw Error('Invalid short vector');
  };
  const signatures = shortVec(bytes);
  if (signatures !== 2) throw Error('Expected sponsored fee payer and buyer');
  take(bytes, 64); // The sponsor may add its signature; ownership is the buyer's signature.
  const buyerSignature = take(bytes, 64);
  const message = bytes.subarray(cursor);
  cursor = 0;
  const versioned = !!(message[0] & 128);
  if (versioned && take(message, 1)[0] !== 128) throw Error('Unsupported transaction version');
  const header = take(message, 3);
  if (header[0] !== 2 || header[1] >= 2) throw Error('Invalid signer layout');
  const accounts = shortVec(message);
  if (accounts < 2 || accounts > 256 || header[2] > accounts - 2) throw Error('Invalid account layout');
  const keys = take(message, accounts * 32);
  const feePayer = keys.subarray(0, 32), buyer = keys.subarray(32, 64);
  if (base58(feePayer) !== SOLANA_FEE_PAYER || buyer.equals(feePayer)) throw Error('Unexpected sponsored fee payer');
  take(message, 32); // Recent blockhash is covered by the buyer signature, not checked for expiry here.
  const instructions = shortVec(message);
  const accountReferences: number[] = [];
  for (let i = 0; i < instructions; i++) {
    accountReferences.push(take(message, 1)[0]);
    accountReferences.push(...take(message, shortVec(message)));
    take(message, shortVec(message));
  }
  let loadedAccounts = 0;
  if (versioned) {
    const lookups = shortVec(message);
    for (let i = 0; i < lookups; i++) {
      take(message, 32);
      const writable = shortVec(message); take(message, writable);
      const readonly = shortVec(message); take(message, readonly);
      loadedAccounts += writable + readonly;
    }
  }
  if (cursor !== message.length || accounts + loadedAccounts > 256 || accountReferences.some(index => index >= accounts + loadedAccounts)) throw Error('Invalid message account references');
  const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), buyer]), format: 'der', type: 'spki' });
  if (!verifyEd25519(null, message, publicKey, buyerSignature)) throw Error('Invalid buyer signature');
  return { message, buyer };
}

/** Local proof of buyer ownership only. Expiry/funding/terms belong to new-settlement
 * validation, so genuine expired authorizations can still recover purchased results. */
export async function verifyPaymentOwnership(payment: any): Promise<boolean> {
  try {
    if (payment?.accepted?.network === SOLANA_NETWORK) { solanaAuthorization(payment); return true; }
    const message = evmAuthorization(payment);
    return await verifyTypedData({ address: message.from, domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: ASSET },
      types: transferTypes, primaryType: 'TransferWithAuthorization', message, signature: payment.payload.signature });
  } catch { return false; }
}

/** Stable authorization identity. Call verifyPaymentOwnership first for EVM: this
 * synchronous helper canonicalizes its identity but cannot authenticate ECDSA. */
export function canonicalPaymentIdentity(payment: any): string | null {
  try {
    const hash = createHash('sha256');
    if (payment?.accepted?.network === SOLANA_NETWORK) {
      const { message, buyer } = solanaAuthorization(payment);
      return hash.update(SOLANA_NETWORK).update('\0').update(SOLANA_USDC_MINT).update('\0').update(message).update(buyer).digest('hex');
    }
    const auth = evmAuthorization(payment);
    return hash.update([NETWORK, ASSET.toLowerCase(), auth.from, auth.nonce].join('\0')).digest('hex');
  } catch { return null; }
}
