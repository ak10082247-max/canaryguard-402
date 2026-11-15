import type { CryptoAddressFinding, SanitizeResult } from '../types.js';

const INVISIBLE_CHARACTERS = /[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/gu;
const ROLE_DELIMITER = /\[\/?INST\]|<\|(?:im_start|im_end|system|developer|assistant|user)\|>|<<\/?SYS>>/i;
const ROLE_PREFIX = /(?:^|[\r\n])\s*(?:system|developer|assistant)\s*:/i;
const INSTRUCTION_OVERRIDE = /\b(?:(?:ignore|disregard|forget|override)\s+(?:(?:all|any|the|your|our)\s+)*(?:previous|prior|earlier|above|system|developer)\s+(?:instructions?|prompts?|rules?|messages?)|(?:you\s+(?:are\s+to|must|will)\s+)?(?:do\s+(?:what|as)\s+i\s+(?:say|tell\s+you)|obey(?:\s+(?:all|only|my)\s+(?:commands?|instructions?))?)|follow\s+only\s+(?:my|these)\s+instructions?)\b/i;
const WALLET_ASSET_COMMAND = /\b(?:(?:drain|empty|sweep|flush|dump)\s+(?:(?:all|every|entire|the|your|my|our|any|remaining)\s+)*(?:wallet|treasury|vault|funds?|balances?|assets?|tokens?|crypto|eth|usdc|usdt|coins?)|(?:send|transfer|wire|move|withdraw|forward)\s+(?:(?:all(?:\s+of)?|every|entire|your|our|remaining)\s+(?:the\s+|remaining\s+)?|(?:the\s+)?(?:entire|remaining|full)\s+)(?:wallet|treasury|vault|funds?|balances?|assets?|tokens?|crypto|eth|usdc|usdt|coins?)|(?:send|transfer|wire|move|drain|empty|sweep|withdraw|flush|forward)\s+(?:the\s+)?(?:wallet|treasury|vault))\b/i;
const WALLET_DESTINATION_COMMAND = /\b(?:send|transfer|wire|move|drain|empty|sweep|withdraw|flush|forward)\s+(?:(?:[\d,.]+(?:[kmb])?|all|every|entire|remaining|the|your|my|our|any|it|them|funds?|balances?|tokens?|assets?|wallet|treasury|vault|crypto|eth|usdc|usdt|coins?|sol|solana)\s+){0,6}(?:to|into)\s+(?:(?:the\s+following|this|my|the|an?|new|specified|designated)\s+)*(?:(?:wallet|recipient|destination)\s+)?(?:address\s*(?::|\s+)?)?0x[\da-f]{4,40}\b/i;
const EVM_ADDRESS = /\b0x[\da-f]{40}\b/gi;

export function matchesWalletCommand(value: string): boolean {
  return WALLET_ASSET_COMMAND.test(value) || WALLET_DESTINATION_COMMAND.test(value);
}

export function commandThreats(value: string): string[] {
  const normalized = value.normalize('NFKC');
  const found: string[] = [];
  if (ROLE_DELIMITER.test(normalized) || ROLE_PREFIX.test(normalized)) found.push('role_delimiter_override');
  if (INSTRUCTION_OVERRIDE.test(normalized)) found.push('instruction_override');
  if (matchesWalletCommand(normalized)) found.push('wallet_transfer_command');
  return found;
}

export function extractAddresses(value: string): CryptoAddressFinding[] {
  const normalized = value.normalize('NFKC');
  const addresses = new Map<string, CryptoAddressFinding>();
  for (const match of normalized.matchAll(EVM_ADDRESS)) {
    const address = match[0];
    const key = address.toLowerCase();
    const context = normalized.slice(Math.max(0, match.index - 160), match.index + address.length + 40);
    const reasons = ['unverified_address'];
    let riskScore = 0.1;
    if (/^0x(?:0{40}|0{36}dead)$/i.test(address)) {
      reasons.push('burn_destination');
      riskScore = 0.7;
    }
    if (matchesWalletCommand(context)) {
      reasons.push('wallet_transfer_command_nearby');
      riskScore = 0.98;
    }
    const existing = addresses.get(key);
    if (!existing || existing.risk_score < riskScore) addresses.set(key, { address, risk_score: riskScore, reasons });
  }
  return [...addresses.values()];
}

export function neutralizeCommandsInPlace(value: string): string {
  let text = value.normalize('NFKC');
  text = text.replace(new RegExp(INSTRUCTION_OVERRIDE.source, 'gi'), '[instruction_override_neutralized]');
  text = text.replace(new RegExp(WALLET_ASSET_COMMAND.source, 'gi'), '[wallet_asset_command_neutralized]');
  text = text.replace(new RegExp(WALLET_DESTINATION_COMMAND.source, 'gi'), '[wallet_destination_command_neutralized]');
  text = text.replace(/\[\/?INST\]|<\|(?:im_start|im_end|system|developer|assistant|user)\|>|<<\/?SYS>>/gi, '[role_delimiter_neutralized]');
  return text;
}

import { sanitizeContentLocal } from '../local_sanitizer.js';

export function inspectContent(content: string, strictMode = false): SanitizeResult {
  const res = sanitizeContentLocal(content, strictMode);
  return {
    status: res.status,
    risk_score: res.risk_score,
    injection_detected: res.injection_detected,
    threats_neutralized: res.threats_neutralized,
    sanitized_content: res.sanitized_content,
    safety_receipt: res.safety_receipt,
    crypto_addresses: res.crypto_addresses.map((addr) => ({
      address: addr.address,
      risk_score: addr.risk_score,
      reasons: addr.reasons,
    })),
    recommended_actions: res.crypto_addresses.length
      ? [
          {
            service: 'rugshield-402',
            description: 'Verify token contract bytecode, honeypot risk, and DEX liquidity depth on Base before trading',
            url: 'https://rugshield-402.onrender.com/v1/scan',
            price: '0.010 USDC',
          },
        ]
      : undefined,
    inspection: res.inspection,
    payment_mode: 'local_fast',
    latency_ms: res.latency_ms,
    mode: res.mode,
  };
}
