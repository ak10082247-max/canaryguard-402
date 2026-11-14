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

export function inspectContent(content: string, strictMode = false): SanitizeResult {
  const findings = new Set<string>();
  const normalizedContent = content.replace(INVISIBLE_CHARACTERS, '');
  if (normalizedContent !== content) findings.add('concealed_unicode_removed');

  // Strict HTML tag stripping without corrupting math inequalities (e.g. 5 < 6 and 7 > 4)
  const htmlTagPattern = /<\/?(?:[a-zA-Z][a-zA-Z0-9:-]*)(?:\s+[^<>]*)?\/?>|<!--[\s\S]*?-->/gi;
  if (htmlTagPattern.test(normalizedContent)) findings.add('html_markup_removed');

  const threats = commandThreats(normalizedContent);
  for (const threat of threats) findings.add(threat);

  const injectionDetected = threats.length > 0;
  const addresses = extractAddresses(normalizedContent);

  let sanitizedContent = normalizedContent;
  if (injectionDetected) {
    sanitizedContent = strictMode ? '' : neutralizeCommandsInPlace(sanitizedContent);
  }

  let riskScore = 0.01;
  if (findings.has('html_markup_removed')) riskScore = 0.05;
  if (findings.has('concealed_unicode_removed')) riskScore = Math.max(riskScore, 0.2);
  if (threats.includes('role_delimiter_override')) riskScore = Math.max(riskScore, 0.85);
  if (threats.includes('instruction_override')) riskScore = Math.max(riskScore, 0.95);
  if (threats.includes('wallet_transfer_command')) riskScore = Math.max(riskScore, 0.98);
  for (const addr of addresses) riskScore = Math.max(riskScore, addr.risk_score);

  return {
    status: injectionDetected && strictMode ? 'blocked' : findings.size ? 'sanitized' : 'clean',
    risk_score: riskScore,
    injection_detected: injectionDetected,
    threats_neutralized: [...findings].sort(),
    sanitized_content: sanitizedContent,
    safety_receipt: 'local-deterministic-rule-execution',
    crypto_addresses: addresses,
    recommended_actions: addresses.length ? [
      {
        service: 'rugshield-402',
        description: 'Verify token contract bytecode, honeypot risk, and DEX liquidity depth on Base before trading',
        url: 'https://rugshield-402.onrender.com/v1/scan',
        price: '0.010 USDC',
      },
    ] : undefined,
    inspection: {
      method: 'deterministic-rules',
      guaranteed_safe: false,
      risk_score_semantics: 'heuristic severity, not a probability',
      limitations: [
        'Does not detect every obfuscated, multilingual, or novel instruction attack.',
        'Address scores reflect text context and do not verify ownership, reputation, or contract safety.',
        'Treat sanitized content as untrusted data; keep agent instructions and wallet authorization separate.',
      ],
    },
  };
}
