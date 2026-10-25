/**
 * CanaryGuard — deterministic, sub-millisecond prompt-injection firewall.
 *
 * Hardening notes (bounty fix):
 *  - Input is NFKC-normalised and stripped of zero-width / soft-hyphen
 *    characters before matching, so `Ign\u200Bore prev\u200Bious ...` and
 *    full-width `Ｉｇｎｏｒｅ ...` payloads no longer slip through.
 *  - Override detection tolerates filler words between verb and target
 *    ("ignore ALL of the previous system instructions").
 *  - Added delimiter, role-hijack and system-prompt exfiltration families.
 */

export type SanitizeMode = "strict" | "balanced" | "permissive";

export const MODES: SanitizeMode[] = ["strict", "balanced", "permissive"];
export const DEFAULT_MODE: SanitizeMode = "strict";

export interface SanitizeFinding {
  id: string;
  label: string;
  weight: number;
  match: string;
}

export interface SanitizeResult {
  status: "clean" | "blocked";
  risk_score: number;
  findings: SanitizeFinding[];
  matches: SanitizeFinding[];
  sanitized: string;
  redacted: string;
  mode: SanitizeMode;
}

interface Rule {
  id: string;
  label: string;
  weight: number;
  re: RegExp;
}

/** Zero-width, soft hyphen and other invisible joiners used to split tokens. */
const INVISIBLE = /[\u00AD\u180E\u200B-\u200D\u2060\uFEFF]/g;

/**
 * Canonicalise the payload so that homoglyph / invisible-character evasion
 * cannot defeat the regex engine.
 */
function normalize(input: string): string {
  return input
    .normalize("NFKC")
    .replace(INVISIBLE, "")
    .replace(/[\u2018\u2019\u201A\u201B]/g, "'")
    .replace(/[\u201C\u201D\u201E]/g, '"')
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\s+/g, " ")
    .trim();
}

const RULES: Rule[] = [
  {
    id: "override.prior",
    label: "Instruction override of prior context",
    weight: 45,
    re: /\b(?:ignore|disregard|forget|override|bypass|skip|drop|discard)\s+(?:all\s+)?(?:of\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding|foregoing|original|initial|existing)\s+(?:\w+\s+){0,2}(?:instructions?|prompts?|rules?|directions?|guidelines?|constraints?)\b/i,
  },
  {
    id: "override.system",
    label: "Instruction override of the system prompt",
    weight: 45,
    re: /\b(?:ignore|disregard|forget|override|bypass)\s+(?:the\s+)?system\s+(?:prompt|message|instructions?|rules?)\b/i,
  },
  {
    id: "override.loose",
    label: "Loose instruction override",
    weight: 30,
    re: /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:instructions?|prompts?|rules?|directions?)\b/i,
  },
  {
    id: "exfil.system_prompt",
    label: "System prompt exfiltration",
    weight: 25,
    re: /\b(?:reveal|print|show|output|repeat|dump|leak|display|echo)\b[^.\n]{0,30}\b(?:system\s+prompt|instructions?|rules?|prompt|context)\b/i,
  },
  {
    id: "forget.everything",
    label: "Forget everything",
    weight: 25,
    re: /\bforget\s+(?:everything|all)\b/i,
  },
  { id: "system_prompt", label: "System prompt reference", weight: 20, re: /\bsystem\s+prompt\b/i },
  { id: "role.you_are_now", label: "Role hijack", weight: 20, re: /\byou\s+are\s+now\b/i },
  {
    id: "new.instructions",
    label: "New instructions block",
    weight: 20,
    re: /\bnew\s+(?:instructions?|rules?|task|persona|role|system\s+prompt)\b/i,
  },
  {
    id: "jailbreak",
    label: "Jailbreak / developer mode",
    weight: 20,
    re: /\bjailbreak\b|\bDAN\b|\bdeveloper\s+mode\b/i,
  },
  { id: "role.from_now_on", label: "Persistent role switch", weight: 15, re: /\bfrom\s+now\s+on\b/i },
  {
    id: "role.role_tag",
    label: "Role tag",
    weight: 15,
    re: /\brole\s*:\s*(?:system|developer|assistant)\b/i,
  },
  {
    id: "delimiter.role_prefix",
    label: "Line-leading role prefix",
    weight: 15,
    re: /^\s*(?:system|assistant|developer)\s*:/im,
  },
  {
    id: "delimiter.chat_template",
    label: "Chat template token",
    weight: 15,
    re: /<\|?\s*(?:system|im_start|im_end|endoftext)\s*\|?>/i,
  },
  { id: "override.bare", label: "Bare override keyword", weight: 15, re: /\boverride\b/i },
  { id: "role.act_as", label: "Act as", weight: 12, re: /\bact\s+as\b/i },
  {
    id: "delimiter.fence",
    label: "Fenced block delimiter",
    weight: 12,
    re: /```(?:system|prompt|instructions|json|text)/i,
  },
  { id: "delimiter.bracket", label: "Bracket role delimiter", weight: 12, re: /\[\/?(?:system|inst|sys)\]/i },
  {
    id: "session.restart",
    label: "New session marker",
    weight: 12,
    re: /\b(?:begin|start)\s+(?:a\s+)?(?:new|fresh)\s+(?:session|context|conversation)\b/i,
  },
  { id: "role.pretend", label: "Pretend", weight: 10, re: /\bpretend\b/i },
  {
    id: "silence",
    label: "Silence instruction",
    weight: 10,
    re: /\bdo\s+not\s+(?:tell|mention|reveal|say|disclose)\b/i,
  },
  {
    id: "note.to_model",
    label: "Note addressed to the model",
    weight: 10,
    re: /\bnote\s+to\s+(?:the\s+)?(?:ai|assistant|model|llm)\b/i,
  },
  {
    id: "end_of_context",
    label: "End-of-context marker",
    weight: 10,
    re: /\bend\s+of\s+(?:prompt|instructions?|context)\b/i,
  },
  { id: "delimiter.heading", label: "Markdown heading", weight: 8, re: /^\s*#{2,}\s*\S+/m },
  {
    id: "delimiter.rule",
    label: "Horizontal rule delimiter",
    weight: 8,
    re: /^\s*(?:-{3,}|={3,}|<{3,}|>{3,}|\*{3,})\s*$/m,
  },
  { id: "instead", label: "Contrastive instruction", weight: 8, re: /\binstead\b/i },
  { id: "important", label: "Emphasis marker", weight: 8, re: /\bimportant\s*:/i },
  { id: "tool_call", label: "Tool/function call", weight: 8, re: /\b(?:tool|function)\s+call\b/i },
  { id: "base64", label: "Encoded payload", weight: 8, re: /\bbase64\b/i },
  { id: "canary", label: "Canary token", weight: 8, re: /\bcanary\b/i },
  {
    id: "output.directive",
    label: "Output directive",
    weight: 8,
    re: /\b(?:must|should)\s+(?:respond|reply|answer|output|return)\b/i,
  },
];

const THRESHOLDS: Record<SanitizeMode, number> = {
  strict: 30,
  balanced: 50,
  permissive: 70,
};

/**
 * Score a prompt against the rule set and classify it for the given mode.
 * Deterministic and allocation-light: no network, no model calls.
 */
export function sanitizePrompt(prompt: string, mode: SanitizeMode = DEFAULT_MODE): SanitizeResult {
  const raw = typeof prompt === "string" ? prompt : String(prompt ?? "");
  const sanitized = normalize(raw);
  const findings: SanitizeFinding[] = [];

  for (const rule of RULES) {
    const hit = rule.re.exec(sanitized);
    if (hit) {
      findings.push({
        id: rule.id,
        label: rule.label,
        weight: rule.weight,
        match: hit[0].slice(0, 120),
      });
    }
  }

  const risk_score = Math.min(
    100,
    findings.reduce((total, finding) => total + finding.weight, 0),
  );

  const threshold = THRESHOLDS[mode] ?? THRESHOLDS[DEFAULT_MODE];
  const status: SanitizeResult["status"] = risk_score >= threshold ? "blocked" : "clean";

  return {
    status,
    risk_score,
    findings,
    matches: findings,
    sanitized,
    redacted: sanitized,
    mode,
  };
}

export const sanitize = sanitizePrompt;
export default sanitizePrompt;
