export interface CryptoAddressFinding {
  address: string;
  risk_score: number;
  reasons: string[];
}

export interface RecommendedAction {
  service: string;
  description: string;
  url: string;
  price: string;
}

export interface SanitizeResult {
  status: 'clean' | 'sanitized' | 'blocked';
  risk_score: number;
  injection_detected: boolean;
  threats_neutralized: string[];
  sanitized_content: string;
  safety_receipt: string;
  crypto_addresses: CryptoAddressFinding[];
  recommended_actions?: RecommendedAction[];
  inspection: {
    method: 'deterministic-rules' | 'hybrid-oracle' | string;
    guaranteed_safe: boolean;
    risk_score_semantics: string;
    limitations: string[];
  };
  payment_mode?: 'x402_paid' | 'x402_header' | 'free_preview' | 'local_fast';
  payment_response?: string | null;
  x402_upgrade_hint?: string;
  latency_ms?: number;
  mode?: 'local_in_process' | 'cloud_api';
}

export interface CanaryGuardConfig {
  serviceUrl?: string;
  paymentHeader?: string;
  privateKey?: `0x${string}` | string;
  strictMode?: boolean;
  localFast?: boolean;
  executionMode?: 'local_fast' | 'cloud_api';
  customFetch?: typeof fetch;
}

export type CanaryGuardPluginConfig = CanaryGuardConfig;
export type CanaryGuardResult = SanitizeResult;
