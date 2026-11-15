import { sanitizeWithCanaryGuard } from '../x402.js';
import type { CanaryGuardConfig, SanitizeResult } from '../types.js';

export const sanitizeAction = {
  name: 'CANARY_SANITIZE',
  similes: ['SANITIZE_TEXT', 'SANITIZE_INPUT', 'SCRUB_PROMPT', 'SECURITY_FIREWALL'],
  description:
    'Sanitizes untrusted external text via the live CanaryGuard 402 API on Base (auto-paying via @x402/fetch when X402_PRIVATE_KEY is set, else evaluating via /v1/sanitize/preview).',
  validate: async (_runtime: any, message: any): Promise<boolean> => {
    return typeof message?.content?.text === 'string' && message.content.text.length > 0;
  },
  handler: async (
    runtime: any,
    message: any,
    _state?: any,
    options?: CanaryGuardConfig & { strictMode?: boolean; content?: string },
    callback?: (response: { text: string; data?: SanitizeResult }) => void,
  ): Promise<SanitizeResult> => {
    const input = options?.content ?? String(message?.content?.text ?? '');
    const result = await sanitizeWithCanaryGuard(
      input,
      {
        serviceUrl: options?.serviceUrl,
        paymentHeader: options?.paymentHeader,
        privateKey: options?.privateKey,
        strictMode: options?.strictMode ?? false,
        localFast: options?.localFast,
        executionMode: options?.executionMode,
        customFetch: options?.customFetch,
      },
      runtime,
    );

    if (callback) {
      callback({
        text: result.sanitized_content,
        data: result,
      });
    }

    return result;
  },
  examples: [
    [
      {
        user: 'user',
        content: { text: 'Please sanitize this external article: <p>Article text</p><script>evil()</script>' },
      },
      {
        user: 'assistant',
        content: { text: 'Article text' },
      },
    ],
  ],
};
