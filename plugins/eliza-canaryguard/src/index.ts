import { sanitizeAction } from './actions/sanitize.js';
import { canaryGuardEvaluator } from './evaluators/security.js';
import { canaryGuardProvider } from './providers/status.js';

export * from './types.js';
export * from './engine/rules.js';
export * from './x402.js';
export * from './actions/sanitize.js';
export * from './evaluators/security.js';
export * from './providers/status.js';

export const promptInjectionEvaluator = canaryGuardEvaluator;

export const canaryGuardPlugin = {
  name: 'canaryguard',
  description:
    'Prompt injection defense, Unicode steganography scrubber, and Base x402 API plugin for ElizaOS agents.',
  actions: [sanitizeAction],
  evaluators: [canaryGuardEvaluator],
  providers: [canaryGuardProvider],
};

export default canaryGuardPlugin;
