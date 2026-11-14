import { Actor } from 'apify';
import { sanitizeContent } from './sanitize.js';

interface CanaryActorInput {
  content?: string;
  strict_mode?: boolean;
}

await Actor.init();

try {
  const input = (await Actor.getInput<CanaryActorInput>()) || {};
  const content = typeof input.content === 'string' ? input.content.trim() : '';
  if (!content) {
    throw new Error('Missing required string input: content');
  }
  const strictMode = input.strict_mode ?? true;

  console.log(`[canaryguard-apify] Processing content (length: ${content.length}, strict: ${strictMode})`);

  // Execute deterministic rule-based sanitization before charging PPE event
  const result = sanitizeContent(content, strictMode);

  // Charge 1 Pay-Per-Event (PPE) event: sanitize_content
  try {
    await Actor.charge({ eventName: 'sanitize_content', count: 1 });
    console.log('[canaryguard-apify] Charged 1 sanitize_content PPE event');
  } catch (chargeErr: any) {
    console.warn(`[canaryguard-apify] PPE charge notice: ${chargeErr?.message || chargeErr}`);
  }

  await Actor.pushData(result);
  console.log('[canaryguard-apify] Sanitization output successfully pushed to dataset');
  await Actor.exit();
} catch (err: any) {
  console.error(`[canaryguard-apify] Error: ${err.message}`);
  await Actor.fail(`CanaryGuard Actor execution failed: ${err.message}`);
}
