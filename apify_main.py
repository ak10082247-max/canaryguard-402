import asyncio
import logging
import os
import httpx
from typing import Dict, Any
from apify import Actor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("canaryguard.apify")

LIVE_CANARYGUARD_URL = "https://canaryguard-402.onrender.com/v1/sanitize"
PREVIEW_CANARYGUARD_URL = "https://canaryguard-402.onrender.com/v1/sanitize/preview"

async def run_actor():
    """
    Apify Pay-Per-Event (PPE) Actor entrypoint for CanaryGuard-402.
    Forwards inputs to live CanaryGuard-402 and charges sanitize_content only after HTTP 200.
    """
    async with Actor:
        actor_input: Dict[str, Any] = await Actor.get_input() or {}
        content = actor_input.get("content")
        if not isinstance(content, str) or not content.strip():
            await Actor.fail(status_message="Missing required string input: content")
            return
        strict_mode = bool(actor_input.get("strict_mode", True))
        use_preview = bool(actor_input.get("use_free_preview", False))
        logger.info(f"CanaryGuard-402 Apify Actor invoked for content length: {len(content)}")

        try:
            service_key = os.environ.get("CANARYGUARD_SERVICE_API_KEY") or os.environ.get("SERVICE_API_KEY")
            payment_sig = actor_input.get("payment_signature")
            headers: Dict[str, str] = {}
            target_url = PREVIEW_CANARYGUARD_URL if use_preview else LIVE_CANARYGUARD_URL
            if service_key:
                headers["x-api-key"] = service_key
            if isinstance(payment_sig, str) and payment_sig.strip():
                headers["PAYMENT-SIGNATURE"] = payment_sig.strip()

            async with httpx.AsyncClient(timeout=25.0) as client:
                resp = await client.post(
                    target_url,
                    headers=headers,
                    json={"content": content, "strict_mode": strict_mode},
                )
                if resp.status_code != 200:
                    await Actor.fail(
                        status_message=f"CanaryGuard live endpoint returned HTTP {resp.status_code}: {resp.text[:300]}"
                    )
                    return
                result = resp.json()

            if not use_preview:
                await Actor.charge(event_name="sanitize_content", count=1)

            await Actor.push_data(result)
            logger.info("Successfully pushed CanaryGuard result to Apify dataset.")
        except Exception as e:
            logger.error(f"Error during CanaryGuard sanitization: {e}")
            await Actor.fail(status_message=f"Sanitization error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(run_actor())
