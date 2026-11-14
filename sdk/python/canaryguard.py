"""CanaryGuard 402 - Python Client

Deterministic prompt-injection firewall and honeypot scrubber for AI agents.
$0.010 USDC per call on Base (eip155:8453) or Solana via x402.
"""

from typing import Any, Dict, List, Optional
import json
import urllib.request
import urllib.error


class CanaryGuard:
    def __init__(
        self,
        base_url: str = "https://canaryguard-402.onrender.com",
        payment_header: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.payment_header = payment_header

    def sanitize(
        self,
        content: str,
        strict_mode: bool = True,
        payment_header: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Sanitizes untrusted text before placing into LLM context.

        Args:
            content: Untrusted text, scraped HTML, tool output, or user message.
            strict_mode: When True (default), redacts high-risk addresses & base64 blobs,
                         and marks exfiltration commands as blocked.
            payment_header: Optional X-PAYMENT authorization signature.

        Returns:
            Dict containing status ("clean" | "sanitized" | "blocked"),
            risk_score (0.0 - 1.0), injection_detected (bool),
            threats_neutralized, crypto_addresses, sanitized_content, and safety_receipt.
        """
        url = f"{self.base_url}/v1/sanitize"
        payload = json.dumps({"content": content, "strict_mode": strict_mode}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        sig = payment_header or self.payment_header
        if sig:
            headers["X-PAYMENT"] = sig

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            if e.code == 402:
                pr = e.headers.get("PAYMENT-REQUIRED")
                raise PermissionError(
                    f"402 Payment Required: 0.010 USDC required on Base/Solana. Challenge: {pr}"
                )
            raise RuntimeError(f"CanaryGuard HTTP {e.code}: {body}")

    def health(self) -> Dict[str, Any]:
        """Check CanaryGuard service health."""
        req = urllib.request.Request(f"{self.base_url}/health")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def stats(self) -> Dict[str, Any]:
        """Fetch live settlement stats and metrics."""
        req = urllib.request.Request(f"{self.base_url}/stats")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
