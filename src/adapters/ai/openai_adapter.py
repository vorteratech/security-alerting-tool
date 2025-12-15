"""
OpenAI GPT AI adapter.

Provides security alert analysis using OpenAI models.
"""

import time
from typing import Any, Optional

import httpx

from ...config.logging import get_logger
from ..edr.base import Alert
from .base import BaseAIAdapter, AIAnalysisResult

logger = get_logger(__name__)


class OpenAIAdapter(BaseAIAdapter):
    """
    OpenAI API adapter.

    Uses GPT models for security alert analysis and recommendations.
    """

    API_BASE = "https://api.openai.com/v1"
    DEFAULT_MODEL = "gpt-4o-mini"  # Fast and cost-effective

    def __init__(self, api_key: str, model: str = "", **kwargs):
        """
        Initialize the OpenAI adapter.

        Args:
            api_key: OpenAI API key.
            model: Model to use (default: gpt-4o-mini).
            **kwargs: Additional configuration.
        """
        super().__init__(api_key, model or self.DEFAULT_MODEL, **kwargs)
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def default_model(self) -> str:
        return self.DEFAULT_MODEL

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.API_BASE,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=60.0,
            )
        return self._client

    async def analyze_alert(
        self,
        alert: Alert,
        enrichment_data: Optional[dict[str, Any]] = None,
        additional_context: str = "",
    ) -> AIAnalysisResult:
        """
        Analyze a security alert using OpenAI GPT.

        Args:
            alert: The normalized alert to analyze.
            enrichment_data: Optional threat intelligence data.
            additional_context: Additional context for analysis.

        Returns:
            AIAnalysisResult with analysis and recommendations.
        """
        start_time = time.time()

        try:
            client = await self._get_client()

            # Build the prompt
            user_prompt = self._build_alert_prompt(alert, enrichment_data, additional_context)

            # Call OpenAI API
            response = await client.post(
                "/chat/completions",
                json={
                    "model": self.model,
                    "max_tokens": 1500,
                    "temperature": 0.3,  # Lower for more consistent analysis
                    "messages": [
                        {"role": "system", "content": self.SECURITY_ANALYST_PROMPT},
                        {"role": "user", "content": user_prompt}
                    ],
                },
            )
            response.raise_for_status()

            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            usage = data.get("usage", {})
            tokens_used = usage.get("total_tokens", 0)

            # Parse the response
            result = self._parse_response(content)
            result.provider = self.provider_name
            result.model = self.model
            result.tokens_used = tokens_used
            result.analysis_time_ms = int((time.time() - start_time) * 1000)
            result.raw_response = data

            logger.info(
                "OpenAI analysis complete",
                alert_id=alert.id,
                tokens=tokens_used,
                time_ms=result.analysis_time_ms,
            )

            return result

        except Exception as e:
            logger.error("OpenAI analysis failed", alert_id=alert.id, error=str(e))
            return AIAnalysisResult(
                summary=f"Analysis failed: {str(e)}",
                description="Unable to complete AI analysis.",
                severity_assessment="unknown",
                confidence=0,
                provider=self.provider_name,
                model=self.model,
                analysis_time_ms=int((time.time() - start_time) * 1000),
            )

    def _parse_response(self, content: str) -> AIAnalysisResult:
        """
        Parse OpenAI's response into structured result.

        Args:
            content: Raw text response from OpenAI.

        Returns:
            Structured AIAnalysisResult.
        """
        # Default values
        summary = ""
        description = ""
        severity_assessment = "medium"
        confidence = 70
        recommended_actions = []
        immediate_actions = []
        investigation_steps = []

        lines = content.split("\n")
        current_section = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect section headers
            line_lower = line.lower()
            if "summary" in line_lower and (":" in line or line.startswith("#")):
                current_section = "summary"
                if ":" in line:
                    summary = line.split(":", 1)[1].strip().strip("*")
                continue
            elif "analysis" in line_lower and (":" in line or line.startswith("#")):
                current_section = "description"
                continue
            elif "severity" in line_lower and (":" in line or line.startswith("#")):
                current_section = "severity"
                if ":" in line:
                    sev_text = line.split(":", 1)[1].strip().lower()
                    if "critical" in sev_text:
                        severity_assessment = "critical"
                        confidence = 90
                    elif "high" in sev_text:
                        severity_assessment = "high"
                        confidence = 85
                    elif "medium" in sev_text:
                        severity_assessment = "medium"
                        confidence = 75
                    elif "low" in sev_text:
                        severity_assessment = "low"
                        confidence = 70
                continue
            elif "immediate" in line_lower and ("action" in line_lower or ":" in line):
                current_section = "immediate"
                continue
            elif "recommend" in line_lower and (":" in line or line.startswith("#")):
                current_section = "recommended"
                continue
            elif "investigation" in line_lower and (":" in line or line.startswith("#")):
                current_section = "investigation"
                continue

            # Process content based on current section
            if current_section == "summary" and not summary:
                summary = line.strip("*- ")
            elif current_section == "description":
                description += line + " "
            elif current_section == "immediate":
                if line.startswith(("-", "*", "•")) or (len(line) > 0 and line[0].isdigit() and "." in line[:3]):
                    action = line.lstrip("-*•0123456789. ").strip()
                    if action:
                        immediate_actions.append(action)
            elif current_section == "recommended":
                if line.startswith(("-", "*", "•")) or (len(line) > 0 and line[0].isdigit() and "." in line[:3]):
                    action = line.lstrip("-*•0123456789. ").strip()
                    if action:
                        recommended_actions.append(action)
            elif current_section == "investigation":
                if line.startswith(("-", "*", "•")) or (len(line) > 0 and line[0].isdigit() and "." in line[:3]):
                    step = line.lstrip("-*•0123456789. ").strip()
                    if step:
                        investigation_steps.append(step)

        # Fallbacks
        if not summary:
            for line in lines:
                if len(line.strip()) > 20:
                    summary = line.strip()[:200]
                    break
            if not summary:
                summary = "Security alert detected - review recommended"

        if not description:
            description = content[:500] if content else "No detailed analysis available."

        return AIAnalysisResult(
            summary=summary,
            description=description.strip(),
            severity_assessment=severity_assessment,
            confidence=confidence,
            recommended_actions=recommended_actions[:10],
            immediate_actions=immediate_actions[:5],
            investigation_steps=investigation_steps[:10],
        )

    async def test_connectivity(self) -> bool:
        """
        Test API connectivity to OpenAI.

        Returns:
            True if connection is successful.
        """
        try:
            client = await self._get_client()

            # List models to test auth
            response = await client.get("/models")
            response.raise_for_status()

            logger.info("OpenAI connectivity test passed")
            return True

        except Exception as e:
            logger.error("OpenAI connectivity test failed", error=str(e))
            raise

    async def close(self) -> None:
        """Clean up HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
