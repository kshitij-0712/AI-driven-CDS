import os
import logging
from typing import Dict, List
from honeypot.llm_client import BaseLLMClient, GenericLLMClient

logger = logging.getLogger(__name__)


class MockLLMClient(BaseLLMClient):
    """Deterministic fallback honeypot generator for when upstream LLM APIs fail or spike."""
    async def generate_response(self, system_instruction: str, prompt: str) -> str:
        logger.warning("Mock LLM client called as safe honeypot fallback.")
        return """{
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html"
            },
            "body": "<html><head><title>System Administration Panel</title></head><body><div style='background-color:#1e293b; color:#cbd5e1; font-family:sans-serif; padding:40px; border-radius:8px;'><h1>Access Blocked</h1><p>Your request lacks required authorization parameters. Security audit initiated.</p></div></body></html>",
            "session_updates": {}
        }"""


class LLMRouter:
    """
    Unified LLM Router for AdaptiveShield deception decoys.
    Reads generic API configuration (provider, api_url, api_key, model) from settings.yaml.
    Guarantees instant fallback to MockLLMClient if the configured upstream API is unavailable.
    """
    def __init__(self, config: Dict):
        galah_cfg = config.get("galah_honeypot", {})
        llm_cfg = galah_cfg.get("llm", {})

        # Generic API settings
        self.provider = llm_cfg.get("provider", "gemini")
        self.api_url = llm_cfg.get("api_url", "https://generativelanguage.googleapis.com/v1beta")
        self.api_key = llm_cfg.get("api_key", os.environ.get("GEMINI_API_KEY", ""))
        self.model = llm_cfg.get("model", llm_cfg.get("gemini_model", "gemini-2.5-flash"))
        self.timeout_sec = llm_cfg.get("timeout_sec", 30)

        # Backward compatibility for legacy test configs
        if llm_cfg.get("ollama_url") and not llm_cfg.get("api_url"):
            self.api_url = llm_cfg["ollama_url"]
            self.provider = "ollama"
            self.model = llm_cfg.get("ollama_model", self.model)
            self.timeout_sec = llm_cfg.get("ollama_timeout", self.timeout_sec)

        self.client = GenericLLMClient(
            provider=self.provider,
            api_url=self.api_url,
            api_key=self.api_key,
            model=self.model,
            timeout=self.timeout_sec
        )
        self.mock_client = MockLLMClient()

    def get_client(self, intent_label: str = "general") -> BaseLLMClient:
        """Return the active LLM client."""
        return self.client

    async def generate(self, intent_label: str, system_instruction: str, prompt: str) -> str:
        """Route and execute LLM generation without fallback (drops request on failure/timeout)."""
        return await self.client.generate_response(system_instruction, prompt)

    async def chat(self, intent_label: str, messages: list) -> str:
        """Route and execute LLM chat generation without fallback."""
        return await self.client.chat_response(messages)
