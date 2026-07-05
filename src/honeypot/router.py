import os
import logging
import json
from typing import Dict
from honeypot.llm_client import BaseLLMClient, GeminiClient, OllamaClient

logger = logging.getLogger(__name__)

class MockLLMClient(BaseLLMClient):
    async def generate_response(self, system_instruction: str, prompt: str) -> str:
        logger.warning("Mock LLM client called as a fallback.")
        return """{
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html"
            },
            "body": "<html><head><title>System Administration Panel</title></head><body><div style='background-color:#1e293b; color:#cbd5e1; font-family:sans-serif; padding:40px; border-radius:8px;'><h1>Access Blocked</h1><p>Your request lacks required authorization parameters. Security audit initiated.</p></div></body></html>",
            "session_updates": {}
        }"""

class LLMRouter:
    def __init__(self, config: Dict):
        galah_cfg = config.get("galah_honeypot", {})
        llm_cfg = galah_cfg.get("llm", {})

        self.default_provider = llm_cfg.get("default_provider", "ollama")
        self.router_policy = llm_cfg.get("router_policy", "dynamic")
        
        gemini_model = llm_cfg.get("gemini_model", "gemini-1.5-flash")
        ollama_model = llm_cfg.get("ollama_model", "llama3.2:1b")
        ollama_url = llm_cfg.get("ollama_url", "http://localhost:11434")

        self.gemini_key = os.environ.get("GEMINI_API_KEY", "")
        
        self.gemini_client = GeminiClient(api_key=self.gemini_key, model=gemini_model) if self.gemini_key else None
        self.ollama_client = OllamaClient(base_url=ollama_url, model=ollama_model)
        self.mock_client = MockLLMClient()

    def get_client(self, intent_label: str) -> BaseLLMClient:
        """Select the appropriate LLM client based on policy and intent."""
        if self.router_policy == "gemini_only":
            if self.gemini_client:
                return self.gemini_client
            logger.warning("Gemini policy chosen but GEMINI_API_KEY is missing. Falling back to Ollama.")
            return self.ollama_client

        if self.router_policy == "ollama_only":
            return self.ollama_client

        # Dynamic policy
        if intent_label.lower() in ["exploit", "downloader", "destructive", "advanced_apt"]:
            if self.gemini_client:
                logger.info(f"Routing request (intent: {intent_label}) to Gemini client.")
                return self.gemini_client
            else:
                logger.info(f"GEMINI_API_KEY missing. Routing request (intent: {intent_label}) to Ollama.")
                return self.ollama_client
        
        # Recon/Scanner/Default -> Ollama
        logger.info(f"Routing request (intent: {intent_label}) to Ollama client.")
        return self.ollama_client

    async def generate(self, intent_label: str, system_instruction: str, prompt: str) -> str:
        """Route and execute LLM generation with graceful failovers."""
        client = self.get_client(intent_label)
        try:
            return await client.generate_response(system_instruction, prompt)
        except Exception as e:
            logger.error(f"Primary LLM client failed: {e}. Attempting fallback...")
            
            if client == self.gemini_client and self.ollama_client:
                try:
                    logger.info("Falling back to Ollama...")
                    return await self.ollama_client.generate_response(system_instruction, prompt)
                except Exception as ex:
                    logger.error(f"Fallback Ollama client failed: {ex}")
            elif client == self.ollama_client and self.gemini_client:
                try:
                    logger.info("Falling back to Gemini...")
                    return await self.gemini_client.generate_response(system_instruction, prompt)
                except Exception as ex:
                    logger.error(f"Fallback Gemini client failed: {ex}")
            
            logger.info("Falling back to Mock LLM generator...")
            return await self.mock_client.generate_response(system_instruction, prompt)
