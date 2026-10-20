import abc
import asyncio
import json
import logging
import os
import requests
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


def resolve_config_value(val: Any) -> Any:
    """Resolve environment variable expressions like ${VAR_NAME} in strings."""
    if isinstance(val, str) and val.startswith("${") and val.endswith("}"):
        var_name = val[2:-1].strip()
        return os.environ.get(var_name, "")
    return val


class BaseLLMClient(abc.ABC):
    @abc.abstractmethod
    async def generate_response(self, system_instruction: str, prompt: str) -> str:
        """Asynchronously call the LLM and return the raw generated text."""
        pass


class GenericLLMClient(BaseLLMClient):
    """
    Generic LLM Client supporting Gemini, OpenAI-compatible REST APIs, and Ollama.
    Configured cleanly via api_url, api_key, and model from settings.yaml.
    """
    def __init__(
        self,
        provider: str = "gemini",
        api_url: str = "https://generativelanguage.googleapis.com/v1beta",
        api_key: str = "",
        model: str = "gemini-2.5-flash",
        timeout: int = 8,
    ):
        self.provider = (provider or "gemini").lower().strip()
        self.api_url = (api_url or "").rstrip("/")
        self.api_key = resolve_config_value(api_key) or os.environ.get("GEMINI_API_KEY", "")
        self.model = model or "gemini-2.5-flash"
        self.timeout = max(2, int(timeout))

    async def generate_response(self, system_instruction: str, prompt: str) -> str:
        """Generate response using the configured LLM API provider."""
        if self.provider == "gemini" or "googleapis.com" in self.api_url:
            return await self._call_gemini(system_instruction, prompt)
        elif self.provider in ("openai", "vllm", "litellm", "generic_http"):
            return await self._call_openai(system_instruction, prompt)
        elif self.provider == "ollama":
            return await self._call_ollama(system_instruction, prompt)
        else:
            # Default to Gemini if unknown
            return await self._call_gemini(system_instruction, prompt)

    async def chat_response(self, messages: List[Dict[str, str]]) -> str:
        """Generate multi-turn chat response."""
        if self.provider == "gemini" or "googleapis.com" in self.api_url:
            # Flatten chat into system and prompt
            sys_inst = ""
            user_parts = []
            for m in messages:
                role = m.get("role", "user")
                content = m.get("content", "")
                if role == "system":
                    sys_inst += f"{content}\n"
                else:
                    user_parts.append(f"[{role.upper()}]: {content}")
            return await self._call_gemini(sys_inst.strip(), "\n".join(user_parts))
        elif self.provider in ("openai", "vllm", "litellm", "generic_http"):
            return await self._call_openai_chat(messages)
        elif self.provider == "ollama":
            return await self._call_ollama_chat(messages)
        else:
            return await self.generate_response(messages[0].get("content", ""), messages[-1].get("content", ""))

    # -------------------------------------------------------------------------
    # Provider Implementations
    # -------------------------------------------------------------------------

    async def _call_gemini(self, system_instruction: str, prompt: str) -> str:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not set.")

        base = self.api_url or "https://generativelanguage.googleapis.com/v1beta"
        url = f"{base}/models/{self.model}:generateContent?key={self.api_key}"

        full_text = prompt
        if system_instruction:
            full_text = f"SYSTEM INSTRUCTIONS:\n{system_instruction}\n\nUSER PROMPT:\n{prompt}"

        payload = {
            "contents": [
                {
                    "parts": [{"text": full_text}]
                }
            ],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 2048,
            }
        }
        headers = {"Content-Type": "application/json"}

        connect_timeout = min(3.0, float(self.timeout))
        response = await asyncio.to_thread(
            requests.post,
            url,
            json=payload,
            headers=headers,
            timeout=(connect_timeout, float(self.timeout))
        )
        if response.status_code != 200:
            raise Exception(f"Gemini API returned error {response.status_code}: {response.text}")

        resp_json = response.json()
        candidates = resp_json.get("candidates", [])
        if not candidates:
            raise Exception(f"No candidates returned by Gemini: {resp_json}")

        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            raise Exception(f"No parts in Gemini candidate content: {resp_json}")

        return parts[0].get("text", "")

    async def _call_openai(self, system_instruction: str, prompt: str) -> str:
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})
        return await self._call_openai_chat(messages)

    async def _call_openai_chat(self, messages: List[Dict[str, str]]) -> str:
        endpoint = self.api_url
        if not endpoint.endswith("/chat/completions"):
            endpoint = f"{endpoint}/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}" if self.api_key else ""
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 2048,
        }

        connect_timeout = min(3.0, float(self.timeout))
        response = await asyncio.to_thread(
            requests.post,
            endpoint,
            json=payload,
            headers=headers,
            timeout=(connect_timeout, float(self.timeout))
        )
        if response.status_code != 200:
            raise Exception(f"OpenAI-compatible API error {response.status_code}: {response.text}")

        data = response.json()
        choices = data.get("choices", [])
        if not choices:
            raise Exception(f"Empty choices from API: {data}")

        return choices[0].get("message", {}).get("content", "")

    async def _call_ollama(self, system_instruction: str, prompt: str) -> str:
        url = f"{self.api_url}/api/generate"
        payload = {
            "model": self.model,
            "system": system_instruction,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.7, "num_predict": 2048}
        }
        connect_timeout = min(2.0, float(self.timeout))
        response = await asyncio.to_thread(
            requests.post,
            url,
            json=payload,
            timeout=(connect_timeout, float(self.timeout))
        )
        if response.status_code != 200:
            raise Exception(f"Ollama error {response.status_code}: {response.text}")
        return response.json().get("response", "")

    async def _call_ollama_chat(self, messages: List[Dict[str, str]]) -> str:
        url = f"{self.api_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.7, "num_predict": 2000}
        }
        connect_timeout = min(2.0, float(self.timeout))
        response = await asyncio.to_thread(
            requests.post,
            url,
            json=payload,
            timeout=(connect_timeout, float(self.timeout))
        )
        if response.status_code != 200:
            raise Exception(f"Ollama chat error {response.status_code}: {response.text}")
        return response.json().get("message", {}).get("content", "")


# Backward compatibility aliases
GeminiClient = GenericLLMClient
OllamaClient = GenericLLMClient
