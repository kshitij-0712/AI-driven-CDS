import abc
import asyncio
import json
import logging
import requests
from typing import Optional

logger = logging.getLogger(__name__)

class BaseLLMClient(abc.ABC):
    @abc.abstractmethod
    async def generate_response(self, system_instruction: str, prompt: str) -> str:
        """Asynchronously call the LLM and return the raw generated text."""
        pass

class GeminiClient(BaseLLMClient):
    def __init__(self, api_key: str, model: str = "gemini-1.5-flash"):
        self.api_key = api_key
        self.model = model
        self.url = f"https://generativelanguage.googleapis.com/v1/models/{model}:generateContent?key={api_key}"

    async def generate_response(self, system_instruction: str, prompt: str) -> str:
        if not self.api_key:
            raise ValueError("Gemini API key is not set.")

        full_text = prompt
        if system_instruction:
            full_text = f"SYSTEM INSTRUCTIONS:\n{system_instruction}\n\nUSER PROMPT:\n{prompt}"

        payload = {
            "contents": [
                {
                    "parts": [{"text": full_text}]
                }
            ]
        }

        headers = {"Content-Type": "application/json"}

        try:
            response = await asyncio.to_thread(
                requests.post,
                self.url,
                json=payload,
                headers=headers,
                timeout=25
            )
            if response.status_code != 200:
                logger.error(f"Gemini API returned error {response.status_code}: {response.text}")
                raise Exception(f"Gemini API error: {response.text}")
            
            resp_json = response.json()
            candidates = resp_json.get("candidates", [])
            if not candidates:
                raise Exception(f"No candidates returned by Gemini: {resp_json}")
            
            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                raise Exception(f"No parts in Gemini candidate content: {resp_json}")
            
            return parts[0].get("text", "")
        except Exception as e:
            logger.error(f"Gemini client failed: {e}")
            raise

class OllamaClient(BaseLLMClient):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2:1b"):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.url = f"{self.base_url}/api/chat"

    async def generate_response(self, system_instruction: str, prompt: str) -> str:
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": "json"
        }

        try:
            response = await asyncio.to_thread(
                requests.post,
                self.url,
                json=payload,
                timeout=60
            )
            if response.status_code != 200:
                logger.error(f"Ollama returned error {response.status_code}: {response.text}")
                raise Exception(f"Ollama error: {response.text}")
            
            resp_json = response.json()
            message_content = resp_json.get("message", {}).get("content", "")
            return message_content
        except Exception as e:
            logger.error(f"Ollama client failed: {e}")
            raise
