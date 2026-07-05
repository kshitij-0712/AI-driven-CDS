import os
import json
import logging
import re
from typing import Dict, Any
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from interceptor.session_store import SessionStore
from honeypot.crawler import AppCrawler
from honeypot.router import LLMRouter
from honeypot.prompt_builder import PromptBuilder
from honeypot.state_manager import SessionStateManager
from honeypot.cache import HoneypotCache

logger = logging.getLogger(__name__)

class HoneypotGenerator:
    def __init__(self, config: Dict, store: SessionStore):
        self.config = config
        self.store = store
        self.state_manager = SessionStateManager(store)
        self.router = LLMRouter(config)
        self.cache = HoneypotCache(config)
        
        galah_cfg = config.get("galah_honeypot", {})
        crawler_cfg = galah_cfg.get("crawler", {})
        
        self.target_url = crawler_cfg.get("target_url", "http://127.0.0.1:8090")
        self.structure_path = crawler_cfg.get("output_path", "./runtime/app_structure.json")
        self.auto_crawl = crawler_cfg.get("auto_crawl", True)
        self.app_structure = None

    async def _ensure_app_structure(self):
        """Load or crawl the target app structure."""
        if self.app_structure is not None:
            return
            
        if os.path.exists(self.structure_path):
            try:
                with open(self.structure_path, "r", encoding="utf-8") as f:
                    self.app_structure = json.load(f)
                logger.info(f"Loaded existing app structure from {self.structure_path}")
                return
            except Exception as e:
                logger.error(f"Failed to load app structure: {e}")

        # Auto crawl if missing
        if self.auto_crawl:
            logger.info(f"App structure file missing. Triggering auto crawl on {self.target_url}")
            crawler = AppCrawler(self.target_url, self.structure_path)
            await crawler.crawl()
            try:
                with open(self.structure_path, "r", encoding="utf-8") as f:
                    self.app_structure = json.load(f)
                return
            except Exception as e:
                logger.error(f"Failed to load crawled app structure: {e}")

        # Fallback empty structure
        self.app_structure = {
            "target_url": self.target_url,
            "theme": "",
            "pages": {}
        }

    async def generate_response(
        self,
        request: Request,
        body_str: str,
        decision: Dict[str, Any],
        session_id: str
    ) -> Response:
        """Orchestrate Galah Dynamic Honeypot page generation."""
        method = request.method
        path = request.url.path
        query = str(request.url.query or "")
        label = decision.get("label", "Recon")
        
        is_dynamic = label.lower() in ("exploit", "downloader", "destructive", "advanced_apt") or method.upper() != "GET"

        # Check Cache
        cached_response = self.cache.get(session_id, method, path, query, body_str, is_dynamic)
        if cached_response:
            return Response(
                content=cached_response.get("body", ""),
                status_code=cached_response.get("status_code", 200),
                headers=cached_response.get("headers", {})
            )

        # Ensure we have crawled application knowledge
        await self._ensure_app_structure()

        # Load persistent attacker session memory
        session_memory = self.state_manager.load_state(session_id)

        # Build system instruction and user prompt
        system_instruction = PromptBuilder.build_system_instruction()
        
        request_context = {
            "method": method,
            "path": path,
            "query": query,
            "body": body_str,
            "headers": dict(request.headers)
        }
        
        user_prompt = PromptBuilder.build_user_prompt(
            request_context=request_context,
            intent_label=label,
            app_structure=self.app_structure,
            session_memory=session_memory
        )

        # Call LLM Router (Ollama/Gemini/Mock fallback)
        raw_response = await self.router.generate(label, system_instruction, user_prompt)

        # Parse Response JSON
        parsed_res = self._parse_json_response(raw_response)

        # Update persistent attacker session memory
        updates = parsed_res.get("session_updates", {})
        self.state_manager.update_state(session_id, updates)

        # Store in cache
        self.cache.set(session_id, method, path, query, body_str, is_dynamic, parsed_res)

        # Construct FastAPI Response
        resp_headers = parsed_res.get("headers", {})
        resp_body = parsed_res.get("body", "")
        if isinstance(resp_body, dict):
            resp_body = json.dumps(resp_body)
            resp_headers["Content-Type"] = "application/json"
        
        return Response(
            content=resp_body,
            status_code=parsed_res.get("status_code", 200),
            headers=resp_headers
        )

    def _parse_json_response(self, text: str) -> Dict[str, Any]:
        """Tolerant parser that extracts a JSON object from raw text."""
        text_clean = text.strip()
        try:
            return json.loads(text_clean)
        except json.JSONDecodeError:
            pass

        match = re.search(r"(\{.*\})", text_clean, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        logger.error(f"Failed to parse LLM response as JSON: {text}")
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/html"},
            "body": "<html><body><div style='background-color:#1e293b; color:#cbd5e1; font-family:sans-serif; padding:40px; border-radius:8px;'><h1>Access Blocked</h1><p>Your request lacks required authorization parameters. Security audit initiated.</p></div></body></html>",
            "session_updates": {}
        }
