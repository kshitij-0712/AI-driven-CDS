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

    def _generate_baseline_page(self, path: str) -> str:
        if not self.app_structure:
            return "<html><body>Page not found</body></html>"
            
        page_info = self.app_structure.get("pages", {}).get(path)
        if not page_info:
            return "<html><body>Page not found</body></html>"
            
        title = page_info.get("title", "Daamy App")
        theme = self.app_structure.get("theme", "")
        
        # Generate navigation links
        nav_html = ""
        for link in page_info.get("links", []):
            link_title = self.app_structure.get("pages", {}).get(link, {}).get("title", link)
            nav_html += f'<a href="{link}">{link_title}</a>\n'
            
        # Generate forms
        forms_html = ""
        for form in page_info.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "GET")
            inputs_html = ""
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                inp_type = inp.get("type", "text")
                placeholder = inp.get("placeholder", "")
                inputs_html += f'''
                <div class="form-group">
                    <label for="{name}">{name.capitalize()}</label>
                    <input type="{inp_type}" id="{name}" name="{name}" placeholder="{placeholder}">
                </div>
                '''
            forms_html += f'''
            <div class="card">
                <h3>{action.replace("/", "").capitalize() or "Submit"}</h3>
                <form action="{action}" method="{method}">
                    {inputs_html}
                    <button type="submit">Submit</button>
                </form>
            </div>
            '''
            
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        {theme}
        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color, #0f172a);
            color: var(--text-color, #f8fafc);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }}
        .container {{
            background-color: var(--card-bg, rgba(30, 41, 59, 0.7));
            backdrop-filter: blur(10px);
            padding: 3rem 2.5rem;
            border-radius: 12px;
            border: 1px solid var(--border, rgba(255, 255, 255, 0.1));
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
            max-width: 600px;
            width: 100%;
        }}
        h1 {{
            color: var(--text-color);
            font-size: 2rem;
            margin-bottom: 2rem;
            font-weight: 700;
            text-align: center;
        }}
        .card {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border);
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
        }}
        .form-group {{
            margin-bottom: 1.2rem;
        }}
        label {{
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
            opacity: 0.8;
        }}
        input {{
            width: 100%;
            padding: 0.75rem 1rem;
            background-color: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-color);
            box-sizing: border-box;
        }}
        button {{
            width: 100%;
            padding: 0.8rem;
            background-color: var(--primary, #3b82f6);
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
        }}
        button:hover {{
            background-color: var(--primary-hover, #2563eb);
        }}
        .footer-links {{
            margin-top: 2rem;
            text-align: center;
        }}
        .footer-links a {{
            color: var(--accent, #8b5cf6);
            text-decoration: none;
            margin: 0 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        {forms_html}
        <div class="footer-links">
            {nav_html}
        </div>
    </div>
</body>
</html>
"""
        return html

    def _write_baseline_pages(self, html_dir: str):
        if not self.app_structure:
            return
            
        import httpx
        
        pages = self.app_structure.get("pages", {})
        for path in pages.keys():
            # Map path to file name
            rel_path = path.strip("/")
            if not rel_path:
                rel_path = "index.html"
            else:
                rel_path += ".html"
                
            file_path = os.path.join(html_dir, rel_path)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Fetch the actual HTML from the real application to clone it exactly
            real_page_url = f"{self.target_url}{path}"
            try:
                response = httpx.get(real_page_url, timeout=5)
                if response.status_code == 200:
                    content = response.text
                    logger.info(f"Successfully cloned real page {real_page_url} to decoy {file_path}")
                else:
                    logger.warning(f"Failed to clone real page {real_page_url} (status {response.status_code}), falling back to template")
                    content = self._generate_baseline_page(path)
            except Exception as e:
                logger.warning(f"Exception cloning real page {real_page_url} ({e}), falling back to template")
                content = self._generate_baseline_page(path)
                
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
                
        # Write .baseline_written file to indicate we finished
        with open(os.path.join(html_dir, ".baseline_written"), "w") as f:
            f.write("true")

    async def prepare_decoy_files(
        self,
        session_id: str,
        decision: Dict[str, Any],
        request: Request,
        body_str: str,
        html_dir: str,
        container_id: str,
        decoys_manager: Any
    ):
        """Bakes/updates static content in the decoy container's HTML directory."""
        await self._ensure_app_structure()
        
        # 1. Write baseline pages if not already written
        baseline_flag = os.path.join(html_dir, ".baseline_written")
        if not os.path.exists(baseline_flag):
            self._write_baseline_pages(html_dir)

        # 2. Check Cache
        method = request.method
        path = request.url.path
        query = str(request.url.query or "")
        label = decision.get("label", "Recon")
        is_dynamic = label.lower() in ("exploit", "downloader", "destructive", "advanced_apt") or method.upper() != "GET"
        
        cached_response = self.cache.get(session_id, method, path, query, body_str, is_dynamic)
        
        parsed_res = None
        if cached_response:
            parsed_res = cached_response
        else:
            # 3. Load persistent attacker session memory
            session_memory = self.state_manager.load_state(session_id)

            # 4. Build system instruction and user prompt
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

            # 5. Call LLM Router (Ollama/Gemini/Mock fallback)
            raw_response = await self.router.generate(label, system_instruction, user_prompt)

            # 6. Parse Response JSON
            parsed_res = self._parse_json_response(raw_response)

            # 7. Update persistent attacker session memory
            updates = parsed_res.get("session_updates", {})
            self.state_manager.update_state(session_id, updates)

            # 8. Store in cache
            self.cache.set(session_id, method, path, query, body_str, is_dynamic, parsed_res)

        # 9. Write the response body to the corresponding file path in the html_dir
        rel_path = path.strip("/")
        if not rel_path:
            rel_path = "index.html"
        else:
            # If the response is HTML and not ending in .html, append .html
            headers = parsed_res.get("headers", {})
            content_type = headers.get("Content-Type", headers.get("content-type", "text/html"))
            if "html" in content_type or parsed_res.get("body", "").strip().startswith("<"):
                if not rel_path.endswith(".html"):
                    rel_path += ".html"
                    
        file_path = os.path.join(html_dir, rel_path)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        body = parsed_res.get("body", "")
        if isinstance(body, dict):
            body = json.dumps(body)
            
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(body)

        # 10. Update metadata.json in base directory (parent of html_dir)
        base_dir = os.path.dirname(html_dir)
        metadata_path = os.path.join(base_dir, "metadata.json")
        
        metadata = {}
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
            except Exception:
                pass
                
        # Record path info
        headers = parsed_res.get("headers", {})
        content_type = headers.get("Content-Type", headers.get("content-type", "text/html"))
        metadata[path] = {
            "status_code": parsed_res.get("status_code", 200),
            "content_type": content_type,
            "headers": {k: v for k, v in headers.items() if k.lower() not in ("content-type", "content-length")},
        }
        
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        # 11. Regenerate Nginx config default.conf
        conf_dir = os.path.join(base_dir, "conf")
        default_conf_path = os.path.join(conf_dir, "default.conf")
        
        conf_content = """server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html index.htm;

    location / {
        try_files $uri $uri.html $uri/ /index.html =404;
        error_page 405 =200 $uri;
    }
"""
        for route_path, info in metadata.items():
            if route_path == "/":
                continue
                
            status = info.get("status_code", 200)
            c_type = info.get("content_type", "text/html")
            route_headers = info.get("headers", {})
            
            # Map request route to filesystem relative path
            escaped_route = route_path.strip("/")
            if "html" in c_type:
                if not escaped_route.endswith(".html"):
                    escaped_route += ".html"
                    
            conf_content += f"\n    location = {route_path} {{\n"
            conf_content += f"        default_type {c_type};\n"
            
            for k, v in route_headers.items():
                conf_content += f'        add_header "{k}" "{v}";\n'
                
            if status == 200:
                conf_content += f"        try_files /{escaped_route} /index.html =404;\n"
            elif status in (301, 302):
                loc = route_headers.get("Location", route_headers.get("location", "/"))
                conf_content += f"        return {status} {loc};\n"
            else:
                conf_content += f"        error_page {status} /{escaped_route};\n"
                conf_content += f"        return {status};\n"
                
            conf_content += "    }\n"
            
        conf_content += "}\n"
        
        os.makedirs(conf_dir, exist_ok=True)
        with open(default_conf_path, "w") as f:
            f.write(conf_content)

        # 12. Reload Nginx in container
        if container_id and decoys_manager:
            try:
                container = decoys_manager._docker.containers.get(container_id)
                container.exec_run("nginx -s reload")
            except Exception:
                pass

    async def generate_response(
        self,
        request: Request,
        body_str: str,
        decision: Dict[str, Any],
        session_id: str
    ) -> Response:
        """Orchestrate Galah Dynamic Honeypot page generation (FastAPI response wrapper)."""
        method = request.method
        path = request.url.path
        query = str(request.url.query or "")
        label = decision.get("label", "Recon")
        
        is_dynamic = label.lower() in ("exploit", "downloader", "destructive", "advanced_apt") or method.upper() != "GET"

        # Check Cache
        cached_response = self.cache.get(session_id, method, path, query, body_str, is_dynamic)
        if cached_response:
            resp_headers = cached_response.get("headers", {})
            resp_body = cached_response.get("body", "")
            if isinstance(resp_body, dict):
                resp_body = json.dumps(resp_body)
                resp_headers["Content-Type"] = "application/json"
            return Response(
                content=resp_body,
                status_code=cached_response.get("status_code", 200),
                headers=resp_headers
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
