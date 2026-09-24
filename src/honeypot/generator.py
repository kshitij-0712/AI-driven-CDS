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
from agents.deception import (
    sanitize_and_validate_decoy_path,
    validate_decoy_payload,
    generate_fallback_decoy,
    generate_physical_decoy_files,
)

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
        import httpx

        pages = self.app_structure.get("pages", {}) if self.app_structure else {}
        
        # Always ensure root "/" is included
        paths_to_write = set(pages.keys())
        paths_to_write.add("/")
        for p_info in pages.values():
            for form in p_info.get("forms", []):
                act = form.get("action")
                m = form.get("method", "GET").upper()
                if act and act.startswith("/") and m == "GET":
                    paths_to_write.add(act)

        for path in paths_to_write:
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

    def _is_empty_or_broken_html(self, body: str) -> bool:
        """Detects if LLM generated an empty, blank, broken, or generic filler HTML body."""
        if not body or not str(body).strip():
            return True
        b_str = str(body)
        if re.search(r"<body[^>]*>\s*<\/body>", b_str, re.IGNORECASE):
            return True
        # Check for literal example placeholder copies from prompt or generic filler
        for p in [
            "<h2>heading</h2>", "page title", "content...", "<html>...</html>",
            "resolved successfully", "system response", "connection issues", "system operation result",
            "database connection issues", "database connection"
        ]:
            if p in b_str.lower():
                return True
        visible = re.sub(r"<[^>]+>", "", b_str).strip()
        if len(visible) < 15:
            return True
        return False

    def _synthesize_realistic_decoy_body(
        self,
        path: str,
        query: str,
        label: str,
        parsed_res: Dict[str, Any]
    ) -> str:
        """Synthesizes a realistic, target-app-matched response page with fake exploit data."""
        theme = self.app_structure.get("theme", "") if self.app_structure else ""
        if not theme or ":root" not in theme:
            theme = """:root {
                --bg-color: #0f172a;
                --text-color: #f8fafc;
                --card-bg: rgba(30, 41, 59, 0.7);
                --primary: #3b82f6;
                --primary-hover: #2563eb;
                --accent: #8b5cf6;
                --border: rgba(255, 255, 255, 0.1);
            }"""

        updates = parsed_res.get("session_updates", {}) if isinstance(parsed_res, dict) else {}
        err_msg = (
            updates.get("sql_error")
            or updates.get("error_message")
            or updates.get("message")
            or updates.get("details")
        )

        query_str = query or ""
        lower_q = query_str.lower()
        lower_p = path.lower()

        if "sql" in lower_q or "1=1" in lower_q or "or" in lower_q or "union" in lower_q or "select" in lower_q or "profile" in lower_p or "sql_error" in updates or "user_data" in updates:
            if updates.get("user_data") and isinstance(updates["user_data"], list):
                rows = []
                for u in updates["user_data"]:
                    uname = u.get("username", "")
                    email = u.get("email", "")
                    role = ",".join(u.get("roles", [])) if isinstance(u.get("roles"), list) else str(u.get("roles", ""))
                    pw_hash = u.get("password_hash", "$2y$12$...")
                    rows.append(f"{uname:<10} | {email:<25} | {role:<12} | {pw_hash}")
                table_header = f"[+] Database Query: SELECT * FROM users WHERE id = '{query_str}';\n[+] Status: Returned {len(rows)} record(s):\n\n"
                table_header += f"{'username':<10} | {'email':<25} | {'role':<12} | {'password_hash'}\n"
                table_header += "-" * 75 + "\n"
                err_msg = table_header + "\n".join(rows)
            elif not err_msg:
                rows = [
                    f"{'admin':<10} | {'admin@adaptive.network':<25} | {'superadmin':<12} | $2y$12$e8Y7hK9mP2vWxZ4qR1sTuO0e8Y7hK9mP2vWxZ4qR1sTuO0",
                    f"{'engineer':<10} | {'evelyn@adaptive.network':<25} | {'developer':<12} | $2y$12$9kLmP3vWxZ4qR1sTuO0e8Y7hK9mP2vWxZ4qR1sTuO09kLmP",
                    f"{'operator':<10} | {'liam@adaptive.network':<25} | {'ops_admin':<12} | $2y$12$4vWxZ4qR1sTuO0e8Y7hK9mP2vWxZ4qR1sTuO0e8Y7hK4vWxZ"
                ]
                table_header = f"[+] Database Query: SELECT * FROM users WHERE id = '{query_str}';\n[+] Status: Returned 3 record(s):\n\n"
                table_header += f"{'username':<10} | {'email':<25} | {'role':<12} | {'password_hash'}\n"
                table_header += "-" * 75 + "\n"
                err_msg = table_header + "\n".join(rows)
            title = "Profile Results"
            subtitle = "SQL Query Execution"
        elif "ping" in lower_p or "cat" in lower_q or "shadow" in lower_q or ";" in lower_q or "|" in lower_q:
            if not err_msg:
                err_msg = (
                    "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n"
                    "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms\n"
                    "--- 127.0.0.1 ping statistics ---\n"
                    "1 packets transmitted, 1 received, 0% packet loss\n\n"
                    "root:$6$rounds=40000$h7r2Y9kL0$xQ4bC8dE2fG...:19000:0:99999:7:::\n"
                    "daemon:*:19000:0:99999:7:::\n"
                    "bin:*:19000:0:99999:7:::\n"
                    "sys:*:19000:0:99999:7:::\n"
                    "www-data:*:19000:0:99999:7:::"
                )
            title = "Diagnostic Results"
            subtitle = "Command Execution Output"
        elif "export" in lower_p or "passwd" in lower_q or "etc" in lower_q or ".." in lower_q:
            if not err_msg:
                err_msg = (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                    "sync:x:4:65534:sync:/bin:/bin/sync\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
                )
            title = "File Export"
            subtitle = "File Content Stream"
        elif path in ("/", ""):
            # Home / Dashboard: Always serve the full cloned home page from target application
            import httpx
            try:
                resp = httpx.get(self.target_url, timeout=3)
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                pass
            title = "Adaptive Network Terminal"
            subtitle = "Dashboard"
        else:
            if not err_msg:
                err_msg = f"System notice: Decoy endpoint {path} processed request successfully."
            title = "Adaptive Network Terminal"
            subtitle = "Status 200 OK"

        # Try to embed into real application HTML template
        import httpx
        real_html = ""
        try:
            real_url = f"{self.target_url}{path}"
            if query:
                real_url += f"?{query}"
            resp = httpx.get(real_url, timeout=3)
            if resp.status_code == 200:
                real_html = resp.text
        except Exception:
            pass

        if not real_html:
            try:
                resp = httpx.get(self.target_url, timeout=3)
                if resp.status_code == 200:
                    real_html = resp.text
            except Exception:
                pass

        if real_html and '<div class="result-box">' in real_html:
            formatted_payload = (
                f'<div class="result-box">'
                f'<pre style="color:#a7f3d0;margin:0;font-size:0.9rem;white-space:pre-wrap;font-family:monospace;">{err_msg}</pre>'
                f'</div>'
            )
            return re.sub(r'<div class="result-box">[\s\S]*?</div>', formatted_payload, real_html, count=1)
        elif real_html and '<div class="container">' in real_html:
            split_idx = real_html.find('<div class="grid-2">')
            if split_idx != -1:
                header_part = real_html[:split_idx]
                card_part = f"""
                <div class="card" style="max-width:850px;margin:0 auto;width:100%;">
                    <h3>{title} <span class="badge">{subtitle}</span></h3>
                    <div class="result-box">
                        <pre style="color:#a7f3d0;margin:0;font-size:0.9rem;white-space:pre-wrap;font-family:monospace;">{err_msg}</pre>
                    </div>
                    <br>
                    <a href="/">← Back to Dashboard</a>
                </div>
                """
                return header_part + card_part + "</div></body></html>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        {theme}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background: var(--bg-color, #0f172a);
            color: var(--text-color, #f8fafc);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
            box-sizing: border-box;
        }}
        .card {{
            background: var(--card-bg, rgba(30, 41, 59, 0.7));
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border, rgba(255, 255, 255, 0.1));
            border-radius: 16px;
            padding: 28px;
            max-width: 800px;
            width: 100%;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
        }}
        h3 {{
            margin-top: 0;
            color: #f87171;
            font-size: 1.3rem;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 1px solid var(--border, rgba(255,255,255,0.1));
            padding-bottom: 12px;
        }}
        .badge {{
            font-size: 0.75rem;
            padding: 3px 8px;
            border-radius: 6px;
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        .code-block {{
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 16px;
            color: #fca5a5;
            font-family: monospace;
            font-size: 0.95rem;
            white-space: pre-wrap;
            line-height: 1.5;
            margin-top: 15px;
        }}
        .meta-info {{
            margin-top: 20px;
            font-size: 0.85rem;
            color: #64748b;
            border-top: 1px solid var(--border, rgba(255,255,255,0.1));
            padding-top: 12px;
        }}
        a {{
            color: var(--primary, #3b82f6);
            text-decoration: none;
            display: inline-block;
            margin-top: 20px;
            font-weight: 500;
        }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="card">
        <h3>{title} <span class="badge">{subtitle}</span></h3>
        <div class="code-block">{err_msg}</div>
        <div class="meta-info">Adaptive Decoy Environment | Active Session Monitoring</div>
        <a href="/">← Back to Dashboard</a>
    </div>
</body>
</html>"""

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
        method = request.method
        path = request.url.path
        query = str(request.url.query or "")
        label = decision.get("label", "Recon")
        is_dynamic = label.lower() in ("exploit", "downloader", "destructive", "advanced_apt") or method.upper() != "GET"

        await self._ensure_app_structure()

        # 1. Write baseline pages if not already written
        baseline_flag = os.path.join(html_dir, ".baseline_written")
        if not os.path.exists(baseline_flag):
            self._write_baseline_pages(html_dir)

        # If the request is for the root dashboard "/" and is Safe, preserve real dashboard
        if path in ("/", "") and label == "Safe":
            self._write_baseline_pages(html_dir)
            return
        
        cached_response = self.cache.get(session_id, method, path, query, body_str, is_dynamic)
        
        parsed_res = None
        if cached_response:
            parsed_res = cached_response
        else:
            try:
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

                # 5. Call LLM Router (Ollama/Mock fallback)
                raw_response = await self.router.generate(label, system_instruction, user_prompt)

                # 6. Parse Response JSON
                parsed_res = self._parse_json_response(raw_response)

                # 7. Update persistent attacker session memory
                updates = parsed_res.get("session_updates", {})
                self.state_manager.update_state(session_id, updates)

                # 8. Store in cache
                self.cache.set(session_id, method, path, query, body_str, is_dynamic, parsed_res)
            except Exception as e:
                logger.error(f"Error during LLM decoy generation: {e}. Falling back to static decoy.")
                fallback_files = generate_fallback_decoy(session_id)
                parsed_res = {
                    "status_code": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body": fallback_files[0]["content"],
                    "session_updates": {}
                }

        # 9. If parsed_res contains generated_files, validate and write them safely
        if "generated_files" in parsed_res and isinstance(parsed_res["generated_files"], list):
            try:
                validated_files = validate_decoy_payload(parsed_res)
                generate_physical_decoy_files(session_id, validated_files, base_dir=html_dir)
            except Exception as e:
                logger.warning(f"Payload validation failed for generated_files: {e}. Using fallback.")
                fallback_files = generate_fallback_decoy(session_id)
                generate_physical_decoy_files(session_id, fallback_files, base_dir=html_dir)
        else:
            # Write single response body using path sanitizer
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
                        
            try:
                file_path = sanitize_and_validate_decoy_path(html_dir, rel_path)
            except Exception as e:
                logger.warning(f"Path sanitization triggered for {rel_path}: {e}. Falling back to index.html")
                file_path = os.path.join(html_dir, "index.html")
                
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            body = parsed_res.get("body", "")
            if isinstance(body, dict):
                body = json.dumps(body)
                
            # Guard against empty, blank, or broken HTML generated by smaller LLMs
            if self._is_empty_or_broken_html(body):
                logger.info(f"LLM produced empty or broken body for {path}. Synthesizing realistic decoy page.")
                body = self._synthesize_realistic_decoy_body(path, query, label, parsed_res)

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
    error_page 405 =200 $uri;

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
                conf_content += f"        error_page 405 =200 /{escaped_route};\n"
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
