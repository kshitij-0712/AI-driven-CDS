import json
from typing import Dict, Any

class PromptBuilder:
    @staticmethod
    def build_system_instruction() -> str:
        return """You are Galah, an adaptive, dynamic HTTP honeypot and cyber decoy assistant.
Your goal is to trick attackers into thinking they have successfully accessed or attacked a real web application.
You will generate realistic responses to HTTP requests dynamically.

You must respond ONLY with a valid JSON object matching the following structure:
{
  "status_code": 200,
  "headers": {
    "Content-Type": "text/html"
  },
  "body": "<!DOCTYPE html><html><head><title>System Response</title></head><body><div class='result'><p>System operation result details...</p></div></body></html>",
  "session_updates": {}
}

Guidelines:
1. "status_code": Use realistic HTTP status codes (200, 404, 500, 403, 401) depending on the context and attack progress.
2. "headers": Include appropriate headers like Content-Type ("text/html", "application/json", "text/plain").
3. "body": Return the complete HTML or content that the attacker will see. It MUST have visible, realistic text content inside the <body> tag (e.g., <h2> headers, descriptive paragraphs <p>, code blocks <pre><code>, stack traces, database errors, or forms). NEVER return an empty <body></body> or blank page.
4. "session_updates": Record internal state changes only. Do NOT put visible page text or visible errors only inside session_updates; all visible content MUST be directly in "body".
5. Do not write any explanations outside the JSON block. Return ONLY the JSON object.
"""

    @staticmethod
    def build_decoy_spec_instruction() -> str:
        return """You are Galah, an adaptive cyber decoy assistant.
Your goal is to propose declarative decoy web files to trap attackers inside an isolated decoy container.

You must respond ONLY with a valid JSON object matching the following structure:
{
  "decoy_persona": "vulnerable_web_app",
  "generated_files": [
    {
      "relative_path": "index.html",
      "content": "<!DOCTYPE html><html>...</html>"
    }
  ]
}

Strict Rules:
1. "generated_files": Return a list of at most 5 files.
2. "relative_path": Must be clean relative paths (e.g., "index.html", "admin/login.html", ".env", "api/v1/config.json"). NEVER use absolute paths or path traversal (no ../).
3. "content": High quality, realistic HTML, text, or JSON configuration content matching the target application theme and attack scenario.
4. Do NOT output any security actions, shell commands, or explanations outside the JSON object.
"""


    @staticmethod
    def build_user_prompt(
        request_context: Dict[str, Any],
        intent_label: str,
        app_structure: Dict[str, Any],
        session_memory: Dict[str, Any]
    ) -> str:
        # Simplify app structure for the prompt to save tokens
        clean_pages = {}
        for path, info in app_structure.get("pages", {}).items():
            clean_pages[path] = {
                "title": info.get("title", ""),
                "forms": info.get("forms", [])
            }
        
        app_info = {
            "target_url": app_structure.get("target_url", ""),
            "theme": app_structure.get("theme", ""),
            "pages": clean_pages
        }

        # Formulate instructions based on intent
        strategy = ""
        if intent_label.lower() == "recon":
            strategy = (
                "Strategy: The attacker is performing reconnaissance. Return a highly realistic fake page. "
                "CRITICAL: If the requested path is related to administration (e.g., /admin, /dev-admin, /config), you MUST generate a realistic fake 'Admin Console' or 'Admin Login' portal complete with HTML form input fields for 'Username' and 'Password'. "
                "Make the attacker believe they have found a real administrative login panel. "
                "If they are looking for backups or directories, serve a believable fake directory listing."
            )
        elif intent_label.lower() == "exploit":
            strategy = (
                "Strategy: The attacker is executing an exploit (SQLi, command injection, path traversal, XSS). "
                "Make the exploit seem successful to deceive the attacker! "
                "- If SQLi (e.g. on /profile): generate realistic fake dumped database records (admin, engineer, operator with password hashes and emails) or a realistic MariaDB/MySQL syntax error traceback matching the target application. NEVER return generic phrases like 'Database connection issues have been resolved'. "
                "- If path traversal (e.g. on /export): return realistic fake Linux file contents (e.g. root:x:0:0:root:/root:/bin/bash). "
                "- If command injection (e.g. on /api/ping): simulate the terminal output of ping followed by the output of their command (e.g. fake shadow/passwd output). "
                "- If XSS: return the reflected payload inside a visible element."
            )
        elif intent_label.lower() == "downloader":
            strategy = (
                "Strategy: The attacker is trying to download a malware payload. "
                "Simulate a download response or return a fake binary download or a text confirmation indicating "
                "successful download of a fake payload."
            )
        elif intent_label.lower() in ["scanner", "advanced_apt", "destructive"]:
            strategy = (
                "Strategy: Automated scanner or advanced persistent threat request. "
                "Return structured responses (e.g., standard API JSON formats) with fake data. "
                "Make it look highly realistic but entirely fabricated."
            )
        else:
            strategy = "Strategy: Return a default realistic response matching the app structure."

        prompt_dict = {
            "incoming_request": {
                "method": request_context.get("method", "GET"),
                "path": request_context.get("path", "/"),
                "query": request_context.get("query", ""),
                "body": request_context.get("body", ""),
                "headers": request_context.get("headers", {})
            },
            "intent_classification": intent_label,
            "target_app_knowledge": app_info,
            "attacker_session_memory": session_memory,
            "response_strategy": strategy
        }

        return f"""Generate the honeypot response for the following request context.
Remember to return ONLY a parseable JSON object matching the requested schema.

Context:
{json.dumps(prompt_dict, indent=2)}
"""
