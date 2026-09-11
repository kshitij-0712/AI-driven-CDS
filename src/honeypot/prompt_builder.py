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
  "body": "<html>...</html>",
  "session_updates": {
    "key": "value"
  }
}

Guidelines:
1. "status_code": Use realistic HTTP status codes (200, 404, 500, 403, 401) depending on the context and attack progress.
2. "headers": Include appropriate headers like Content-Type ("text/html", "application/json", "text/plain").
3. "body": Return realistic content. If HTML is returned, use modern and premium styled design (incorporate the style/theme from the target application). Do not use basic unstyled pages. Ensure it matches the look of the crawled pages.
4. "session_updates": Record any state changes made by the attacker's action (e.g., if they added a user, uploaded a file, changed settings, or executed commands). This will be passed back to you in subsequent requests.
5. Do not write any explanations outside the JSON block. Return ONLY the JSON object.
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
                "Make the exploit seem successful or very close to successful! "
                "- If SQLi: return a realistic database error, database exception, stack trace, and software versions (e.g., MariaDB/MySQL/PostgreSQL version info) to make the attacker believe they triggered a vulnerable database query. Do NOT return normal successful pages. "
                "- If path traversal: return a believable fake version of the requested file (e.g., fake /etc/passwd or system logs). "
                "- If command injection: simulate the terminal output of their command inside a realistic response. "
                "- If XSS: return the reflected payload or store it in 'session_updates' to show later."
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
