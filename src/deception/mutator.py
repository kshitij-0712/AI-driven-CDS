"""
AdaptiveShield — Decoy Environment Mutator
Safely updates physical honeypot files, regenerates Nginx routing, and reacts to binary uploads.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

from agents.deception import (
    generate_physical_decoy_files,
    sanitize_and_validate_decoy_path,
    validate_decoy_payload,
)

logger = logging.getLogger(__name__)


class DecoyEnvironmentMutator:
    """
    Manages live physical decoy mutations inside Docker Nginx and Cowrie environments.
    Enforces strict path sanitization, size caps, and non-blocking Nginx reloads.
    """

    def __init__(self, host_runtime_dir: str = "./runtime"):
        self.host_runtime_dir = host_runtime_dir

    def write_decoy_page(
        self,
        html_dir: str,
        rel_path: str,
        body: str,
        content_type: str = "text/html",
    ) -> str:
        """
        Safely writes a single synthesized response page to the container's volume mount.
        """
        clean_rel = rel_path.strip("/")
        if not clean_rel:
            clean_rel = "index.html"
        elif "html" in content_type and not clean_rel.endswith(".html"):
            clean_rel += ".html"

        target_path = sanitize_and_validate_decoy_path(html_dir, clean_rel)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        with open(target_path, "w", encoding="utf-8") as f:
            f.write(body)

        logger.debug(f"Wrote decoy file to {target_path}")
        return target_path

    def write_generated_files(
        self,
        html_dir: str,
        generated_files: List[Dict[str, str]],
    ) -> List[str]:
        """
        Validates and safely writes a batch of generated decoy files.
        """
        payload = {"generated_files": generated_files}
        validated = validate_decoy_payload(payload)
        written_paths = []

        for item in validated:
            rel_p = item.get("relative_path", "")
            content = item.get("content", "")
            target_p = sanitize_and_validate_decoy_path(html_dir, rel_p)
            os.makedirs(os.path.dirname(target_p), exist_ok=True)
            with open(target_p, "w", encoding="utf-8") as f:
                f.write(content)
            written_paths.append(target_p)

        return written_paths

    def update_metadata_and_nginx_conf(
        self,
        base_dir: str,
        path: str,
        status_code: int,
        content_type: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Updates metadata.json and regenerates default.conf for Nginx.
        """
        metadata_path = os.path.join(base_dir, "metadata.json")
        conf_dir = os.path.join(base_dir, "conf")
        default_conf_path = os.path.join(conf_dir, "default.conf")

        metadata: Dict[str, Any] = {}
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
            except Exception:
                metadata = {}

        # Update metadata for this path
        clean_headers = {
            k: v for k, v in (headers or {}).items()
            if k.lower() not in ("content-type", "content-length")
        }
        metadata[path] = {
            "status_code": status_code,
            "content_type": content_type,
            "headers": clean_headers,
        }

        os.makedirs(base_dir, exist_ok=True)
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        # Regenerate Nginx default.conf
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

            escaped_route = route_path.strip("/")
            if "html" in c_type and not escaped_route.endswith(".html"):
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

        return default_conf_path

    def reload_nginx(self, container_id: str, docker_client: Any = None) -> bool:
        """Executes non-disruptive nginx -s reload inside the decoy container."""
        if not container_id or not docker_client:
            return False

        try:
            container = docker_client.containers.get(container_id)
            result = container.exec_run("nginx -s reload")
            return result.exit_code == 0
        except Exception as e:
            logger.warning(f"Failed to reload Nginx in container {container_id}: {e}")
            return False

    def mutate_on_binary_upload(
        self,
        session_id: str,
        decoy_dir: str,
        filename: str,
        triage_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Reactive mutation for Tactic T08 (Binary Dropper Mutation):
        Simulates filesystem artifacts expected by uploaded droppers.
        """
        triage = triage_info or {}
        family = triage.get("family_name", "generic_dropper")
        is_malicious = triage.get("is_malicious", True)

        staged_dir = os.path.join(decoy_dir, "downloads")
        os.makedirs(staged_dir, exist_ok=True)

        # Plant fake target environment files matching dropper expectations
        created_artifacts = []
        app_data_marker = os.path.join(decoy_dir, ".system_lock")
        with open(app_data_marker, "w") as f:
            f.write(f"SYSTEM_STATE=NORMAL\nLOCK_ID={session_id[:8]}\nMALWARE_STAGE_ACTIVE=1\n")
        created_artifacts.append(app_data_marker)

        return {
            "status": "mutated",
            "family_detected": family,
            "is_malicious": is_malicious,
            "created_artifacts": created_artifacts,
        }
