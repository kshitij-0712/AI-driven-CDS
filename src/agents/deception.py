import time
import os
import shutil
import uuid
from dataclasses import dataclass
from typing import Dict, Optional


def decide_decoy_action(intent_label):
    mapping = {
        "Safe": "monitor",
        "Recon": "deploy_low_interaction",
        "Downloader": "deploy_medium_interaction",
        "Exploit": "deploy_high_interaction",
        "Destructive": "isolate_and_deploy_high_interaction",
        "ADVANCED_APT": "contain_and_shadow",
    }
    return mapping.get(intent_label, "monitor")


@dataclass
class DecoyInstance:
    container_id: str
    base_url: str
    decoy_type: str
    last_used_ts: float
    session_id: str = ""
    html_dir: str = ""


class DecoyManager:
    """Manage decoy containers using Docker API.

    The manager is defensive by design:
    - If Docker SDK is missing, it falls back to `fallback_url`.
    - If Docker daemon is unreachable, it falls back to `fallback_url`.
    - If spawning fails, it returns `None` and caller can decide the action.
    """

    def __init__(
        self,
        http_image: str,
        ssh_image: str = "cowrie/cowrie:latest",
        max_instances: int = 5,
        idle_timeout_sec: int = 300,
        fallback_url: Optional[str] = None,
    ):
        self.http_image = http_image
        self.ssh_image = ssh_image
        self.max_instances = max_instances
        self.idle_timeout_sec = idle_timeout_sec
        self.fallback_url = fallback_url

        self._active_http: Dict[str, DecoyInstance] = {}
        self._active_ssh: Dict[str, DecoyInstance] = {}
        self._docker = None

        try:
            import docker

            self._docker = docker.from_env()
            self._docker.ping()
            self._discover_existing_decoys()
        except Exception:
            self._docker = None

    def _discover_existing_decoys(self):
        """Discover and reuse existing decoy containers from previous runs."""
        if not self.docker_available:
            return
        try:
            containers = self._docker.containers.list(all=True, filters={"label": "adaptiveshield.decoy=true"})
            now = time.time()
            for container in containers:
                if container.status != "running":
                    container.start()
                container.reload()
                port_bindings = container.attrs.get("NetworkSettings", {}).get("Ports", {})
                decoy_type = container.labels.get("adaptiveshield.decoy_type", "http")
                session_id = container.labels.get("adaptiveshield.session_id", "")
                
                # Get volume mappings
                mounts = container.attrs.get("Mounts", [])
                html_dir = ""
                for m in mounts:
                    if m.get("Destination") == "/usr/share/nginx/html":
                        host_source = m.get("Source")
                        # Translate host source path back to local path inside core container
                        if "runtime/" in host_source:
                            rel_part = host_source.split("runtime/", 1)[1]
                            html_dir = os.path.abspath(os.path.join("./runtime", rel_part))
                        else:
                            html_dir = host_source
                        break

                if decoy_type == "http":
                    binding = port_bindings.get("80/tcp")
                    if binding:
                        host_port = binding[0].get("HostPort")
                        if host_port:
                            instance = DecoyInstance(
                                container_id=container.id,
                                base_url=f"http://127.0.0.1:{host_port}",
                                decoy_type="http",
                                last_used_ts=now,
                                session_id=session_id,
                                html_dir=html_dir,
                            )
                            self._active_http[container.id] = instance
                elif decoy_type == "ssh":
                    binding = port_bindings.get("2222/tcp")
                    if binding:
                        host_port = binding[0].get("HostPort")
                        if host_port:
                            instance = DecoyInstance(
                                container_id=container.id,
                                base_url=host_port,
                                decoy_type="ssh",
                                last_used_ts=now,
                                session_id=session_id,
                            )
                            self._active_ssh[container.id] = instance
        except Exception:
            pass

    @property
    def docker_available(self) -> bool:
        return self._docker is not None

    def pre_pull_images(self, images):
        """Pre-pull decoy images to reduce first-hit latency."""
        if not self.docker_available:
            return

        for image in images:
            try:
                self._docker.images.pull(image)
            except Exception:
                continue

    def _pick_existing_http_decoy(self) -> Optional[DecoyInstance]:
        if not self._active_http:
            return None
        # Reuse the least recently used decoy.
        return sorted(self._active_http.values(), key=lambda d: d.last_used_ts)[0]

    def _spawn_http_decoy(self, session_id: str) -> Optional[DecoyInstance]:
        if not self.docker_available:
            return None

        try:
            actual_session_id = session_id
            if session_id == "prewarm":
                actual_session_id = f"prewarm_{uuid.uuid4().hex[:8]}"

            # Local paths inside core container for writing files
            local_base_dir = os.path.abspath(f"./runtime/decoy_http/{actual_session_id}")
            html_dir = os.path.join(local_base_dir, "html")
            conf_dir = os.path.join(local_base_dir, "conf")
            os.makedirs(html_dir, exist_ok=True)
            os.makedirs(conf_dir, exist_ok=True)

            # Write initial default.conf
            default_conf = """server {
    listen 80;
    server_name localhost;

    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
        try_files $uri $uri.html $uri/ /index.html =404;
        error_page 405 =200 $uri;
    }
}
"""
            with open(os.path.join(conf_dir, "default.conf"), "w") as f:
                f.write(default_conf)

            # Determine host paths for Docker mounting (Docker-in-Docker path translation)
            host_runtime_dir = "/home/me/data/AdaptiveShield/runtime"
            try:
                # Find our own container and get host source of /app/runtime
                containers = self._docker.containers.list(filters={"name": "adaptiveshield-core"})
                if containers:
                    for m in containers[0].attrs.get("Mounts", []):
                        if m.get("Destination") == "/app/runtime":
                            host_runtime_dir = m.get("Source")
                            break
            except Exception:
                pass

            host_html_dir = os.path.join(host_runtime_dir, "decoy_http", actual_session_id, "html")
            host_conf_dir = os.path.join(host_runtime_dir, "decoy_http", actual_session_id, "conf")

            container = self._docker.containers.run(
                self.http_image,
                detach=True,
                ports={"80/tcp": None},
                volumes={
                    host_html_dir: {"bind": "/usr/share/nginx/html", "mode": "rw"},
                    host_conf_dir: {"bind": "/etc/nginx/conf.d", "mode": "ro"},
                },
                labels={
                    "adaptiveshield.decoy": "true",
                    "adaptiveshield.decoy_type": "http",
                    "adaptiveshield.session_id": session_id,
                },
            )
            container.reload()

            port_bindings = container.attrs.get("NetworkSettings", {}).get("Ports", {})
            http_binding = port_bindings.get("80/tcp")
            if not http_binding:
                return None

            host_port = http_binding[0].get("HostPort")
            if not host_port:
                return None

            now = time.time()
            instance = DecoyInstance(
                container_id=container.id,
                base_url=f"http://127.0.0.1:{host_port}",
                decoy_type="http",
                last_used_ts=now,
                session_id=session_id,
                html_dir=html_dir,
            )
            self._active_http[container.id] = instance
            return instance
        except Exception:
            return None

    def get_or_spawn_http_decoy(self, session_id: str) -> Optional[DecoyInstance]:
        """Return an HTTP decoy endpoint suitable for redirect/proxy."""
        self.cleanup_idle_decoys()

        # 1. Look for a container already running for this session
        for instance in self._active_http.values():
            if instance.session_id == session_id:
                instance.last_used_ts = time.time()
                return instance

        # 2. Check for a "prewarm" container that has no assigned session
        for instance in self._active_http.values():
            if instance.session_id == "prewarm":
                # Assign it to this session
                instance.session_id = session_id
                instance.last_used_ts = time.time()
                return instance

        # 3. Spawn a new container for this session
        spawned = self._spawn_http_decoy(session_id)
        if spawned:
            return spawned

        if self.fallback_url:
            now = time.time()
            return DecoyInstance(
                container_id="fallback",
                base_url=self.fallback_url,
                decoy_type="http",
                last_used_ts=now,
                session_id=session_id,
            )

        return None

    def _pick_existing_ssh_decoy(self) -> Optional[DecoyInstance]:
        if not self._active_ssh:
            return None
        # Reuse the least recently used decoy.
        return sorted(self._active_ssh.values(), key=lambda d: d.last_used_ts)[0]

    def _spawn_ssh_decoy(self, session_id: str) -> Optional[DecoyInstance]:
        if not self.docker_available:
            return None

        try:
            container = self._docker.containers.run(
                self.ssh_image,
                detach=True,
                ports={"2222/tcp": None},
                labels={
                    "adaptiveshield.decoy": "true",
                    "adaptiveshield.decoy_type": "ssh",
                    "adaptiveshield.session_id": session_id,
                },
            )
            container.reload()

            port_bindings = container.attrs.get("NetworkSettings", {}).get("Ports", {})
            ssh_binding = port_bindings.get("2222/tcp")
            if not ssh_binding:
                return None

            host_port = ssh_binding[0].get("HostPort")
            if not host_port:
                return None

            now = time.time()
            instance = DecoyInstance(
                container_id=container.id,
                base_url=host_port,
                decoy_type="ssh",
                last_used_ts=now,
                session_id=session_id,
            )
            self._active_ssh[container.id] = instance
            return instance
        except Exception:
            return None

    def get_or_spawn_ssh_decoy(self, session_id: str) -> Optional[DecoyInstance]:
        """Return an SSH decoy instance."""
        self.cleanup_idle_decoys()

        existing = self._pick_existing_ssh_decoy()
        if existing:
            existing.last_used_ts = time.time()
            return existing

        spawned = self._spawn_ssh_decoy(session_id)
        if spawned:
            return spawned

        return None

    def cleanup_idle_decoys(self):
        if not self.docker_available:
            return
        now = time.time()
        to_remove = []

        for container_id, instance in list(self._active_http.items()) + list(self._active_ssh.items()):
            if now - instance.last_used_ts > self.idle_timeout_sec:
                to_remove.append((container_id, instance.decoy_type))

        for container_id, decoy_type in to_remove:
            instance = self._active_http.get(container_id) or self._active_ssh.get(container_id)
            try:
                container = self._docker.containers.get(container_id)
                container.remove(force=True)
            except Exception:
                pass
            if decoy_type == "http":
                self._active_http.pop(container_id, None)
            else:
                self._active_ssh.pop(container_id, None)

            # Cleanup directories on host
            if instance and instance.html_dir:
                base_dir = os.path.dirname(instance.html_dir)
                if os.path.exists(base_dir):
                    try:
                        shutil.rmtree(base_dir)
                    except Exception:
                        pass

    def shutdown_all_decoys(self):
        """Stop and remove all active decoy containers."""
        if not self.docker_available:
            return
        for container_id in list(self._active_http.keys()) + list(self._active_ssh.keys()):
            instance = self._active_http.get(container_id) or self._active_ssh.get(container_id)
            try:
                container = self._docker.containers.get(container_id)
                container.remove(force=True)
            except Exception:
                pass
            self._active_http.pop(container_id, None)
            self._active_ssh.pop(container_id, None)

            # Cleanup directories on host
            if instance and instance.html_dir:
                base_dir = os.path.dirname(instance.html_dir)
                if os.path.exists(base_dir):
                    try:
                        shutil.rmtree(base_dir)
                    except Exception:
                        pass


# ---------------------------------------------------------------------------
# Security & Physical Decoy File Generation Engine
# ---------------------------------------------------------------------------

MAX_PATH_LENGTH = 1024
MAX_FILENAME_LENGTH = 255
MAX_SINGLE_FILE_BYTES = 100 * 1024      # 100 KB
MAX_TOTAL_PAYLOAD_BYTES = 500 * 1024    # 500 KB
MAX_FILES_COUNT = 10


def sanitize_and_validate_decoy_path(base_dir: str, rel_path: str) -> str:
    """
    Strictly validates relative file paths against traversal, null bytes,
    absolute paths, dot-prefixes, excessive length, and symlink escapes.
    """
    if not rel_path or not isinstance(rel_path, str):
        raise ValueError("Invalid path: path must be a non-empty string.")

    # 1. Null bytes & length checks
    if "\0" in rel_path or len(rel_path) > MAX_PATH_LENGTH:
        raise ValueError("Invalid path: null bytes detected or path length exceeded.")

    # 2. Reject absolute paths BEFORE any stripping
    if rel_path.startswith("/") or rel_path.startswith("\\"):
        raise ValueError(f"Absolute path rejected: {rel_path}")

    # Reject Windows drive letters or URI schemes (e.g. C:\, file://)
    if ":" in rel_path:
        raise ValueError(f"Drive letter or scheme rejected: {rel_path}")

    # 3. Reject dot-prefix and directory traversal indicators
    normalized_separators = rel_path.replace("\\", "/")
    path_segments = normalized_separators.split("/")

    for seg in path_segments:
        if seg in (".", ".."):
            raise ValueError(f"Directory traversal component '{seg}' rejected: {rel_path}")
        if len(seg) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename exceeds maximum length: {seg}")

    # 4. Resolve canonical real paths
    base_real = os.path.realpath(os.path.abspath(base_dir))
    target_abs = os.path.abspath(os.path.join(base_real, rel_path))

    # Verify target path stays strictly within the canonical base directory
    if not target_abs.startswith(base_real + os.sep) and target_abs != base_real:
        raise ValueError(f"Directory escape detected: {rel_path}")

    # 5. Symlink Escape Verification on parent directories
    parent_dir = os.path.dirname(target_abs)
    if os.path.exists(parent_dir):
        parent_real = os.path.realpath(parent_dir)
        if not parent_real.startswith(base_real + os.sep) and parent_real != base_real:
            raise ValueError(f"Symlink traversal escape detected: {rel_path}")

    return target_abs


def validate_decoy_payload(payload: dict) -> list:
    """
    Validates LLM decoy specification:
    - Verifies generated_files exists and is a list.
    - Enforces file count (<= 10).
    - Enforces single file size (<= 100 KB) and total payload (<= 500 KB).
    - Ignores or removes any security action fields.
    """
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object.")

    # LLM is strictly prohibited from dictating security actions
    if "action" in payload:
        del payload["action"]

    files = payload.get("generated_files")
    if not isinstance(files, list):
        raise ValueError("Payload missing 'generated_files' list.")

    if len(files) > MAX_FILES_COUNT:
        raise ValueError(f"File count ({len(files)}) exceeds maximum limit of {MAX_FILES_COUNT}.")

    total_bytes = 0
    validated_files = []
    for item in files:
        if not isinstance(item, dict):
            continue
        rel_path = item.get("relative_path")
        if not rel_path or not isinstance(rel_path, str):
            raise ValueError(f"Missing or invalid 'relative_path' in file spec: {item}")

        content = item.get("content", "")
        if not isinstance(content, str):
            content = str(content)

        content_bytes = len(content.encode("utf-8"))
        if content_bytes > MAX_SINGLE_FILE_BYTES:
            raise ValueError(f"File '{rel_path}' size ({content_bytes}B) exceeds 100 KB limit.")

        total_bytes += content_bytes
        if total_bytes > MAX_TOTAL_PAYLOAD_BYTES:
            raise ValueError(f"Total payload size ({total_bytes}B) exceeds 500 KB limit.")

        validated_files.append({"relative_path": rel_path, "content": content})

    return validated_files


def generate_fallback_decoy(session_id: str, app_theme: str = "") -> list:
    """
    Deterministic static fallback decoy when LLM is unavailable or invalid.
    """
    return [
        {
            "relative_path": "index.html",
            "content": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Corporate Gateway - Maintenance</title>
  <style>
    body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); max-width: 450px; }
    h2 { margin-top: 0; color: #38bdf8; }
    input { width: 100%; padding: 8px; margin: 8px 0; background: #334155; border: 1px solid #475569; color: #fff; border-radius: 4px; box-sizing: border-box; }
    button { background: #0284c7; color: #fff; border: none; padding: 10px; width: 100%; border-radius: 4px; cursor: pointer; margin-top: 10px; font-weight: bold; }
  </style>
</head>
<body>
  <div class="card">
    <h2>System Maintenance Portal</h2>
    <p>Administrative authentication required to bypass maintenance lock.</p>
    <form method="POST" action="/login">
      <input type="text" name="username" placeholder="Username / Service ID" required>
      <input type="password" name="password" placeholder="Passcode / Token" required>
      <button type="submit">Authorize</button>
    </form>
  </div>
</body>
</html>"""
        }
    ]


def generate_physical_decoy_files(session_id: str, generated_files: list, base_dir: Optional[str] = None) -> str:
    """
    Safely writes validated physical decoy files to the session's host mount path.
    Mount target: ./runtime/decoy_http/{session_id}/html/
    Mounted into container at: /usr/share/nginx/html/
    """
    if base_dir:
        base_html_dir = os.path.abspath(base_dir)
    else:
        base_html_dir = os.path.abspath(f"./runtime/decoy_http/{session_id}/html")
    os.makedirs(base_html_dir, exist_ok=True)

    for file_item in generated_files:
        rel_path = file_item.get("relative_path", "")
        content = file_item.get("content", "")

        try:
            target_path = sanitize_and_validate_decoy_path(base_html_dir, rel_path)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            # Re-raise or log as appropriate
            raise e

    return base_html_dir

