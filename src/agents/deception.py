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
    host_dir: str = ""


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
                host_dir = ""
                for m in mounts:
                    if m.get("Destination") == "/usr/share/nginx/html":
                        host_source = m.get("Source")
                        # Translate host source path back to local path inside core container
                        if "runtime/" in host_source:
                            rel_part = host_source.split("runtime/", 1)[1]
                            host_dir = os.path.abspath(os.path.join("./runtime", rel_part))
                        else:
                            host_dir = host_source
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
                                host_dir=host_dir,
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
                                host_dir=host_dir,
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
                host_dir=html_dir,
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
            actual_session_id = session_id

            # Local paths inside core container for writing files
            local_base_dir = os.path.abspath(f"./runtime/decoy_ssh/{actual_session_id}")
            txtcmds_dir = os.path.join(local_base_dir, "txtcmds")
            honeyfs_dir = os.path.join(local_base_dir, "honeyfs")
            os.makedirs(txtcmds_dir, exist_ok=True)
            os.makedirs(honeyfs_dir, exist_ok=True)

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

            host_txtcmds_dir = os.path.join(host_runtime_dir, "decoy_ssh", actual_session_id, "txtcmds")
            host_honeyfs_dir = os.path.join(host_runtime_dir, "decoy_ssh", actual_session_id, "honeyfs")
            host_cowrie_cfg = os.path.join(host_runtime_dir, "decoy_ssh", actual_session_id, "cowrie.cfg")

            # Create empty cowrie.cfg so it can be mounted
            with open(os.path.join(local_base_dir, "cowrie.cfg"), "w") as f:
                f.write("")

            container = self._docker.containers.run(
                self.ssh_image,
                detach=True,
                ports={"2222/tcp": None},
                volumes={
                    host_txtcmds_dir: {"bind": "/cowrie/cowrie-git/share/cowrie/txtcmds", "mode": "ro"},
                    host_honeyfs_dir: {"bind": "/cowrie/cowrie-git/honeyfs", "mode": "ro"},
                    host_cowrie_cfg: {"bind": "/cowrie/cowrie-git/etc/cowrie.cfg", "mode": "ro"},
                },
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
                host_dir=local_base_dir,
            )
            self._active_ssh[container.id] = instance
            return instance
        except Exception:
            return None

    def get_or_spawn_ssh_decoy(self, session_id: str) -> Optional[DecoyInstance]:
        """Return an SSH decoy instance."""
        self.cleanup_idle_decoys()
        
        # 1. Look for a container already running for this session
        for instance in self._active_ssh.values():
            if instance.session_id == session_id:
                instance.last_used_ts = time.time()
                return instance

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
            if instance and instance.host_dir:
                base_dir = os.path.dirname(instance.host_dir) if decoy_type == "http" else instance.host_dir
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
            if instance and instance.host_dir:
                base_dir = os.path.dirname(instance.host_dir) if instance.decoy_type == "http" else instance.host_dir
                if os.path.exists(base_dir):
                    try:
                        shutil.rmtree(base_dir)
                    except Exception:
                        pass
