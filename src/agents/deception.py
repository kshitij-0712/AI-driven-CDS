import time
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
        max_instances: int = 5,
        idle_timeout_sec: int = 300,
        fallback_url: Optional[str] = None,
    ):
        self.http_image = http_image
        self.max_instances = max_instances
        self.idle_timeout_sec = idle_timeout_sec
        self.fallback_url = fallback_url

        self._active_http: Dict[str, DecoyInstance] = {}
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
                http_binding = port_bindings.get("80/tcp")
                if http_binding:
                    host_port = http_binding[0].get("HostPort")
                    if host_port:
                        instance = DecoyInstance(
                            container_id=container.id,
                            base_url=f"http://127.0.0.1:{host_port}",
                            decoy_type=container.labels.get("adaptiveshield.decoy_type", "http"),
                            last_used_ts=now,
                        )
                        self._active_http[container.id] = instance
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
            container = self._docker.containers.run(
                self.http_image,
                detach=True,
                ports={"80/tcp": None},
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
            )
            self._active_http[container.id] = instance
            return instance
        except Exception:
            return None

    def get_or_spawn_http_decoy(self, session_id: str) -> Optional[DecoyInstance]:
        """Return an HTTP decoy endpoint suitable for redirect/proxy."""
        self.cleanup_idle_decoys()

        existing = self._pick_existing_http_decoy()
        if existing:
            existing.last_used_ts = time.time()
            return existing

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
            )

        return None

    def cleanup_idle_decoys(self):
        if not self.docker_available:
            return

        now = time.time()
        to_remove = []

        for container_id, instance in self._active_http.items():
            if now - instance.last_used_ts > self.idle_timeout_sec:
                to_remove.append(container_id)

        for container_id in to_remove:
            try:
                container = self._docker.containers.get(container_id)
                container.stop(timeout=2)
            except Exception:
                pass
            self._active_http.pop(container_id, None)

    def shutdown_all_decoys(self):
        """Stop all active decoy containers without removing them."""
        if not self.docker_available:
            return
        for container_id in list(self._active_http.keys()):
            try:
                container = self._docker.containers.get(container_id)
                container.stop(timeout=2)
            except Exception:
                pass
            self._active_http.pop(container_id, None)
