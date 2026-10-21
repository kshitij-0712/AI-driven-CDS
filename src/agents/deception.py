import time
import os
import json
import logging
import shutil
import threading
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger(__name__)


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

    @property
    def html_dir(self) -> str:
        return self.host_dir


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
        scope: str = "external",
        host_runtime_dir: str = "/home/me/data/AdaptiveShield/runtime",
    ):
        self.scope = scope if scope in ("external", "internal") else "external"
        self.http_subpath = f"decoy_http/{self.scope}"
        self.ssh_subpath = f"decoy_ssh/{self.scope}"
        self.http_image = http_image
        self.ssh_image = ssh_image
        self.max_instances = max_instances
        self.idle_timeout_sec = idle_timeout_sec
        self.fallback_url = fallback_url
        self.host_runtime_dir = host_runtime_dir
        self.prewarm_count = 1
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
                container_scope = container.labels.get("adaptiveshield.scope", "external")
                if container_scope != self.scope:
                    continue
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
                            persisted_session_id = session_id
                            if host_dir:
                                sid_file = os.path.join(os.path.dirname(host_dir), "session_id.txt")
                                if os.path.exists(sid_file):
                                    try:
                                        with open(sid_file, "r") as _f:
                                            persisted_session_id = _f.read().strip() or session_id
                                    except Exception:
                                        pass
                            instance = DecoyInstance(
                                container_id=container.id,
                                base_url=f"http://127.0.0.1:{host_port}",
                                decoy_type="http",
                                last_used_ts=now,
                                session_id=persisted_session_id,
                                host_dir=host_dir,
                            )
                            self._active_http[container.id] = instance
                elif decoy_type == "ssh":
                    binding = port_bindings.get("2222/tcp")
                    if binding:
                        host_port = binding[0].get("HostPort")
                        if host_port:
                            persisted_session_id = session_id
                            if host_dir:
                                sid_file = os.path.join(host_dir, "session_id.txt")
                                if os.path.exists(sid_file):
                                    try:
                                        with open(sid_file, "r") as _f:
                                            persisted_session_id = _f.read().strip() or session_id
                                    except Exception:
                                        pass
                            instance = DecoyInstance(
                                container_id=container.id,
                                base_url=host_port,
                                decoy_type="ssh",
                                last_used_ts=now,
                                session_id=persisted_session_id,
                                host_dir=host_dir,
                            )
                            self._active_ssh[container.id] = instance
        except Exception:
            pass

        # Clean up any leftover directories on host that have no active matching container
        self._cleanup_orphaned_directories()

    def _cleanup_orphaned_directories(self):
        """Clean up directories on host that do not correspond to any active running container."""
        active_dirs = set()
        for inst in list(self._active_http.values()):
            if inst.host_dir:
                active_dirs.add(os.path.abspath(os.path.dirname(inst.host_dir)))
        for inst in list(self._active_ssh.values()):
            if inst.host_dir:
                active_dirs.add(os.path.abspath(inst.host_dir))

        for subpath in (self.http_subpath, self.ssh_subpath):
            scope_dir = os.path.abspath(f"./runtime/{subpath}")
            if not os.path.isdir(scope_dir):
                continue
            try:
                for item in os.listdir(scope_dir):
                    item_path = os.path.abspath(os.path.join(scope_dir, item))
                    if os.path.isdir(item_path) and item_path not in active_dirs:
                        shutil.rmtree(item_path, ignore_errors=True)
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
                # If image is already present in local Docker cache, don't block pulling
                try:
                    self._docker.images.get(image)
                    continue
                except Exception:
                    pass
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
                actual_session_id = f"prewarm_{self.prewarm_count}"
                self.prewarm_count += 1

            # Local paths inside core container for writing files
            local_base_dir = os.path.abspath(f"./runtime/{self.http_subpath}/{actual_session_id}")
            html_dir = os.path.join(local_base_dir, "html")
            conf_dir = os.path.join(local_base_dir, "conf")
            if os.path.exists(local_base_dir):
                try:
                    shutil.rmtree(local_base_dir, ignore_errors=True)
                except Exception:
                    pass
            os.makedirs(html_dir, exist_ok=True)
            os.makedirs(conf_dir, exist_ok=True)

            with open(os.path.join(local_base_dir, "session_id.txt"), "w") as _f:
                _f.write(session_id)

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

            # Pre-populate HTTP baseline files for this scope
            self._populate_http_baseline(html_dir)

            # Determine host paths for Docker mounting (Docker-in-Docker path translation)
            # Use the configured host runtime dir, falling back to our container's mount info
            host_runtime_dir = self.host_runtime_dir
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

            host_html_dir = os.path.join(host_runtime_dir, self.http_subpath, actual_session_id, "html")
            host_conf_dir = os.path.join(host_runtime_dir, self.http_subpath, actual_session_id, "conf")

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
                    "adaptiveshield.scope": self.scope,
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
                
                if instance.host_dir:
                    sid_file = os.path.join(os.path.dirname(instance.host_dir), "session_id.txt")
                    try:
                        with open(sid_file, "w") as _f:
                            _f.write(session_id)
                    except Exception:
                        pass
                
                # Auto-replenish: spawn a replacement prewarm in the background
                # if pool capacity allows.
                if len(self._active_http) < self.max_instances:
                    threading.Thread(
                        target=self._spawn_http_decoy,
                        args=("prewarm",),
                        daemon=True,
                    ).start()
                return instance

        # 3. If capacity reached, recycle least recently used (LRU) decoy
        if len(self._active_http) >= self.max_instances:
            lru = self._pick_existing_http_decoy()
            if lru:
                lru.session_id = session_id
                lru.last_used_ts = time.time()
                return lru

        # 4. Spawn a new container for this session
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

    def _populate_http_baseline(self, html_dir: str):
        """Pre-populates the HTTP decoy with the authentic clone of the service matching scope."""
        try:
            baseline_flag = os.path.join(html_dir, ".baseline_written")
            if os.path.exists(baseline_flag):
                return

            struct_file = (
                "./runtime/app_structure_internal.json"
                if self.scope == "internal"
                else "./runtime/app_structure_external.json"
            )
            target_url = (
                "http://127.0.0.1:8090"
                if self.scope == "internal"
                else "http://127.0.0.1:8080"
            )

            struct_data = None
            if os.path.exists(struct_file):
                with open(struct_file, "r", encoding="utf-8") as f:
                    struct_data = json.load(f)
            elif os.path.exists("./runtime/app_structure.json"):
                with open("./runtime/app_structure.json", "r", encoding="utf-8") as f:
                    struct_data = json.load(f)

            pages = struct_data.get("pages", {}) if struct_data else {}
            paths_to_write = set(pages.keys())
            paths_to_write.add("/")

            import httpx
            for p in paths_to_write:
                rel_path = p.strip("/")
                if not rel_path:
                    rel_path = "index.html"
                elif not rel_path.endswith(".html"):
                    rel_path += ".html"

                out_file = os.path.join(html_dir, rel_path)
                os.makedirs(os.path.dirname(out_file), exist_ok=True)

                content = None
                try:
                    resp = httpx.get(f"{target_url}{p}", timeout=0.8)
                    if resp.status_code == 200:
                        content = resp.text
                except Exception:
                    pass

                if not content:
                    if p in pages and "content_preview" in pages[p]:
                        content = pages[p]["content_preview"]
                    else:
                        title = pages.get(p, {}).get("title", "Nexus Cloud Platform")
                        theme = struct_data.get("theme", "") if struct_data else ""
                        content = f"<!DOCTYPE html><html><head><title>{title}</title><style>{theme}</style></head><body><h1>{title}</h1></body></html>"

                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(content)

            with open(baseline_flag, "w", encoding="utf-8") as f:
                f.write("true")
        except Exception as e:
            logger.warning(f"Failed to pre-populate HTTP baseline: {e}")

    def _populate_ssh_baseline(self, local_base_dir: str):
        """Pre-populates Cowrie decoy with realistic Nexus corporate environment baseline."""
        try:
            baseline_flag = os.path.join(local_base_dir, ".baseline_written")
            if os.path.exists(baseline_flag):
                return

            txtcmds_dir = os.path.join(local_base_dir, "txtcmds")
            honeyfs_etc = os.path.join(local_base_dir, "honeyfs", "etc")
            honeyfs_admin = os.path.join(local_base_dir, "honeyfs", "home", "admin")
            honeyfs_root = os.path.join(local_base_dir, "honeyfs", "root")
            os.makedirs(honeyfs_etc, exist_ok=True)
            os.makedirs(honeyfs_admin, exist_ok=True)
            os.makedirs(honeyfs_root, exist_ok=True)

            txtcmd_map = {
                "whoami": "root\n",
                "id": "uid=0(root) gid=0(root) groups=0(root)\n",
                "hostname": "corp-bastion-01\n",
                "uname": "Linux corp-bastion-01 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux\n",
                "ps": (
                    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                    "root         1  0.0  0.1 168432 11200 ?        Ss   08:00   0:01 /sbin/init\n"
                    "root       320  0.0  0.1  45120  7120 ?        Ss   08:00   0:00 /usr/lib/systemd/systemd-journald\n"
                    "root       412  0.0  0.1  28412  6420 ?        Ss   08:00   0:00 /usr/sbin/sshd -D\n"
                    "marcus.vance 621 0.0 0.5 450100 85200 ?       Sl   08:15   0:05 /opt/nexus/bin/k8s-sync-agent --config=/etc/nexus/cluster.yaml\n"
                    "nexus-admin  890 0.0 0.3 320100 45200 ?       Sl   08:30   0:02 /usr/local/bin/vault-agent -config=/etc/vault/agent.hcl\n"
                    "root      1042  0.0  0.1  38200  8100 ?        Ss   09:12   0:00 sshd: root@pts/0\n"
                    "root      1050  0.0  0.1  22100  5400 pts/0    Ss   09:12   0:00 -bash\n"
                ),
                "df": (
                    "Filesystem      Size  Used Avail Use% Mounted on\n"
                    "udev            7.8G     0  7.8G   0% /dev\n"
                    "tmpfs           1.6G  1.2M  1.6G   1% /run\n"
                    "/dev/sda1        97G   28G   65G  31% /\n"
                    "/dev/sdb1       492G  142G  325G  31% /data/nexus\n"
                ),
                "netstat": (
                    "Active Internet connections (only servers)\n"
                    "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
                    "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
                    "tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN\n"
                    "tcp        0      0 127.0.0.1:8090          0.0.0.0:*               LISTEN\n"
                    "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN\n"
                    "tcp        0      0 10.10.0.1:6443          0.0.0.0:*               LISTEN\n"
                    "tcp        0      0 10.10.0.1:8200          0.0.0.0:*               LISTEN\n"
                ),
            }

            for sub in ["", "bin", "usr/bin", "sbin", "usr/sbin"]:
                sub_dir = os.path.join(txtcmds_dir, sub) if sub else txtcmds_dir
                os.makedirs(sub_dir, exist_ok=True)
                for cmd_name, cmd_content in txtcmd_map.items():
                    with open(os.path.join(sub_dir, cmd_name), "w", encoding="utf-8") as f:
                        f.write(cmd_content.strip() + "\n")

            with open(os.path.join(honeyfs_etc, "hostname"), "w", encoding="utf-8") as f:
                f.write("corp-bastion-01\n")

            with open(os.path.join(honeyfs_etc, "hosts"), "w", encoding="utf-8") as f:
                f.write(
                    "127.0.0.1 localhost corp-bastion-01\n"
                    "10.10.0.1 corp-bastion-01.corp.nexuscloud.internal\n"
                    "10.10.1.10 auth-kdc.corp.nexuscloud.internal\n"
                    "10.10.2.15 lnx-sre-1004.corp.nexuscloud.internal\n"
                    "10.10.2.50 k8s-master.corp.nexuscloud.internal\n"
                    "10.10.3.100 vault-prod-01.corp.nexuscloud.internal\n"
                )

            with open(os.path.join(honeyfs_etc, "passwd"), "w", encoding="utf-8") as f:
                f.write(
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "nexus-admin:x:1000:1000:Nexus Infra Admin,,,:/home/admin:/bin/bash\n"
                    "marcus.vance:x:1001:1001:Marcus Vance (Principal SRE),,,:/home/marcus.vance:/bin/bash\n"
                    "sarah.chen:x:1002:1002:Dr. Sarah Chen (Lead ML),,,:/home/sarah.chen:/bin/bash\n"
                )

            with open(os.path.join(honeyfs_etc, "shadow"), "w", encoding="utf-8") as f:
                f.write(
                    "root:$6$nexus_salt$p9X1Zl2.871k182...:19800:0:99999:7:::\n"
                    "nexus-admin:$6$nexus_salt$xK71.02kd81...:19800:0:99999:7:::\n"
                    "marcus.vance:$6$nexus_salt$w01kd92.z1...:19800:0:99999:7:::\n"
                )

            with open(os.path.join(honeyfs_admin, ".bash_history"), "w", encoding="utf-8") as f:
                f.write(
                    "sudo systemctl status k8s-sync-agent\n"
                    "kubectl get pods -n production\n"
                    "vault login -method=ldap\n"
                )

            with open(os.path.join(honeyfs_root, ".bash_history"), "w", encoding="utf-8") as f:
                f.write(
                    "systemctl restart sshd\n"
                    "tail -n 50 /var/log/auth.log\n"
                )

            with open(baseline_flag, "w", encoding="utf-8") as f:
                f.write("true")
        except Exception as e:
            logger.warning(f"Failed to pre-populate SSH baseline: {e}")

    def _spawn_ssh_decoy(self, session_id: str) -> Optional[DecoyInstance]:
        if not self.docker_available:
            return None

        try:
            actual_session_id = session_id
            if session_id == "prewarm":
                actual_session_id = f"prewarm_{self.prewarm_count}"
                self.prewarm_count += 1
            # Local paths inside core container for writing files
            local_base_dir = os.path.abspath(f"./runtime/{self.ssh_subpath}/{actual_session_id}")
            txtcmds_dir = os.path.join(local_base_dir, "txtcmds")
            honeyfs_dir = os.path.join(local_base_dir, "honeyfs")
            downloads_dir = os.path.join(local_base_dir, "downloads")
            if os.path.exists(local_base_dir):
                try:
                    shutil.rmtree(local_base_dir, ignore_errors=True)
                except Exception:
                    pass
            os.makedirs(txtcmds_dir, exist_ok=True)
            os.makedirs(honeyfs_dir, exist_ok=True)
            os.makedirs(downloads_dir, exist_ok=True)

            # Fix permissions so Cowrie (uid 1000) can write to downloads
            os.chmod(downloads_dir, 0o777)

            with open(os.path.join(local_base_dir, "session_id.txt"), "w") as _f:
                _f.write(session_id)

            # Ensure cowrie patches exist in runtime/cowrie_patches
            patch_dir = os.path.abspath("./runtime/cowrie_patches")
            os.makedirs(patch_dir, exist_ok=True)
            local_proto_patch = os.path.join(patch_dir, "protocol.py")
            local_fs_patch = os.path.join(patch_dir, "fs.py")
            src_proto = os.path.abspath("./src/honeypot/cowrie_patches/protocol.py")
            src_fs = os.path.abspath("./src/honeypot/cowrie_patches/fs.py")
            repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            if not os.path.exists(src_proto):
                src_proto = os.path.join(repo_root, "src", "honeypot", "cowrie_patches", "protocol.py")
            if not os.path.exists(src_fs):
                src_fs = os.path.join(repo_root, "src", "honeypot", "cowrie_patches", "fs.py")
            import shutil
            if not os.path.exists(local_proto_patch) and os.path.exists(src_proto):
                try:
                    shutil.copy(src_proto, local_proto_patch)
                except Exception:
                    pass
            if not os.path.exists(local_fs_patch) and os.path.exists(src_fs):
                try:
                    shutil.copy(src_fs, local_fs_patch)
                except Exception:
                    pass

            # Pre-populate SSH realistic corporate baseline
            self._populate_ssh_baseline(local_base_dir)

            # Determine host paths for Docker mounting (Docker-in-Docker path translation)
            # Use the configured host runtime dir, falling back to our container's mount info
            host_runtime_dir = self.host_runtime_dir
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

            host_txtcmds_dir = os.path.join(host_runtime_dir, self.ssh_subpath, actual_session_id, "txtcmds")
            host_honeyfs_dir = os.path.join(host_runtime_dir, self.ssh_subpath, actual_session_id, "honeyfs")
            host_cowrie_cfg = os.path.join(host_runtime_dir, self.ssh_subpath, actual_session_id, "cowrie.cfg")
            host_downloads_dir = os.path.join(host_runtime_dir, self.ssh_subpath, actual_session_id, "downloads")
            host_proto_patch = os.path.join(host_runtime_dir, "cowrie_patches", "protocol.py")
            host_fs_patch = os.path.join(host_runtime_dir, "cowrie_patches", "fs.py")

            # Write realistic cowrie.cfg
            cowrie_cfg_content = """[honeypot]
hostname = corp-bastion-01
contents_path = /cowrie/cowrie-git/honeyfs
txtcmds_path = /cowrie/cowrie-git/txtcmds

[shell]
filesystem = /cowrie/cowrie-git/src/cowrie/data/fs.pickle
"""
            with open(os.path.join(local_base_dir, "cowrie.cfg"), "w", encoding="utf-8") as f:
                f.write(cowrie_cfg_content)

            cowrie_volumes = {
                host_txtcmds_dir: {"bind": "/cowrie/cowrie-git/txtcmds", "mode": "rw"},
                host_honeyfs_dir: {"bind": "/cowrie/cowrie-git/honeyfs", "mode": "rw"},
                host_cowrie_cfg: {"bind": "/cowrie/cowrie-git/etc/cowrie.cfg", "mode": "ro"},
                host_downloads_dir: {"bind": "/cowrie/cowrie-git/var/lib/cowrie/downloads", "mode": "rw"},
            }
            if os.path.exists(local_proto_patch):
                cowrie_volumes[host_proto_patch] = {"bind": "/cowrie/cowrie-git/src/cowrie/shell/protocol.py", "mode": "ro"}
            if os.path.exists(local_fs_patch):
                cowrie_volumes[host_fs_patch] = {"bind": "/cowrie/cowrie-git/src/cowrie/shell/fs.py", "mode": "ro"}

            container = self._docker.containers.run(
                self.ssh_image,
                detach=True,
                ports={"2222/tcp": None},
                volumes=cowrie_volumes,
                environment={
                    "COWRIE_HONEYPOT_HOSTNAME": "corp-bastion-01",
                    "COWRIE_HONEYPOT_CONTENTS_PATH": "/cowrie/cowrie-git/honeyfs",
                    "COWRIE_HONEYPOT_TXTCMDS_PATH": "/cowrie/cowrie-git/txtcmds",
                },
                labels={
                    "adaptiveshield.decoy": "true",
                    "adaptiveshield.decoy_type": "ssh",
                    "adaptiveshield.scope": self.scope,
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
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Failed to spawn SSH decoy: {e}")
            return None

    def get_or_spawn_ssh_decoy(self, session_id: str) -> Optional[DecoyInstance]:
        """Return an SSH decoy instance."""
        self.cleanup_idle_decoys()
        
        # 1. Look for a container already running for this session
        for instance in self._active_ssh.values():
            if instance.session_id == session_id:
                instance.last_used_ts = time.time()
                return instance

        # 2. Check for a prewarm container and claim it, then replenish
        for instance in self._active_ssh.values():
            if instance.session_id == "prewarm":
                instance.session_id = session_id
                instance.last_used_ts = time.time()

                if instance.host_dir:
                    sid_file = os.path.join(instance.host_dir, "session_id.txt")
                    try:
                        with open(sid_file, "w") as _f:
                            _f.write(session_id)
                    except Exception:
                        pass

                # Auto-replenish: spawn a replacement prewarm in the background
                # if pool capacity allows.
                if len(self._active_ssh) < self.max_instances:
                    threading.Thread(
                        target=self._spawn_ssh_decoy,
                        args=("prewarm",),
                        daemon=True,
                    ).start()
                return instance

        # 3. If capacity reached, recycle least recently used (LRU) decoy
        if len(self._active_ssh) >= self.max_instances:
            existing = self._pick_existing_ssh_decoy()
            if existing:
                existing.session_id = session_id
                existing.last_used_ts = time.time()
                return existing

        spawned = self._spawn_ssh_decoy(session_id)
        if spawned:
            return spawned

        existing = self._pick_existing_ssh_decoy()
        if existing:
            existing.session_id = session_id
            existing.last_used_ts = time.time()
            return existing

        return None

    def cleanup_idle_decoys(self):
        if not self.docker_available:
            return
        now = time.time()
        to_remove = []

        for container_id, instance in list(self._active_http.items()) + list(self._active_ssh.items()):
            # Never clean up prewarm containers — they are intentionally kept
            # warm and idle, waiting for the next attacker to claim them.
            if instance.session_id == "prewarm":
                continue
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
                        shutil.rmtree(base_dir, ignore_errors=True)
                    except Exception:
                        pass

        # Cleanup any remaining orphaned directories on host
        self._cleanup_orphaned_directories()

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
                        shutil.rmtree(base_dir, ignore_errors=True)
                    except Exception:
                        pass

        # Also purge any leftover Docker containers matching this decoy scope
        try:
            containers = self._docker.containers.list(all=True, filters={"label": "adaptiveshield.decoy=true"})
            for c in containers:
                c_scope = c.labels.get("adaptiveshield.scope")
                if not c_scope or c_scope == self.scope:
                    try:
                        c.remove(force=True)
                    except Exception:
                        pass
        except Exception:
            pass

        # Clean up any leftover host directories for this scope
        self._cleanup_orphaned_directories()


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
