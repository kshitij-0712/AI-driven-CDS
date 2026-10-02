import sys
import os
# Add 'src' directory to Python path automatically to prevent import failures
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if src_path not in sys.path:
    sys.path.insert(0, src_path)

import argparse
from pathlib import Path
import logging
logging.basicConfig(level=logging.INFO)
# Load .env manually if it exists
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            if line.strip() and not line.startswith("#") and "=" in line:
                key, val = line.strip().split("=", 1)
                os.environ[key] = val

import uvicorn
import yaml

from interceptor.http_proxy import create_http_guard_app


def load_config(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


import asyncio
from interceptor.ssh_proxy import start_ssh_proxy

def run(config_path: str):
    config = load_config(config_path)
    
    # 1. External HTTP Guard (Port 8000)
    ext_app = create_http_guard_app(config, is_internal=False)
    ext_host = config.get("http_guard", {}).get("listen_host", "0.0.0.0")
    ext_port = int(config.get("http_guard", {}).get("listen_port", 8000))
    ext_config = uvicorn.Config(ext_app, host=ext_host, port=ext_port, proxy_headers=True)
    ext_server = uvicorn.Server(ext_config)

    # 2. Internal HTTP Guard (Port 8001)
    int_app = create_http_guard_app(config, is_internal=True)
    int_host = config.get("internal_http_guard", {}).get("listen_host", "0.0.0.0")
    int_port = int(config.get("internal_http_guard", {}).get("listen_port", 8001))
    int_config = uvicorn.Config(int_app, host=int_host, port=int_port, proxy_headers=True)
    int_server = uvicorn.Server(int_config)

    async def main_loop():
        # Pre-warm decoys using external app's decoy manager
        logging.info("Pre-warming HTTP and SSH decoys...")
        ext_app.state.decoys.get_or_spawn_http_decoy("prewarm")
        ext_app.state.decoys.get_or_spawn_ssh_decoy("prewarm")
        logging.info("Decoys ready.")

        from honeypot.ssh_decoy_builder import SSHDecoyBuilder
        from core.triage.watcher import TriageWatcher
        builder = SSHDecoyBuilder(config, ext_app.state.store)
        
        watcher = TriageWatcher(
            watch_dir="./runtime/decoy_ssh",
            store=ext_app.state.store,
            classifier=ext_app.state.classifier,
            builder=builder,
            decoy_mgr=ext_app.state.decoys
        )
        watcher.start()

        # Start SSH proxy
        ssh_task = asyncio.create_task(
            start_ssh_proxy(
                config, ext_app.state.store, ext_app.state.nft, ext_app.state.classifier, ext_app.state.decoys, builder
            )
        )
        
        # Start both HTTP servers
        logging.info(f"Starting External Guard on {ext_host}:{ext_port}")
        logging.info(f"Starting Internal Guard on {int_host}:{int_port}")
        
        try:
            await asyncio.gather(
                ext_server.serve(),
                int_server.serve()
            )
        finally:
            logging.info("Shutting down... cleaning up all decoy containers.")
            watcher.stop()
            try:
                ext_app.state.decoys.shutdown_all_decoys()
                int_app.state.decoys.shutdown_all_decoys()
            except Exception as e:
                logging.error(f"Error during decoy cleanup: {e}")

    asyncio.run(main_loop())

def main():
    parser = argparse.ArgumentParser(description="AdaptiveShield Orchestrator")
    parser.add_argument(
        "--config",
        default=str(Path(__file__).resolve().parents[2] / "config" / "settings.yaml"),
        help="Path to YAML config file",
    )
    args = parser.parse_args()
    run(args.config)


if __name__ == "__main__":
    main()
