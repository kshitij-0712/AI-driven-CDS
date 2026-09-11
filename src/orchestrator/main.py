import argparse
import os
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
    app = create_http_guard_app(config)

    deployment = config.get("deployment", {})
    host = deployment.get("host", "0.0.0.0")
    port = int(deployment.get("port", 80))

    uvicorn_config = uvicorn.Config(app, host=host, port=port, proxy_headers=True)
    server = uvicorn.Server(uvicorn_config)

    async def main_loop():
        # Pre-warm decoys to eliminate startup latency for the first attack
        logging.info("Pre-warming HTTP and SSH decoys...")
        app.state.decoys.get_or_spawn_http_decoy("prewarm")
        app.state.decoys.get_or_spawn_ssh_decoy("prewarm")
        logging.info("Decoys ready.")

        # Start SSH proxy
        ssh_task = asyncio.create_task(
            start_ssh_proxy(config, app.state.store, app.state.nft, app.state.classifier, app.state.decoys)
        )
        # Start HTTP server
        await server.serve()

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
