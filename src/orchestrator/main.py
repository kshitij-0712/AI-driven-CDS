import argparse
from pathlib import Path

import uvicorn
import yaml

from interceptor.http_proxy import create_http_guard_app


def load_config(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run(config_path: str):
    config = load_config(config_path)
    app = create_http_guard_app(config)

    deployment = config.get("deployment", {})
    host = deployment.get("host", "0.0.0.0")
    port = int(deployment.get("port", 80))

    uvicorn.run(app, host=host, port=port, proxy_headers=True)


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
