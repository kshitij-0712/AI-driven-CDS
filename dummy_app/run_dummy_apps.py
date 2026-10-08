import sys
import os
import asyncio
import uvicorn

# Add repo root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dummy_app.public_server import app as public_app
from dummy_app.internal_server import app as internal_app

async def main():
    print("=" * 70)
    print("  NEXUS CLOUD ENTERPRISE SIMULATION PLATFORM")
    print("  1. Public Customer Facing Website: http://127.0.0.1:8080")
    print("  2. Corporate Internal Intranet:    http://127.0.0.1:8090")
    print("=" * 70)

    pub_config = uvicorn.Config(public_app, host="127.0.0.1", port=8080, log_level="warning")
    int_config = uvicorn.Config(internal_app, host="127.0.0.1", port=8090, log_level="warning")

    pub_server = uvicorn.Server(pub_config)
    int_server = uvicorn.Server(int_config)

    await asyncio.gather(
        pub_server.serve(),
        int_server.serve()
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nDummy servers stopped.")
