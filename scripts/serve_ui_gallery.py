"""Serve the app with the component gallery on a port, for review and screenshots (dev tool only).

Usage: uv run python scripts/serve_ui_gallery.py PORT [APP_ENV]
No database is touched: the gallery is static, and the engine is never connected.
"""

from __future__ import annotations

import sys

import uvicorn
from sqlalchemy import create_engine

from countersign.api.app import create_app
from countersign.merchant.keys import generate_jwk, validate_jwk
from countersign.runtime import RuntimeSettings


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    env = sys.argv[2] if len(sys.argv) > 2 else "dev"
    app = create_app(
        key=validate_jwk(generate_jwk()),
        engine=create_engine("sqlite://"),
        runtime=RuntimeSettings(app_env=env),
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
