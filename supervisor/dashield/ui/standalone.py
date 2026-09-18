"""Standalone application entry point for Dockerized DaShield supervisory console."""

from __future__ import annotations

import os
from dashield.drift.detector import DriftDetector
from dashield.ui.app import create_dashboard_app


def main() -> None:
    """Launch the Dash server bound to container network interfaces."""
    port = int(os.environ.get("PORT", 8050))
    detector = DriftDetector()
    app = create_dashboard_app(detector=detector, node_id=101)

    print(f"[*] Starting DaShield Console on http://0.0.0.0:{port}")
    # In production/container context debug is disabled, host set to 0.0.0.0
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
