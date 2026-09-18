"""Entry point to launch the supervisory console with active traffic simulation."""

from __future__ import annotations

import sys
from pathlib import Path

# Add supervisor package root to python search path
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "supervisor"))
sys.path.insert(0, str(repo_root))

from dashield.drift.detector import DriftDetector
from dashield.ui.app import create_dashboard_app
from simulation.generator import start_background_simulation


def main() -> None:
    detector = DriftDetector(window_size=100, threshold=0.05, min_samples=20)
    
    print("[*] Starting background traffic simulation...")
    start_background_simulation(detector)
    
    print("[*] Launching DaShield Console on http://127.0.0.1:8051 ...")
    app = create_dashboard_app(detector=detector, node_id=101)
    app.run(host="0.0.0.0", port=8051, debug=False)


if __name__ == "__main__":
    main()
