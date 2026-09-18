"""Adversary playback generator feeding telemetry directly into DaShield."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

API_URL = "http://localhost:8050/api/verdict"


def send_verdict(verdict: int) -> dict[str, object]:
    """Send a single verdict via HTTP POST to the running supervisor."""
    req = urllib.request.Request(
        API_URL,
        data=json.dumps({"verdict": verdict}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]


def run_simulation(delay_sec: float = 0.15) -> None:
    """Execute nominal, attack, and drift phases against the supervisor."""
    print("================================================================")
    print("  MICROSHIELD LIVE TELEMETRY SIMULATION PLAYBACK")
    print("================================================================")

    # 1. Phase: Nominal industrial traffic (40 packets -> 0% drift)
    print("\n[PHASE 1] Streaming nominal Modbus/TCP traffic (BENIGN = 0)...")
    for i in range(40):
        status = send_verdict(0)
        if (i + 1) % 10 == 0:
            ratio = float(status.get("ambiguity_ratio", 0.0)) * 100
            print(f"  Frame {i+1:02d}/40 | Ambiguity: {ratio:.1f}% | State: NOMINAL")
        time.sleep(delay_sec)

    # 2. Phase: Volumetric DoS flood (20 attack packets -> 0% drift)
    print("\n[PHASE 2] Injecting volumetric SYN flood attack (ATTACK = 1)...")
    for i in range(20):
        status = send_verdict(1)
        if (i + 1) % 5 == 0:
            ratio = float(status.get("ambiguity_ratio", 0.0)) * 100
            print(f"  Attack {i+1:02d}/20 | Ambiguity: {ratio:.1f}% | Quarantined on Edge")
        time.sleep(delay_sec)

    # 3. Phase: Statistical boundary drift (12 ambiguous packets -> ratio > 5%)
    print("\n[PHASE 3] Inducing Concept Drift via borderline deltas (AMBIGUOUS = 2)...")
    for i in range(12):
        status = send_verdict(2)
        ratio = float(status.get("ambiguity_ratio", 0.0)) * 100
        drift = bool(status.get("is_drift_detected", False))
        alert = ">>> DRIFT DETECTED <<<" if drift else "Watching window"
        print(f"  Drift Frame {i+1:02d}/12 | Ambiguity: {ratio:.1f}% | {alert}")
        time.sleep(delay_sec)

    print("\n================================================================")
    print("  SIMULATION COMPLETE")
    print("  Check http://localhost:8050 on your browser to see the alarm.")
    print("================================================================")


if __name__ == "__main__":
    try:
        run_simulation()
    except urllib.error.URLError as err:
        print(f"\n[ERROR] Could not connect to {API_URL}: {err.reason}")
        print("Ensure the Docker container is running via 'docker compose up -d'.")
