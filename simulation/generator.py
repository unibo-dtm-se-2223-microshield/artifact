"""Adversary playback harness for live dashboard simulation.

Generates continuous synthetic network telemetry mimicking edge hardware.
Adapts dynamically: injects drift until the operator triggers retraining.
"""

from __future__ import annotations

import random
import time
from threading import Thread
from typing import Any, Dict
from dashield.domain.types import Verdict
from dashield.drift.detector import DriftDetector


def _generate_telemetry_payload(verdict: Verdict) -> Dict[str, Any]:
    now_str = time.strftime("%H:%M:%S")
    if verdict == Verdict.BENIGN:
        delta_t = round(random.uniform(95.0, 165.0), 1)
        variance = round(random.uniform(12.0, 42.0), 1)
        rule_id = 1
        reason = "Nominal Modbus cyclic telemetry"
        length = random.choice([60, 64, 128, 256])
    elif verdict == Verdict.ATTACK:
        if random.random() < 0.6:
            delta_t = round(random.uniform(8.0, 32.0), 1)
            variance = round(random.uniform(15.0, 48.0), 1)
            rule_id = 14
            reason = "Volumetric line rate flood (inter-arrival violation)"
            length = random.choice([64, 128, 1500])
        else:
            delta_t = round(random.uniform(35.0, 85.0), 1)
            variance = round(random.uniform(145.0, 235.0), 1)
            rule_id = 22
            reason = "High-entropy payload fuzzing (variance anomaly)"
            length = random.choice([256, 512, 1024])
    else:  # AMBIGUOUS
        delta_t = round(random.uniform(65.0, 95.0), 1)
        variance = round(random.uniform(62.0, 108.0), 1)
        rule_id = 4
        reason = "Boundary erosion candidate (concept drift sample)"
        length = random.choice([80, 160, 320])

    return {
        "timestamp": now_str,
        "verdict": verdict.name,
        "delta_time_us": delta_t,
        "byte_variance": variance,
        "rule_id": rule_id,
        "reason": reason,
        "length": length,
    }


def simulate_network_traffic(detector: DriftDetector) -> None:
    """Inject continuous traffic adapting to operator retraining actions."""
    print("[*] Continuous traffic simulation active.")

    while True:
        # Phase A: Nominal baseline (traffic is healthy, green state)
        print("[*] Phase: NOMINAL traffic injection...")
        for _ in range(60):
            v = Verdict.BENIGN if random.random() < 0.95 else Verdict.ATTACK
            detector.record_verdict(v, record=_generate_telemetry_payload(v))
            time.sleep(0.3)

        # Phase B: Introduce Concept Drift (ambiguity climbs past 5%)
        print("[*] Phase: CONCEPT DRIFT injection (evasion attack)...")
        while not detector.is_drift_detected():
            roll = random.random()
            if roll < 0.70:
                v = Verdict.BENIGN
            elif roll < 0.85:
                v = Verdict.ATTACK
            else:
                v = Verdict.AMBIGUOUS
            detector.record_verdict(v, record=_generate_telemetry_payload(v))
            time.sleep(0.3)

        # Phase C: Active Alarm (wait for human to press the retrain button)
        print("[!] Phase: ALARM ACTIVE - waiting for operator AST Retrain trigger...")
        while detector.is_drift_detected():
            v = Verdict.AMBIGUOUS if random.random() < 0.60 else Verdict.ATTACK
            detector.record_verdict(v, record=_generate_telemetry_payload(v))
            time.sleep(0.4)

        print("[+] Retrain detected! Detector reset by operator. Returning to nominal...")
        time.sleep(1.0)


def start_background_simulation(detector: DriftDetector) -> None:
    """Launch the traffic generator in a background daemon thread."""
    thread = Thread(target=simulate_network_traffic, args=(detector,), daemon=True)
    thread.start()
