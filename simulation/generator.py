"""Adversary playback harness for live dashboard simulation.

Generates continuous synthetic network telemetry mimicking edge hardware.
Adapts dynamically: injects drift until the operator triggers retraining.
"""

from __future__ import annotations

import random
import time
from threading import Thread
from dashield.domain.types import Verdict
from dashield.drift.detector import DriftDetector


def simulate_network_traffic(detector: DriftDetector) -> None:
    """Inject continuous traffic adapting to operator retraining actions."""
    print("[*] Continuous traffic simulation active.")
    
    while True:
        # Phase A: Nominal baseline (traffic is healthy, green state)
        print("[*] Phase: NOMINAL traffic injection...")
        for _ in range(60):
            if random.random() < 0.95:
                detector.record_verdict(Verdict.BENIGN)
            else:
                detector.record_verdict(Verdict.ATTACK)
            time.sleep(0.3)

        # Phase B: Introduce Concept Drift (ambiguity climbs past 5%)
        print("[*] Phase: CONCEPT DRIFT injection (evasion attack)...")
        while not detector.is_drift_detected():
            roll = random.random()
            if roll < 0.70:
                detector.record_verdict(Verdict.BENIGN)
            elif roll < 0.85:
                detector.record_verdict(Verdict.ATTACK)
            else:
                detector.record_verdict(Verdict.AMBIGUOUS)
            time.sleep(0.3)

        # Phase C: Active Alarm (wait for human to press the retrain button)
        print("[!] Phase: ALARM ACTIVE - waiting for operator AST Retrain trigger...")
        while detector.is_drift_detected():
            # Keep pumping ambiguous packets to sustain alarm until reset() is called
            roll = random.random()
            if roll < 0.60:
                detector.record_verdict(Verdict.AMBIGUOUS)
            else:
                detector.record_verdict(Verdict.ATTACK)
            time.sleep(0.4)

        print("[+] Retrain detected! Detector reset by operator. Returning to nominal...")
        time.sleep(1.0)


def start_background_simulation(detector: DriftDetector) -> None:
    """Launch the traffic generator in a background daemon thread."""
    thread = Thread(target=simulate_network_traffic, args=(detector,), daemon=True)
    thread.start()
