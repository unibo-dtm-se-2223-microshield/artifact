"""Automated SIL Fleet Scalability & Channel Stress Benchmark.

Simulates heterogeneous edge fleets (100, 500, 1000 nodes) transmitting packed
C99 telemetry frames over simulated noisy channels. Quantifies supervisory
ingestion throughput, CRC32 error rejection, and concept drift convergence latency.
"""

from __future__ import annotations

import random
import struct
import time
import zlib
from typing import Dict, List
from cobs import cobs  # type: ignore[import-untyped]
from dashield.domain.types import Verdict
from dashield.drift.detector import DriftDetector

# Geometry: 28 bytes payload (Timestamp, Seq, Node, Verdict, Rule, f0, f1, f2, f3) + 4 bytes CRC32 = 32 bytes
PAYLOAD_FORMAT = "<IIBBHffff"


def build_c99_frame(node_id: int, seq: int, verdict: Verdict, rule_id: int, dt: float, var: float) -> bytes:
    """Pack an authentic 32-byte C99 telemetry frame with IEEE 802.3 CRC32."""
    timestamp = int(time.time() * 1000) & 0xFFFFFFFF
    length_bytes = 64
    f0_norm = float(length_bytes) / 1500.0
    f1_dt = float(dt)
    f2_flags = 0.04
    f3_var = float(var)

    # Pack 28-byte payload
    payload = struct.pack(
        PAYLOAD_FORMAT,
        timestamp,
        seq,
        node_id & 0xFF,
        verdict.value,
        rule_id,
        f0_norm,
        f1_dt,
        f2_flags,
        f3_var,
    )

    # Compute IEEE 802.3 CRC32 over payload
    crc = zlib.crc32(payload) & 0xFFFFFFFF

    # Append CRC32 (total 32 bytes packed)
    packed_frame = payload + struct.pack("<I", crc)

    # Encode with COBS and append null delimiter
    return cobs.encode(packed_frame) + b"\x00"


def run_fleet_benchmark(fleet_size: int, packets_per_node: int = 6, noise_ratio: float = 0.03) -> Dict[str, float]:
    """Execute a deterministic SIL benchmark for a given fleet size."""
    detector = DriftDetector(window_size=100, threshold=0.05, min_samples=20)
    total_frames = fleet_size * packets_per_node

    # Generate synthetic edge telemetry stream
    frames: List[bytes] = []
    seq_counter = 0
    for node in range(1, fleet_size + 1):
        for _ in range(packets_per_node):
            roll = random.random()
            if roll < 0.80:
                v, r, dt, var = Verdict.BENIGN, 1, 120.0, 25.0
            elif roll < 0.95:
                v, r, dt, var = Verdict.AMBIGUOUS, 4, 80.0, 85.0
            else:
                v, r, dt, var = Verdict.ATTACK, 14, 20.0, 30.0

            frame = build_c99_frame(node, seq_counter, v, r, dt, var)
            seq_counter += 1

            # Inject simulated transmission channel noise
            if random.random() < noise_ratio:
                raw_list = bytearray(frame)
                mutate_idx = random.randint(0, len(raw_list) - 2)
                raw_list[mutate_idx] ^= 0xFF
                frame = bytes(raw_list)

            frames.append(frame)

    # Execute supervisory ingestion pipeline under measurement
    t_start = time.perf_counter()
    processed_ok = 0
    rejected_crc = 0
    drift_trigger_time: float = 0.0
    drift_detected = False

    for wire_frame in frames:
        # 1. COBS delimiter and framing check
        if not wire_frame.endswith(b"\x00"):
            rejected_crc += 1
            continue

        try:
            decoded = cobs.decode(wire_frame[:-1])
        except Exception:
            rejected_crc += 1
            continue

        if len(decoded) != 32:
            rejected_crc += 1
            continue

        # 2. Checksum validation (IEEE 802.3 CRC32)
        payload, rx_crc = decoded[:28], struct.unpack("<I", decoded[28:])[0]
        if (zlib.crc32(payload) & 0xFFFFFFFF) != rx_crc:
            rejected_crc += 1
            continue

        # 3. Domain ingestion & Drift monitoring
        unpacked = struct.unpack(PAYLOAD_FORMAT, payload)
        verdict = Verdict(unpacked[3])
        detector.record_verdict(verdict)
        processed_ok += 1

        if not drift_detected and detector.is_drift_detected():
            drift_detected = True
            drift_trigger_time = time.perf_counter() - t_start

    t_total = time.perf_counter() - t_start
    throughput = processed_ok / t_total if t_total > 0 else 0.0

    return {
        "fleet_size": float(fleet_size),
        "total_injected": float(total_frames),
        "processed_valid": float(processed_ok),
        "rejected_corrupted": float(rejected_crc),
        "rejection_rate_pct": (rejected_crc / total_frames) * 100.0,
        "elapsed_sec": t_total,
        "throughput_fps": throughput,
        "drift_latency_ms": (drift_trigger_time * 1000.0) if drift_detected else 0.0,
    }


def main() -> None:
    print("=======================================================================")
    print("  MICROSHIELD SIL BENCHMARK: FLEET SCALABILITY & CHANNEL METROLOGY")
    print("=======================================================================")
    print("Evaluating supervisory tier over simulated heterogeneous fleet links...\n")

    scales = [100, 500, 1000]
    results = []

    for size in scales:
        print(f"[*] Running SIL Benchmark for Fleet Size = {size} Edge Nodes...")
        res = run_fleet_benchmark(fleet_size=size, packets_per_node=6, noise_ratio=0.03)
        results.append(res)
        print(f"    -> Injected: {int(res['total_injected'])} frames | Valid: {int(res['processed_valid'])} | Corrupted Dropped: {int(res['rejected_corrupted'])}")
        print(f"    -> Throughput: {res['throughput_fps']:.1f} frames/sec | Drift Latency: {res['drift_latency_ms']:.2f} ms\n")

    print("=======================================================================================")
    print("  EMPIRICAL SIL FLEET BENCHMARK RESULTS (FOR REPORT CHAPTER 5)")
    print("=======================================================================================")
    print(f"{'Fleet Size':<12} | {'Frames':<8} | {'Valid Rx':<10} | {'CRC Drops':<10} | {'Throughput (fps)':<18} | {'Drift Lat. (ms)':<15}")
    print("-" * 87)
    for r in results:
        print(f"{int(r['fleet_size']):<12} | {int(r['total_injected']):<8} | {int(r['processed_valid']):<10} | {int(r['rejected_corrupted']):<10} | {r['throughput_fps']:<18.1f} | {r['drift_latency_ms']:<15.2f}")
    print("=======================================================================================\n")


if __name__ == "__main__":
    main()
