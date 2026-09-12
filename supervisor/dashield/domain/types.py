"""Domain data types and value objects for the MicroShield supervisory tier.

Provides strictly typed, immutable representations of edge telemetry,
feature vectors, and classification verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Verdict(IntEnum):
    """Ternary classification verdicts emitted by the edge detection engine."""

    BENIGN = 0
    ATTACK = 1
    AMBIGUOUS = 2


@dataclass(frozen=True)
class FeatureVector:
    """Normalized statistical feature vector extracted from an intercepted frame."""

    norm_length: float
    delta_time_us: float
    protocol_flags: float
    byte_variance: float

    def to_tuple(self) -> tuple[float, float, float, float]:
        """Convert the feature vector into a 4-element floating point tuple."""
        return (
            self.norm_length,
            self.delta_time_us,
            self.protocol_flags,
            self.byte_variance,
        )


@dataclass(frozen=True)
class TelemetryRecord:
    """Immutable supervisory representation of a diagnostic telemetry event."""

    node_id: int
    rule_id: int
    sequence_id: int
    verdict: Verdict
    split_feature: int
    features: FeatureVector
    crc32: int
