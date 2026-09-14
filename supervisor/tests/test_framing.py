"""Unit tests verifying transport framing, COBS decoding, and CRC32 integrity."""

from __future__ import annotations

import struct
import zlib
from typing import cast
import pytest
from cobs import cobs  # type: ignore[import-untyped]

from dashield.domain.types import Verdict
from dashield.transport.framing import (
    FramingError,
    decode_telemetry_frame,
)


def build_synthetic_cobs_frame(
    node_id: int = 101,
    rule_id: int = 14,
    seq: int = 0,
    verdict: int = 1,
    split_feat: int = 3,
    f0: float = 0.5,
    f1: float = 45.0,
    f2: float = 1.0,
    f3: float = 180.25,
    corrupt_crc: bool = False,
) -> bytes:
    """Helper function generating raw binary telemetry matching C struct layout."""
    payload = struct.pack(
        "<HHI2BH4f",
        node_id,
        rule_id,
        seq,
        verdict,
        split_feat,
        0,  # reserved
        f0,
        f1,
        f2,
        f3,
    )
    crc = (zlib.crc32(payload) & 0xFFFFFFFF) if not corrupt_crc else 0xDEADBEEF
    raw_frame = payload + struct.pack("<I", crc)
    return cast(bytes, cobs.encode(raw_frame))


def test_decode_valid_frame_matching_c_test() -> None:
    """Verify that a binary payload matching the C unit test is parsed accurately."""
    encoded_packet = build_synthetic_cobs_frame()
    record = decode_telemetry_frame(encoded_packet)

    assert record.node_id == 101
    assert record.rule_id == 14
    assert record.sequence_id == 0
    assert record.verdict == Verdict.ATTACK
    assert record.split_feature == 3
    assert pytest.approx(record.features.norm_length) == 0.5
    assert pytest.approx(record.features.delta_time_us) == 45.0
    assert pytest.approx(record.features.protocol_flags) == 1.0
    assert pytest.approx(record.features.byte_variance) == 180.25


def test_corrupted_crc_rejection() -> None:
    """Verify that any single-bit or deliberate CRC corruption raises FramingError."""
    corrupted_packet = build_synthetic_cobs_frame(corrupt_crc=True)

    with pytest.raises(FramingError, match="CRC32 mismatch"):
        decode_telemetry_frame(corrupted_packet)


def test_truncated_frame_rejection() -> None:
    """Verify that undersized or truncated frames are rejected immediately."""
    truncated_raw = b"\x01\x02\x03\x04"
    truncated_packet = cast(bytes, cobs.encode(truncated_raw))

    with pytest.raises(FramingError, match="Unexpected frame length"):
        decode_telemetry_frame(truncated_packet)
