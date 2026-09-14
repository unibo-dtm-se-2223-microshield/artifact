"""Transport-level serialization and deserialization for MicroShield telemetry.

Implements COBS frame boundary extraction and IEEE 802.3 CRC32 verification
to guarantee transport-agnostic end-to-end integrity.
"""

from __future__ import annotations

import struct
import zlib
from cobs import cobs  # type: ignore[import-untyped]

from dashield.domain.types import FeatureVector, TelemetryRecord, Verdict

# Format: node_id (H), rule_id (H), sequence_id (I), verdict (B),
#         split_feature (B), reserved (H), 4 floats (4f), crc32 (I)
TELEMETRY_STRUCT_FORMAT = "<HHI2BH4fI"
TELEMETRY_PAYLOAD_SIZE = 28  # 32 bytes total - 4 bytes CRC32 field


class FramingError(Exception):
    """Raised when incoming byte stream exhibits invalid framing or corruption."""


def decode_telemetry_frame(cobs_packet: bytes) -> TelemetryRecord:
    """Decode a COBS-delimited packet and construct a validated TelemetryRecord.

    Args:
        cobs_packet: Raw byte sequence stripped of the trailing 0x00 delimiter.

    Returns:
        Validated immutable TelemetryRecord instance.

    Raises:
        FramingError: If COBS decoding fails, size is invalid, or CRC32 mismatches.
    """
    try:
        raw_bytes = bytes(cobs.decode(cobs_packet))
    except cobs.DecodeError as err:
        raise FramingError(f"COBS decoding failure: {err}") from err

    if len(raw_bytes) != struct.calcsize(TELEMETRY_STRUCT_FORMAT):
        raise FramingError(
            f"Unexpected frame length: expected {struct.calcsize(TELEMETRY_STRUCT_FORMAT)} "
            f"bytes, received {len(raw_bytes)} bytes."
        )

    # Compute CRC32 over the first 28 bytes (payload)
    computed_crc = zlib.crc32(raw_bytes[:TELEMETRY_PAYLOAD_SIZE]) & 0xFFFFFFFF

    (
        node_id,
        rule_id,
        sequence_id,
        verdict_raw,
        split_feature,
        _reserved,
        f0,
        f1,
        f2,
        f3,
        received_crc,
    ) = struct.unpack(TELEMETRY_STRUCT_FORMAT, raw_bytes)

    if computed_crc != received_crc:
        raise FramingError(
            f"CRC32 mismatch: payload computed 0x{computed_crc:08X}, "
            f"frame claimed 0x{received_crc:08X}."
        )

    try:
        verdict = Verdict(verdict_raw)
    except ValueError as err:
        raise FramingError(f"Invalid verdict code: {verdict_raw}") from err

    features = FeatureVector(
        norm_length=f0,
        delta_time_us=f1,
        protocol_flags=f2,
        byte_variance=f3,
    )

    return TelemetryRecord(
        node_id=node_id,
        rule_id=rule_id,
        sequence_id=sequence_id,
        verdict=verdict,
        split_feature=split_feature,
        features=features,
        crc32=received_crc,
    )
