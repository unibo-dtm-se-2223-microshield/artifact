/**
 * @file test_cobs.c
 * @brief Unit tests for IEEE 802.3 CRC32 checksum and COBS encoding/decoding.
 */

#include "microshield.h"
#include "microshield_cobs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void test_crc32_standard_vector(void) {
    /* Standard IEEE 802.3 test vector: "123456789" -> 0xCBF43926 */
    const uint8_t test_data[] = "123456789";
    const uint32_t expected_crc = 0xCBF43926UL;
    
    uint32_t computed_crc = microshield_crc32(test_data, 9);
    printf("[TEST] CRC32('123456789'): 0x%08X (Expected: 0x%08X)\n", computed_crc, expected_crc);
    assert(computed_crc == expected_crc);
}

static void test_cobs_roundtrip_with_null_bytes(void) {
    /* Payload with embedded null bytes that would break standard framing */
    const uint8_t raw_payload[8] = { 0x01, 0x00, 0x02, 0x00, 0x00, 0x03, 0x04, 0x05 };
    uint8_t encoded[MICROSHIELD_COBS_MAX_ENCODED];
    uint8_t decoded[sizeof(raw_payload)];

    size_t enc_len = microshield_cobs_encode(raw_payload, sizeof(raw_payload), encoded);
    
    /* Ensure the only null byte in the encoded stream is the final delimiter */
    for (size_t i = 0; i < enc_len - 1U; i++) {
        assert(encoded[i] != 0x00U);
    }
    assert(encoded[enc_len - 1U] == 0x00U);

    /* Decode (excluding trailing delimiter) and verify bit-for-bit equality */
    size_t dec_len = microshield_cobs_decode(encoded, enc_len - 1U, decoded);
    assert(dec_len == sizeof(raw_payload));
    assert(memcmp(raw_payload, decoded, sizeof(raw_payload)) == 0);
    printf("[TEST] COBS Roundtrip: %zu raw bytes -> %zu encoded bytes -> matched\n", sizeof(raw_payload), enc_len);
}

static void test_telemetry_structure_crc32(void) {
    microshield_init(101);

    microshield_features_t feat = {
        .norm_length = 0.5f,
        .delta_time_us = 45.0f,
        .protocol_flags = 1.0f,
        .byte_variance = 180.25f
    };

    microshield_telemetry_t frame;
    uint16_t size = microshield_build_telemetry(VERDICT_ATTACK, 14, 3, &feat, &frame);

    assert(size == 32U);
    assert(frame.node_id == 101);
    assert(frame.rule_id == 14);
    assert(frame.verdict == (uint8_t)VERDICT_ATTACK);

    /* Verify CRC32 calculated on first 28 bytes matches the stored checksum */
    uint32_t verify_crc = microshield_crc32((const uint8_t *)&frame, 28);
    assert(frame.crc32 == verify_crc);
    printf("[TEST] TelemetryFrame CRC32 Verified: 0x%08X (Sequence: %u)\n", frame.crc32, frame.sequence_id);
}

int main(void) {
    printf("--- Running MicroShield Edge C99 Framing & Integrity Tests ---\n");
    test_crc32_standard_vector();
    test_cobs_roundtrip_with_null_bytes();
    test_telemetry_structure_crc32();
    printf("--- ALL C99 FRAMING & INTEGRITY TESTS PASSED SUCCESSFULLY ---\n");
    return 0;
}
