/**
 * @file test_features.c
 * @brief Unit tests for zero-copy feature extractor and numerical stability.
 */

#include "microshield.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>

/* Declaration of internal test helper */
extern void microshield_features_reset(void);

static void test_length_normalization(void) {
    microshield_features_reset();
    uint8_t buffer[2000];
    memset(buffer, 0xAA, sizeof(buffer));

    microshield_features_t feat;

    /* 1. Standard small packet (60 bytes) */
    microshield_extract_features(buffer, 60, 1000, &feat);
    assert(fabsf(feat.norm_length - (60.0f / 1500.0f)) < 0.0001f);

    /* 2. Full MTU packet (1500 bytes) */
    microshield_extract_features(buffer, 1500, 2000, &feat);
    assert(fabsf(feat.norm_length - 1.0f) < 0.0001f);

    /* 3. Jumbo frame exceeding MTU (capped to 1.0) */
    microshield_extract_features(buffer, 2000, 3000, &feat);
    assert(fabsf(feat.norm_length - 1.0f) < 0.0001f);

    printf("[TEST] Length Normalization: PASSED (60B, 1500B, 2000B)\n");
}

static void test_inter_arrival_delta_and_rollover(void) {
    microshield_features_reset();
    uint8_t buffer[64] = {0};
    microshield_features_t feat;

    /* 1. First packet after boot -> default nominal delta */
    microshield_extract_features(buffer, 64, 50000U, &feat);
    assert(feat.delta_time_us == 1000.0f);

    /* 2. Nominal subsequent arrival (50 µs later) */
    microshield_extract_features(buffer, 64, 50050U, &feat);
    assert(feat.delta_time_us == 50.0f);

    /* 3. Hardware Timer Rollover Test:
     * Previous: 0xFFFFFFF0 (4,294,967,280)
     * Current:  0x00000010 (16)
     * Expected difference in modular arithmetic: 16 + 16 = 32 µs */
    microshield_extract_features(buffer, 64, 0xFFFFFFF0U, &feat);
    microshield_extract_features(buffer, 64, 0x00000010U, &feat);
    assert(feat.delta_time_us == 32.0f);

    printf("[TEST] Timing Delta & Rollover Protection: PASSED (Boot default, nominal, wrap-around)\n");
}

static void test_protocol_flag_bounds(void) {
    microshield_features_reset();
    uint8_t buffer[64] = {0};
    microshield_features_t feat;

    /* Inject TCP SYN flag (0x02) at byte offset 47 */
    buffer[47] = 0x02U;
    microshield_extract_features(buffer, 64, 1000, &feat);
    assert(fabsf(feat.protocol_flags - (2.0f / 255.0f)) < 0.0001f);

    /* Runt frame smaller than TCP header (10 bytes) -> fallback to 0.0 without out-of-bounds */
    microshield_extract_features(buffer, 10, 2000, &feat);
    assert(feat.protocol_flags == 0.0f);

    printf("[TEST] Protocol Flags Extraction: PASSED (TCP SYN detected, runt frame guarded)\n");
}

static void test_two_pass_variance_accuracy(void) {
    microshield_features_reset();
    microshield_features_t feat;

    /* 1. Constant payload: variance must be exactly 0.0 */
    uint8_t const_buffer[100];
    memset(const_buffer, 0x7A, sizeof(const_buffer));
    microshield_extract_features(const_buffer, sizeof(const_buffer), 1000, &feat);
    assert(feat.byte_variance == 0.0f);

    /* 2. Known distribution: [0, 100, 0, 100]
     * Mean = (0 + 100 + 0 + 100) / 4 = 50.0
     * Variance = ((0-50)^2 + (100-50)^2 + (0-50)^2 + (100-50)^2) / 4
     *          = (2500 + 2500 + 2500 + 2500) / 4 = 2500.0 */
    uint8_t known_buffer[4] = { 0, 100, 0, 100 };
    microshield_extract_features(known_buffer, 4, 2000, &feat);
    assert(fabsf(feat.byte_variance - 2500.0f) < 0.001f);

    printf("[TEST] Two-Pass Variance Accuracy: PASSED (Constant=0.0, Known-dist=2500.0)\n");
}

int main(void) {
    printf("--- Running MicroShield Edge C99 Feature Extractor Tests ---\n");
    test_length_normalization();
    test_inter_arrival_delta_and_rollover();
    test_protocol_flag_bounds();
    test_two_pass_variance_accuracy();
    printf("--- ALL C99 FEATURE EXTRACTOR TESTS PASSED SUCCESSFULLY ---\n");
    return 0;
}
