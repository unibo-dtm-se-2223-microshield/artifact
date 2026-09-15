/**
 * @file test_engine.c
 * @brief Unit verification suite for microshield_engine deterministic classification.
 */

#include "microshield.h"
#include <stdio.h>
#include <assert.h>

static void test_nominal_benign_classification(void) {
    microshield_features_t feat = {
        .norm_length = 0.08f,
        .delta_time_us = 120.0f, /* > 80.0 -> branches to Node 2 */
        .protocol_flags = 0.0f,
        .byte_variance = 30.0f   /* <= 50.0 -> branches to Leaf 5 (Rule 1) */
    };

    uint16_t rule_id = 0U;
    uint8_t split_feat = 0U;
    microshield_verdict_t verdict = microshield_classify(&feat, &rule_id, &split_feat);

    printf("[TEST] Nominal: verdict=%d, rule_id=%u, split_feat=%u\n", verdict, rule_id, split_feat);
    assert(verdict == VERDICT_BENIGN);
    assert(rule_id == 1U);
    assert(split_feat == 3U); /* Split by byte_variance */
}

static void test_volumetric_flood_attack(void) {
    microshield_features_t feat = {
        .norm_length = 0.85f,    /* > 0.50 -> branches to Leaf 4 (Rule 14) */
        .delta_time_us = 20.0f,  /* <= 80.0 -> branches to Node 1 */
        .protocol_flags = 1.0f,
        .byte_variance = 100.0f
    };

    uint16_t rule_id = 0U;
    uint8_t split_feat = 0U;
    microshield_verdict_t verdict = microshield_classify(&feat, &rule_id, &split_feat);

    printf("[TEST] Volumetric Flood: verdict=%d, rule_id=%u, split_feat=%u\n", verdict, rule_id, split_feat);
    assert(verdict == VERDICT_ATTACK);
    assert(rule_id == 14U);
    assert(split_feat == 0U); /* Split by norm_length */
}

static void test_fuzzing_attack_high_entropy(void) {
    microshield_features_t feat = {
        .norm_length = 0.10f,    /* <= 0.50 -> branches to Node 3 */
        .delta_time_us = 20.0f,  /* <= 80.0 -> branches to Node 1 */
        .protocol_flags = 0.0f,
        .byte_variance = 180.0f  /* > 150.0 -> branches to Leaf 8 (Rule 22) */
    };

    uint16_t rule_id = 0U;
    uint8_t split_feat = 0U;
    microshield_verdict_t verdict = microshield_classify(&feat, &rule_id, &split_feat);

    printf("[TEST] Fuzzing Attack: verdict=%d, rule_id=%u, split_feat=%u\n", verdict, rule_id, split_feat);
    assert(verdict == VERDICT_ATTACK);
    assert(rule_id == 22U);
    assert(split_feat == 3U); /* Split by byte_variance */
}

static void test_ambiguous_drift_candidate(void) {
    microshield_features_t feat = {
        .norm_length = 0.08f,
        .delta_time_us = 120.0f, /* > 80.0 -> branches to Node 2 */
        .protocol_flags = 0.0f,
        .byte_variance = 75.0f   /* > 50.0 -> branches to Leaf 6 (Rule 4) */
    };

    uint16_t rule_id = 0U;
    uint8_t split_feat = 0U;
    microshield_verdict_t verdict = microshield_classify(&feat, &rule_id, &split_feat);

    printf("[TEST] Ambiguous Drift: verdict=%d, rule_id=%u, split_feat=%u\n", verdict, rule_id, split_feat);
    assert(verdict == VERDICT_AMBIGUOUS);
    assert(rule_id == 4U);
    assert(split_feat == 3U);
}

static void test_null_pointer_safety(void) {
    uint16_t rule_id = 99U;
    uint8_t split_feat = 99U;
    microshield_verdict_t verdict = microshield_classify(NULL, &rule_id, &split_feat);

    printf("[TEST] Null Pointer Safety: verdict=%d\n", verdict);
    assert(verdict == VERDICT_AMBIGUOUS);
}

int main(void) {
    printf("--- Running MicroShield Edge C99 Inference Engine Tests ---\n");
    test_nominal_benign_classification();
    test_volumetric_flood_attack();
    test_fuzzing_attack_high_entropy();
    test_ambiguous_drift_candidate();
    test_null_pointer_safety();
    printf("--- ALL C99 INFERENCE ENGINE TESTS PASSED SUCCESSFULLY ---\n");
    return 0;
}
