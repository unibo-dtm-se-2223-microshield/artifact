/**
 * @file microshield_features.c
 * @brief Zero-copy statistical feature extraction for inline network frames.
 */

#include "microshield.h"
#include <stddef.h>
#include <stdbool.h>

#define ETHERNET_STANDARD_MTU   1500.0f
#define TCP_FLAGS_OFFSET        47U
#define ETHERTYPE_OFFSET        12U
#define DEFAULT_BOOT_DELTA_US   1000.0f

/* Internal state tracking inter-packet arrival timing */
static uint32_t g_last_timestamp_us = 0U;
static bool g_has_prior_timestamp = false;

/**
 * @brief Reset internal timing state (primarily used during test suites).
 */
void microshield_features_reset(void) {
    g_last_timestamp_us = 0U;
    g_has_prior_timestamp = false;
}

void microshield_extract_features(const uint8_t *frame_buffer, 
                                 uint16_t length, 
                                 uint32_t current_time_us, 
                                 microshield_features_t *out_features) {
    /* Defensive check against null pointers or invalid zero length */
    if ((frame_buffer == NULL) || (out_features == NULL) || (length == 0U)) {
        if (out_features != NULL) {
            out_features->norm_length = 0.0f;
            out_features->delta_time_us = DEFAULT_BOOT_DELTA_US;
            out_features->protocol_flags = 0.0f;
            out_features->byte_variance = 0.0f;
        }
        return;
    }

    /* f0: Normalized Frame Length clamped to standard Ethernet MTU */
    float capped_length = (length > (uint16_t)ETHERNET_STANDARD_MTU) ? ETHERNET_STANDARD_MTU : (float)length;
    out_features->norm_length = capped_length / ETHERNET_STANDARD_MTU;

    /* f1: Inter-Arrival Time Delta with hardware timer rollover protection */
    if (!g_has_prior_timestamp) {
        out_features->delta_time_us = DEFAULT_BOOT_DELTA_US;
        g_has_prior_timestamp = true;
    } else {
        /* Unsigned subtraction guarantees correct modular arithmetic on 32-bit overflow */
        uint32_t diff_us = current_time_us - g_last_timestamp_us;
        out_features->delta_time_us = (float)diff_us;
    }
    g_last_timestamp_us = current_time_us;

    /* f2: Protocol & Control Flags with defensive boundary checks */
    if (length > TCP_FLAGS_OFFSET) {
        out_features->protocol_flags = (float)frame_buffer[TCP_FLAGS_OFFSET] / 255.0f;
    } else if (length > ETHERTYPE_OFFSET) {
        out_features->protocol_flags = (float)frame_buffer[ETHERTYPE_OFFSET] / 255.0f;
    } else {
        out_features->protocol_flags = 0.0f;
    }

    /* f3: Two-Pass Numerically Stable Byte Variance */
    /* Pass 1: Unsigned 32-bit integer summation to prevent catastrophic cancellation */
    uint32_t byte_sum = 0U;
    for (uint16_t i = 0U; i < length; i++) {
        byte_sum += (uint32_t)frame_buffer[i];
    }
    float mean = (float)byte_sum / (float)length;

    /* Pass 2: Summation of squared deviations from mean */
    float sum_squared_diff = 0.0f;
    for (uint16_t i = 0U; i < length; i++) {
        float diff = (float)frame_buffer[i] - mean;
        sum_squared_diff += diff * diff;
    }
    out_features->byte_variance = sum_squared_diff / (float)length;
}
