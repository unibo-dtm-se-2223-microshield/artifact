#ifndef MICROSHIELD_H
#define MICROSHIELD_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Ternary classification verdict codes.
 */
typedef enum {
    VERDICT_BENIGN    = 0,
    VERDICT_ATTACK    = 1,
    VERDICT_AMBIGUOUS = 2
} microshield_verdict_t;

/**
 * @brief Extracted statistical feature vector (16 bytes, natural 32-bit alignment).
 */
typedef struct {
    float norm_length;     /* Normalized frame length [0.0, 1.0] */
    float delta_time_us;   /* Inter-arrival interval in microseconds */
    float protocol_flags;  /* Normalized protocol control flags */
    float byte_variance;   /* Two-pass payload byte variance */
} microshield_features_t;

/**
 * @brief Out-of-band serial diagnostic telemetry frame (32 bytes exact, packed).
 */
typedef struct __attribute__((packed)) {
    uint16_t node_id;         /* Physical edge node identifier (2 bytes) */
    uint16_t rule_id;         /* Active decision tree leaf ID for XAI (2 bytes) */
    uint32_t sequence_id;     /* Monotonic transmission sequence counter (4 bytes) */
    uint8_t  verdict;         /* microshield_verdict_t numeric code (1 byte) */
    uint8_t  split_feature;   /* Index of dominant feature causing the split (1 byte) */
    uint16_t reserved;        /* Explicit alignment padding (2 bytes) */
    float    features[4];     /* Snapshot of the extracted feature vector (16 bytes) */
    uint32_t crc32;           /* IEEE 802.3 CRC32 integrity checksum (4 bytes) */
} microshield_telemetry_t;

/**
 * @brief Initialize the MicroShield detection engine.
 * @param node_id Unique identifier for this edge device.
 */
void microshield_init(uint16_t node_id);

/**
 * @brief Extract normalized statistical features from a raw frame (Zero-Copy).
 * @param frame Pointer to contiguous raw data-link packet bytes.
 * @param len Total length of the frame in bytes.
 * @param timestamp_us Hardware microsecond capture timestamp.
 * @param out_features Pointer to pre-allocated destination struct.
 */
void microshield_extract_features(const uint8_t *frame, 
                                  uint16_t len, 
                                  uint32_t timestamp_us, 
                                  microshield_features_t *out_features);

/**
 * @brief Classify a feature vector in deterministic bounded time (<= 50 us).
 * @param features Pointer to populated feature vector.
 * @param out_rule_id Pointer to store the matched leaf Rule ID (XAI).
 * @param out_split_feature Pointer to store the dominant feature index.
 * @return microshield_verdict_t Classification result.
 */
microshield_verdict_t microshield_classify(const microshield_features_t *features, 
                                           uint16_t *out_rule_id, 
                                           uint8_t *out_split_feature);

/**
 * @brief Construct a diagnostic telemetry frame with CRC32 integrity.
 * @param verdict Classification verdict.
 * @param rule_id Matched rule ID.
 * @param split_feature Index of dominant split feature.
 * @param features Feature snapshot.
 * @param out_frame Pointer to destination telemetry struct.
 * @return Total serialized byte count (always sizeof(microshield_telemetry_t)).
 */
uint16_t microshield_build_telemetry(microshield_verdict_t verdict, 
                                     uint16_t rule_id, 
                                     uint8_t split_feature, 
                                     const microshield_features_t *features, 
                                     microshield_telemetry_t *out_frame);

#ifdef __cplusplus
}
#endif

#endif /* MICROSHIELD_H */
