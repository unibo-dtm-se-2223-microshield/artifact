/**
 * @file microshield_cobs.h
 * @brief Consistent Overhead Byte Stuffing (COBS) and IEEE 802.3 CRC32 framing.
 *
 * Implements deterministic zero-allocation serialization, checksum calculation,
 * and byte stuffing for transport-agnostic telemetry offloading.
 */

#ifndef MICROSHIELD_COBS_H
#define MICROSHIELD_COBS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MICROSHIELD_TELEMETRY_RAW_SIZE  32U
#define MICROSHIELD_COBS_MAX_ENCODED    34U /* Overhead: 1 byte prefix + 1 byte delimiter */

/**
 * @brief Calculate standard IEEE 802.3 CRC32 over a byte buffer.
 * @param data Pointer to input data buffer.
 * @param length Number of bytes to compute checksum over.
 * @return uint32_t Computed 32-bit CRC.
 */
uint32_t microshield_crc32(const uint8_t *data, size_t length);

/**
 * @brief Encode a raw buffer using Consistent Overhead Byte Stuffing (COBS).
 * @param src Pointer to unencoded source buffer.
 * @param length Number of source bytes to encode.
 * @param dst Pointer to destination buffer (must hold at least length + 2 bytes).
 * @return size_t Total encoded bytes including the trailing 0x00 delimiter.
 */
size_t microshield_cobs_encode(const uint8_t *src, size_t length, uint8_t *dst);

/**
 * @brief Decode a COBS-encoded buffer back into raw binary form.
 * @param src Pointer to COBS-encoded input buffer (excluding trailing 0x00).
 * @param length Number of encoded bytes to process.
 * @param dst Pointer to destination buffer.
 * @return size_t Number of decoded raw bytes, or 0 if payload is corrupted.
 */
size_t microshield_cobs_decode(const uint8_t *src, size_t length, uint8_t *dst);

#ifdef __cplusplus
}
#endif

#endif /* MICROSHIELD_COBS_H */
