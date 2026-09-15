/**
 * @file transpiled_model.h
 * @brief Static decision tree lookup matrices transpiled from scikit-learn.
 *
 * Stored entirely in Flash (.rodata) to achieve zero volatile RAM consumption.
 * Supports O(depth) deterministic tree traversal with depth <= 6.
 */

#ifndef TRANSPILED_MODEL_H
#define TRANSPILED_MODEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MICROSHIELD_TREE_MAX_DEPTH      6U
#define MICROSHIELD_TREE_NODE_COUNT     9U

/**
 * @brief Left child indices (-1 denotes a terminal leaf node).
 */
static const int16_t TREE_CHILD_LEFT[MICROSHIELD_TREE_NODE_COUNT] = {
     1,  /* Row 0: Internal (Root) -> Row 1                          */
     3,  /* Row 1: Internal        -> Row 3                          */
     5,  /* Row 2: Internal        -> Row 5                          */
     7,  /* Row 3: Internal        -> Row 7                          */
    -1,  /* Row 4: Leaf            (Rule 14: Volumetric Buffer Flood)*/
    -1,  /* Row 5: Leaf            (Rule 1:  Nominal Cyclic Flow)    */
    -1,  /* Row 6: Leaf            (Rule 4:  Out-of-Spec Payload)    */
    -1,  /* Row 7: Leaf            (Rule 7:  Borderline Burst Drift) */
    -1   /* Row 8: Leaf            (Rule 22: High-Entropy Fuzzing)   */
};

/**
 * @brief Right child indices (-1 denotes a terminal leaf node).
 */
static const int16_t TREE_CHILD_RIGHT[MICROSHIELD_TREE_NODE_COUNT] = {
     2,  /* Row 0: Internal (Root) -> Row 2                          */
     4,  /* Row 1: Internal        -> Row 4                          */
     6,  /* Row 2: Internal        -> Row 6                          */
     8,  /* Row 3: Internal        -> Row 8                          */
    -1,  /* Row 4: Leaf            (Rule 14: Volumetric Buffer Flood)*/
    -1,  /* Row 5: Leaf            (Rule 1:  Nominal Cyclic Flow)    */
    -1,  /* Row 6: Leaf            (Rule 4:  Out-of-Spec Payload)    */
    -1,  /* Row 7: Leaf            (Rule 7:  Borderline Burst Drift) */
    -1   /* Row 8: Leaf            (Rule 22: High-Entropy Fuzzing)   */
};

/**
 * @brief Feature index evaluated at each row:
 * 0: norm_length
 * 1: delta_time_us
 * 2: protocol_flags
 * 3: byte_variance
 */
static const uint8_t TREE_FEATURE[MICROSHIELD_TREE_NODE_COUNT] = {
    1U,  /* Row 0: delta_time_us */
    0U,  /* Row 1: norm_length   */
    3U,  /* Row 2: byte_variance */
    3U,  /* Row 3: byte_variance */
    0U,  /* Row 4: Terminal leaf */
    0U,  /* Row 5: Terminal leaf */
    0U,  /* Row 6: Terminal leaf */
    0U,  /* Row 7: Terminal leaf */
    0U   /* Row 8: Terminal leaf */
};

/**
 * @brief Split threshold constants evaluated at each row.
 */
static const float TREE_THRESHOLD[MICROSHIELD_TREE_NODE_COUNT] = {
     80.0f,  /* Row 0: delta_time_us <= 80.0 us */
      0.5f,  /* Row 1: norm_length <= 0.50       */
     50.0f,  /* Row 2: byte_variance <= 50.0     */
    150.0f,  /* Row 3: byte_variance <= 150.0    */
      0.0f,  /* Row 4: Terminal leaf             */
      0.0f,  /* Row 5: Terminal leaf             */
      0.0f,  /* Row 6: Terminal leaf             */
      0.0f,  /* Row 7: Terminal leaf             */
      0.0f   /* Row 8: Terminal leaf             */
};

/**
 * @brief Classification verdict emitted at terminal leaves:
 * 0: VERDICT_BENIGN
 * 1: VERDICT_ATTACK
 * 2: VERDICT_AMBIGUOUS
 */
static const uint8_t TREE_LEAF_VERDICT[MICROSHIELD_TREE_NODE_COUNT] = {
    2U,  /* Row 0: Internal node                                     */
    2U,  /* Row 1: Internal node                                     */
    2U,  /* Row 2: Internal node                                     */
    2U,  /* Row 3: Internal node                                     */
    1U,  /* Row 4: VERDICT_ATTACK    (Rule 14: Volumetric Buffer)    */
    0U,  /* Row 5: VERDICT_BENIGN    (Rule 1:  Nominal Process)      */
    2U,  /* Row 6: VERDICT_AMBIGUOUS (Rule 4:  Out-of-Spec Payload)  */
    2U,  /* Row 7: VERDICT_AMBIGUOUS (Rule 7:  Borderline Burst)     */
    1U   /* Row 8: VERDICT_ATTACK    (Rule 22: High-Entropy Fuzzing) */
};

/**
 * @brief Explainable AI (XAI) immutable rule identifier for terminal leaves.
 */
static const uint16_t TREE_LEAF_RULE_ID[MICROSHIELD_TREE_NODE_COUNT] = {
     0U,  /* Row 0: Internal node                                     */
     0U,  /* Row 1: Internal node                                     */
     0U,  /* Row 2: Internal node                                     */
     0U,  /* Row 3: Internal node                                     */
    14U,  /* Row 4: Rule 14 (ATTACK: Volumetric Buffer Flooding)      */
     1U,  /* Row 5: Rule 1  (BENIGN: Nominal Cyclic Process Flow)     */
     4U,  /* Row 6: Rule 4  (AMBIGUOUS: Out-of-Spec Payload / Drift)  */
     7U,  /* Row 7: Rule 7  (AMBIGUOUS: Borderline Burst / Drift)     */
    22U   /* Row 8: Rule 22 (ATTACK: High-Entropy Fuzzing Scan)       */
};

#ifdef __cplusplus
}
#endif

#endif /* TRANSPILED_MODEL_H */
