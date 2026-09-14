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
 * @brief Index of left child node (-1 indicates a terminal leaf node).
 */
static const int16_t TREE_CHILD_LEFT[MICROSHIELD_TREE_NODE_COUNT] = {
     1,  /* Node 0: left child -> Node 1 */
     3,  /* Node 1: left child -> Node 3 */
    -1,  /* Node 2: Leaf (Rule ID 1)    */
    -1,  /* Node 3: Leaf (Rule ID 7)    */
    -1,  /* Node 4: Leaf (Rule ID 14)   */
    -1,  /* Node 5: Leaf (Rule ID 22)   */
    -1,  /* Node 6: Leaf (Rule ID 4)    */
    -1,  /* Reserved / unused slot      */
    -1   /* Reserved / unused slot      */
};

/**
 * @brief Index of right child node (-1 indicates a terminal leaf node).
 */
static const int16_t TREE_CHILD_RIGHT[MICROSHIELD_TREE_NODE_COUNT] = {
     2,  /* Node 0: right child -> Node 2 */
     4,  /* Node 1: right child -> Node 4 */
    -1,  /* Node 2: Leaf (Rule ID 1)     */
    -1,  /* Node 3: Leaf (Rule ID 7)     */
    -1,  /* Node 4: Leaf (Rule ID 14)    */
    -1,  /* Node 5: Leaf (Rule ID 22)    */
    -1,  /* Node 6: Leaf (Rule ID 4)     */
    -1,  /* Reserved / unused slot       */
    -1   /* Reserved / unused slot       */
};

/**
 * @brief Feature index evaluated at each node:
 * 0: norm_length
 * 1: delta_time_us
 * 2: protocol_flags
 * 3: byte_variance
 */
static const uint8_t TREE_FEATURE[MICROSHIELD_TREE_NODE_COUNT] = {
    1U,  /* Node 0: delta_time_us */
    0U,  /* Node 1: norm_length   */
    3U,  /* Node 2: byte_variance */
    3U,  /* Node 3: byte_variance */
    0U,  /* Node 4: terminal leaf */
    0U,  /* Node 5: terminal leaf */
    0U,  /* Node 6: terminal leaf */
    0U,  /* Unused                */
    0U   /* Unused                */
};

/**
 * @brief Split threshold constants evaluated at each node.
 */
static const float TREE_THRESHOLD[MICROSHIELD_TREE_NODE_COUNT] = {
     80.0f,  /* Node 0: delta_time_us <= 80.0 us */
      0.5f,  /* Node 1: norm_length <= 0.50       */
     50.0f,  /* Node 2: byte_variance <= 50.0     */
    150.0f,  /* Node 3: byte_variance <= 150.0    */
      0.0f,  /* Node 4: terminal leaf             */
      0.0f,  /* Node 5: terminal leaf             */
      0.0f,  /* Node 6: terminal leaf             */
      0.0f,  /* Unused                            */
      0.0f   /* Unused                            */
};

/**
 * @brief Verdict classification emitted at terminal leaf nodes:
 * 0: VERDICT_BENIGN
 * 1: VERDICT_ATTACK
 * 2: VERDICT_AMBIGUOUS
 */
static const uint8_t TREE_LEAF_VERDICT[MICROSHIELD_TREE_NODE_COUNT] = {
    2U,  /* Node 0: internal node               */
    2U,  /* Node 1: internal node               */
    0U,  /* Node 2: BENIGN (Rule ID 1)          */
    2U,  /* Node 3: AMBIGUOUS (Rule ID 7)       */
    1U,  /* Node 4: ATTACK (Rule ID 14)         */
    1U,  /* Node 5: ATTACK (Rule ID 22)         */
    2U,  /* Node 6: AMBIGUOUS (Rule ID 4)       */
    0U,  /* Unused                              */
    0U   /* Unused                              */
};

/**
 * @brief Explainable AI (XAI) immutable rule identifier for terminal leaves.
 */
static const uint16_t TREE_LEAF_RULE_ID[MICROSHIELD_TREE_NODE_COUNT] = {
     0U,  /* Node 0: internal node */
     0U,  /* Node 1: internal node */
     1U,  /* Node 2: Rule 1  (BENIGN: Nominal Cyclic Flow)       */
     7U,  /* Node 3: Rule 7  (AMBIGUOUS: Borderline Burst Flow)  */
    14U,  /* Node 4: Rule 14 (ATTACK: Volumetric Buffer Flood)   */
    22U,  /* Node 5: Rule 22 (ATTACK: High-Entropy Fuzzing Scan) */
     4U,  /* Node 6: Rule 4  (AMBIGUOUS: Out-of-Spec Payload)    */
     0U,  /* Unused                                              */
     0U   /* Unused                                              */
};

#ifdef __cplusplus
}
#endif

#endif /* TRANSPILED_MODEL_H */
