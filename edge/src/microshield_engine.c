/**
 * @file microshield_engine.c
 * @brief Deterministic decision tree traversal engine complying with MISRA C:2012 Rule 17.2.
 */

#include "microshield.h"
#include "transpiled_model.h"
#include <stddef.h>

/**
 * @brief Helper function to extract a feature metric by index using pointer notation.
 * @param features Pointer to feature structure.
 * @param feat_idx Numerical index of the feature (0 to 3).
 * @return float Extracted feature metric value.
 */
static float extract_feature_by_index(const microshield_features_t *features, uint8_t feat_idx) {
    switch (feat_idx) {
        case 0U:
            return features->norm_length;
        case 1U:
            return features->delta_time_us;
        case 2U:
            return features->protocol_flags;
        case 3U:
            return features->byte_variance;
        default:
            return 0.0f;
    }
}

microshield_verdict_t microshield_classify(const microshield_features_t *features, 
                                           uint16_t *out_rule_id, 
                                           uint8_t *out_split_feature) {
    /* Defensive check against null pointer dereference */
    if ((features == NULL) || (out_rule_id == NULL) || (out_split_feature == NULL)) {
        return VERDICT_AMBIGUOUS;
    }

    int16_t current_node = 0;
    uint8_t last_split_feature = 0U;
    uint8_t depth = 0U;

    /* Iterative traversal loop: continue while node is internal (has child != -1) */
    while ((current_node >= 0) && 
           (current_node < (int16_t)MICROSHIELD_TREE_NODE_COUNT) && 
           (TREE_CHILD_LEFT[current_node] != -1)) {

        /* MISRA C bounded depth enforcement: prevent infinite loops */
        if (depth >= MICROSHIELD_TREE_MAX_DEPTH) {
            *out_rule_id = 0U;
            *out_split_feature = last_split_feature;
            return VERDICT_AMBIGUOUS;
        }

        uint8_t feat_idx = TREE_FEATURE[current_node];
        float val = extract_feature_by_index(features, feat_idx);
        float threshold = TREE_THRESHOLD[current_node];

        last_split_feature = feat_idx;

        if (val <= threshold) {
            current_node = TREE_CHILD_LEFT[current_node];
        } else {
            current_node = TREE_CHILD_RIGHT[current_node];
        }

        depth++;
    }

    /* Guard against invalid index out-of-bounds */
    if ((current_node < 0) || (current_node >= (int16_t)MICROSHIELD_TREE_NODE_COUNT)) {
        *out_rule_id = 0U;
        *out_split_feature = last_split_feature;
        return VERDICT_AMBIGUOUS;
    }

    /* Extract decision parameters stored in the terminal leaf */
    *out_rule_id = TREE_LEAF_RULE_ID[current_node];
    *out_split_feature = last_split_feature;
    return (microshield_verdict_t)TREE_LEAF_VERDICT[current_node];
}
