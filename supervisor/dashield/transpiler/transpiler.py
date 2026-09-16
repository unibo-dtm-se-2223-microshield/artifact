"""AST Transpiler compiling scikit-learn decision trees into C99 lookup matrices.

Emits static Flash-resident (.rodata) C lookup arrays complying with MISRA C:2012
Rule 17.2 and exports Explainable AI (XAI) semantic rule descriptors to JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
import numpy as np
from sklearn.tree import DecisionTreeClassifier  # type: ignore[import-untyped]

MAX_ALLOWED_DEPTH = 6

FEATURE_NAMES = [
    "norm_length",
    "delta_time_us",
    "protocol_flags",
    "byte_variance",
]

VERDICT_NAMES = {
    0: "VERDICT_BENIGN",
    1: "VERDICT_ATTACK",
    2: "VERDICT_AMBIGUOUS",
}


class DecisionTreeTranspiler:
    """Translates trained scikit-learn estimators to deterministic C99 source artifacts."""

    def __init__(self, classifier: DecisionTreeClassifier) -> None:
        """Initialize and validate model geometry against edge hardware ceilings.

        Args:
            classifier: Fitted DecisionTreeClassifier instance.

        Raises:
            ValueError: If the estimator depth violates the max allowed depth.
        """
        self.classifier = classifier
        tree_depth = int(classifier.get_depth())
        if tree_depth > MAX_ALLOWED_DEPTH:
            raise ValueError(
                f"Trained tree depth {tree_depth} exceeds edge WCET ceiling ({MAX_ALLOWED_DEPTH})."
            )

        self.tree = classifier.tree_
        self.n_nodes: int = int(self.tree.node_count)
        self.children_left: np.ndarray[Any, Any] = self.tree.children_left
        self.children_right: np.ndarray[Any, Any] = self.tree.children_right
        self.feature: np.ndarray[Any, Any] = self.tree.feature
        self.threshold: np.ndarray[Any, Any] = self.tree.threshold
        self.values: np.ndarray[Any, Any] = self.tree.value

    def is_leaf(self, node_id: int) -> bool:
        """Check whether a given node index is a terminal leaf."""
        return bool(self.children_left[node_id] == -1)

    def get_leaf_verdict(self, node_id: int) -> int:
        """Determine winning classification verdict via majority class vote."""
        class_counts = self.values[node_id][0]
        return int(np.argmax(class_counts))

    def generate_c_header(self) -> str:
        """Generate MISRA-compliant C99 header file content with static const arrays.

        Returns:
            A string containing the full C99 header source code.
        """
        lines: List[str] = [
            "/**",
            " * @file transpiled_model.h",
            " * @brief Auto-generated decision tree lookup matrices from DaShield MLOps.",
            " *",
            " * Zero-RAM footprint: mapped directly into MCU Flash (.rodata).",
            " * Bounded WCET traversal: O(depth) with depth <= 6.",
            " */",
            "",
            "#ifndef TRANSPILED_MODEL_H",
            "#define TRANSPILED_MODEL_H",
            "",
            "#include <stdint.h>",
            "",
            "#ifdef __cplusplus",
            'extern "C" {',
            "#endif",
            "",
            f"#define MICROSHIELD_TREE_MAX_DEPTH      {MAX_ALLOWED_DEPTH}U",
            f"#define MICROSHIELD_TREE_NODE_COUNT     {self.n_nodes}U",
            "",
        ]

        # 1. TREE_CHILD_LEFT
        lines.append("static const int16_t TREE_CHILD_LEFT[MICROSHIELD_TREE_NODE_COUNT] = {")
        for i in range(self.n_nodes):
            comma = "," if i < self.n_nodes - 1 else ""
            lines.append(f"    {int(self.children_left[i]):4d}{comma}  /* Node {i} */")
        lines.append("};")
        lines.append("")

        # 2. TREE_CHILD_RIGHT
        lines.append("static const int16_t TREE_CHILD_RIGHT[MICROSHIELD_TREE_NODE_COUNT] = {")
        for i in range(self.n_nodes):
            comma = "," if i < self.n_nodes - 1 else ""
            lines.append(f"    {int(self.children_right[i]):4d}{comma}  /* Node {i} */")
        lines.append("};")
        lines.append("")

        # 3. TREE_FEATURE
        lines.append("static const uint8_t TREE_FEATURE[MICROSHIELD_TREE_NODE_COUNT] = {")
        for i in range(self.n_nodes):
            feat_idx = int(self.feature[i]) if not self.is_leaf(i) else 0
            comma = "," if i < self.n_nodes - 1 else ""
            lines.append(f"    {feat_idx:2d}U{comma}  /* Node {i} */")
        lines.append("};")
        lines.append("")

        # 4. TREE_THRESHOLD
        lines.append("static const float TREE_THRESHOLD[MICROSHIELD_TREE_NODE_COUNT] = {")
        for i in range(self.n_nodes):
            thresh_val = float(self.threshold[i]) if not self.is_leaf(i) else 0.0
            comma = "," if i < self.n_nodes - 1 else ""
            lines.append(f"    {thresh_val:10.4f}f{comma}  /* Node {i} */")
        lines.append("};")
        lines.append("")

        # 5. TREE_LEAF_VERDICT
        lines.append("static const uint8_t TREE_LEAF_VERDICT[MICROSHIELD_TREE_NODE_COUNT] = {")
        for i in range(self.n_nodes):
            verdict = self.get_leaf_verdict(i) if self.is_leaf(i) else 2
            comma = "," if i < self.n_nodes - 1 else ""
            lines.append(f"    {verdict:2d}U{comma}  /* Node {i} ({VERDICT_NAMES.get(verdict, 'UNKNOWN')}) */")
        lines.append("};")
        lines.append("")

        # 6. TREE_LEAF_RULE_ID
        lines.append("static const uint16_t TREE_LEAF_RULE_ID[MICROSHIELD_TREE_NODE_COUNT] = {")
        for i in range(self.n_nodes):
            # Leaves receive a unique 1-based rule identifier; internal nodes receive 0
            rule_id = (i + 1) if self.is_leaf(i) else 0
            comma = "," if i < self.n_nodes - 1 else ""
            lines.append(f"    {rule_id:4d}U{comma}  /* Node {i} */")
        lines.append("};")
        lines.append("")

        lines.extend([
            "#ifdef __cplusplus",
            "}",
            "#endif",
            "",
            "#endif /* TRANSPILED_MODEL_H */",
            "",
        ])

        return "\n".join(lines)

    def generate_rule_dictionary(self) -> Dict[str, Any]:
        """Produce symbolic XAI metadata describing logic paths leading to each leaf.

        Returns:
            Dictionary mapping rule identifiers to human-readable split conditions.
        """
        rules: Dict[str, Any] = {}

        def traverse(node: int, current_path: List[str]) -> None:
            if self.is_leaf(node):
                rule_id = str(node + 1)
                verdict_code = self.get_leaf_verdict(node)
                rules[rule_id] = {
                    "node_id": node,
                    "verdict": VERDICT_NAMES.get(verdict_code, "UNKNOWN"),
                    "explanation": " AND ".join(current_path) if current_path else "Root Decision",
                }
                return

            feat_idx = int(self.feature[node])
            feat_name = FEATURE_NAMES[feat_idx] if feat_idx < len(FEATURE_NAMES) else f"f{feat_idx}"
            thresh = float(self.threshold[node])

            left_cond = f"({feat_name} <= {thresh:.3f})"
            right_cond = f"({feat_name} > {thresh:.3f})"

            traverse(int(self.children_left[node]), current_path + [left_cond])
            traverse(int(self.children_right[node]), current_path + [right_cond])

        traverse(0, [])
        return rules

    def write_artifacts(self, header_path: Path | str, rules_json_path: Path | str) -> None:
        """Write both C99 header and JSON rule dictionary to disk.

        Args:
            header_path: Target filesystem path for transpiled_model.h.
            rules_json_path: Target filesystem path for rule_dictionary.json.
        """
        Path(header_path).write_text(self.generate_c_header(), encoding="utf-8")
        rules_dict = self.generate_rule_dictionary()
        Path(rules_json_path).write_text(json.dumps(rules_dict, indent=2), encoding="utf-8")
