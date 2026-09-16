"""Unit tests verifying AST transpiler C code and XAI JSON generation."""

from __future__ import annotations

import json
from pathlib import Path
import numpy as np
import pytest
from sklearn.tree import DecisionTreeClassifier  # type: ignore[import-untyped]
from dashield.transpiler.trainer import generate_benchmark_dataset, train_bounded_decision_tree
from dashield.transpiler.transpiler import DecisionTreeTranspiler


@pytest.fixture
def trained_model() -> DecisionTreeTranspiler:
    """Fixture providing a transpiler instance with a valid bounded tree."""
    x_data, y_data = generate_benchmark_dataset(n_samples_per_class=100)
    model = train_bounded_decision_tree(x_data, y_data, max_depth=4)
    return DecisionTreeTranspiler(model)


def test_tree_depth_exceeded_guard() -> None:
    """Verify that transpiler rejects models violating hardware depth ceilings."""
    rng = np.random.default_rng(42)
    # Generate high-entropy noise forcing tree growth beyond depth 6
    x_noise = rng.normal(size=(600, 4)).astype(np.float32)
    y_noise = rng.integers(0, 3, size=600, dtype=np.int32)

    deep_model = DecisionTreeClassifier(
        max_depth=12,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=42,
    )
    deep_model.fit(x_noise, y_noise)

    # Ensure test premise holds: fitted tree must exceed max allowed depth (6)
    assert deep_model.get_depth() > 6

    with pytest.raises(ValueError, match="exceeds edge WCET ceiling"):
        DecisionTreeTranspiler(deep_model)


def test_c_header_generation_syntax(trained_model: DecisionTreeTranspiler) -> None:
    """Verify generated C99 source text contains required arrays and macro boundaries."""
    c_source = trained_model.generate_c_header()

    assert "#ifndef TRANSPILED_MODEL_H" in c_source
    assert "#define MICROSHIELD_TREE_MAX_DEPTH      6U" in c_source
    assert "TREE_CHILD_LEFT" in c_source
    assert "TREE_CHILD_RIGHT" in c_source
    assert "TREE_FEATURE" in c_source
    assert "TREE_THRESHOLD" in c_source
    assert "TREE_LEAF_VERDICT" in c_source
    assert "TREE_LEAF_RULE_ID" in c_source


def test_rule_dictionary_xai_generation(trained_model: DecisionTreeTranspiler) -> None:
    """Verify XAI dictionary contains structured explanations for all leaves."""
    rules = trained_model.generate_rule_dictionary()

    assert len(rules) > 0
    for rule_id, meta in rules.items():
        assert "verdict" in meta
        assert meta["verdict"] in {"VERDICT_BENIGN", "VERDICT_ATTACK", "VERDICT_AMBIGUOUS"}
        assert "explanation" in meta
        assert "node_id" in meta


def test_artifacts_disk_emission(tmp_path: Path, trained_model: DecisionTreeTranspiler) -> None:
    """Verify writing artifacts to disk produces valid non-empty files."""
    header_file = tmp_path / "transpiled_model.h"
    json_file = tmp_path / "rule_dictionary.json"

    trained_model.write_artifacts(header_file, json_file)

    assert header_file.exists()
    assert header_file.stat().st_size > 0

    assert json_file.exists()
    parsed_json = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(parsed_json) > 0
