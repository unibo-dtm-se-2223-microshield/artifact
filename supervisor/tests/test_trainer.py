"""Unit tests verifying decision tree training and hardware depth constraints."""

from __future__ import annotations

from dashield.transpiler.trainer import (
    MAX_TREE_DEPTH,
    generate_benchmark_dataset,
    train_bounded_decision_tree,
)


def test_dataset_generation_dimensions() -> None:
    """Verify generated feature matrix geometry and balanced class distribution."""
    n_per_class = 200
    x_data, y_data = generate_benchmark_dataset(n_samples_per_class=n_per_class)

    assert x_data.shape == (n_per_class * 3, 4)
    assert y_data.shape == (n_per_class * 3,)
    assert set(y_data.tolist()) == {0, 1, 2}


def test_tree_depth_hardware_constraint() -> None:
    """Verify that fitted tree strictly complies with WCET bound (depth <= 6)."""
    x_data, y_data = generate_benchmark_dataset(n_samples_per_class=300)
    model = train_bounded_decision_tree(x_data, y_data, max_depth=MAX_TREE_DEPTH)

    tree_depth = model.get_depth()
    assert tree_depth <= MAX_TREE_DEPTH, f"Tree depth {tree_depth} violates bound {MAX_TREE_DEPTH}"


def test_tree_classification_performance() -> None:
    """Verify baseline model achieves robust discrimination across benchmark classes."""
    x_data, y_data = generate_benchmark_dataset(n_samples_per_class=400)
    model = train_bounded_decision_tree(x_data, y_data, max_depth=MAX_TREE_DEPTH)

    accuracy = float(model.score(x_data, y_data))
    assert accuracy > 0.90, f"Expected accuracy > 0.90, obtained {accuracy:.3f}"
