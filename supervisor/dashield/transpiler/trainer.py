"""Decision tree training pipeline tailored for bare-metal edge constraints.

Generates representative traffic distributions conforming to Bot-IoT and Edge-IIoTset
characteristics and trains a scikit-learn DecisionTreeClassifier bounded to depth <= 6.
"""

from __future__ import annotations

from typing import Any, Tuple
import numpy as np
from sklearn.tree import DecisionTreeClassifier  # type: ignore[import-untyped]

# Edge operational constraints
MAX_TREE_DEPTH = 6
RANDOM_SEED = 42


def generate_benchmark_dataset(
    n_samples_per_class: int = 500,
    random_seed: int = RANDOM_SEED,
) -> Tuple[np.ndarray[Any, Any], np.ndarray[Any, Any]]:
    """Synthesize representative industrial network traffic based on IoT benchmarks.

    Feature Vector composition (4D Orthogonal Space):
        - f0: norm_length [0.0, 1.0]
        - f1: delta_time_us (microsecond arrival intervals)
        - f2: protocol_flags [0.0, 1.0]
        - f3: byte_variance (dispersion across payload bytes)

    Classes:
        - 0: BENIGN (Nominal cyclic industrial Modbus/TCP polling)
        - 1: ATTACK (Volumetric buffer floods and high-entropy fuzzing)
        - 2: AMBIGUOUS (Borderline drift, out-of-spec timings, parameter variations)

    Args:
        n_samples_per_class: Number of observations per target class.
        random_seed: Deterministic seed for reproducible evaluation.

    Returns:
        Tuple of (X, y) where X is an (N, 4) float32 array and y is an (N,) int32 array.
    """
    rng = np.random.default_rng(random_seed)

    # 1. Class 0: BENIGN (Periodic flow, low payload entropy, standard size)
    f0_benign = rng.uniform(0.04, 0.15, n_samples_per_class)
    f1_benign = rng.normal(120.0, 15.0, n_samples_per_class).clip(85.0, 300.0)
    f2_benign = rng.uniform(0.0, 0.05, n_samples_per_class)
    f3_benign = rng.normal(25.0, 8.0, n_samples_per_class).clip(5.0, 48.0)
    x_benign = np.column_stack([f0_benign, f1_benign, f2_benign, f3_benign])
    y_benign = np.zeros(n_samples_per_class, dtype=np.int32)

    # 2. Class 1: ATTACK (Volumetric flood burst + High-entropy fuzzing)
    n_flood = n_samples_per_class // 2
    n_fuzz = n_samples_per_class - n_flood

    # 2a. Volumetric Buffer Flood (large packets, minimal arrival delta)
    f0_flood = rng.uniform(0.70, 1.00, n_flood)
    f1_flood = rng.uniform(5.0, 40.0, n_flood)
    f2_flood = rng.uniform(0.5, 1.0, n_flood)
    f3_flood = rng.uniform(40.0, 120.0, n_flood)
    x_flood = np.column_stack([f0_flood, f1_flood, f2_flood, f3_flood])

    # 2b. High-Entropy Fuzzing Scan (burst timing, maximum byte entropy)
    f0_fuzz = rng.uniform(0.05, 0.40, n_fuzz)
    f1_fuzz = rng.uniform(5.0, 45.0, n_fuzz)
    f2_fuzz = rng.uniform(0.0, 0.2, n_fuzz)
    f3_fuzz = rng.uniform(155.0, 250.0, n_fuzz)
    x_fuzz = np.column_stack([f0_fuzz, f1_fuzz, f2_fuzz, f3_fuzz])

    x_attack = np.vstack([x_flood, x_fuzz])
    y_attack = np.ones(n_samples_per_class, dtype=np.int32)

    # 3. Class 2: AMBIGUOUS (Borderline drift, unexpected variance, transitional timings)
    f0_ambig = rng.uniform(0.05, 0.50, n_samples_per_class)
    f1_ambig = rng.uniform(70.0, 95.0, n_samples_per_class)
    f2_ambig = rng.uniform(0.0, 0.3, n_samples_per_class)
    f3_ambig = rng.uniform(52.0, 145.0, n_samples_per_class)
    x_ambig = np.column_stack([f0_ambig, f1_ambig, f2_ambig, f3_ambig])
    y_ambig = np.full(n_samples_per_class, 2, dtype=np.int32)

    # Combine and shuffle
    x_all = np.vstack([x_benign, x_attack, x_ambig]).astype(np.float32)
    y_all = np.concatenate([y_benign, y_attack, y_ambig])

    shuffle_indices = rng.permutation(len(y_all))
    return x_all[shuffle_indices], y_all[shuffle_indices]


def train_bounded_decision_tree(
    x_train: np.ndarray[Any, Any],
    y_train: np.ndarray[Any, Any],
    max_depth: int = MAX_TREE_DEPTH,
    random_seed: int = RANDOM_SEED,
) -> DecisionTreeClassifier:
    """Train a scikit-learn decision tree under deterministic hardware depth bounds.

    Args:
        x_train: Training feature matrix of shape (N, 4).
        y_train: Target classification labels of shape (N,).
        max_depth: Strict ceiling on tree depth (defaults to 6).
        random_seed: Fixed seed for deterministic split selections.

    Returns:
        Fitted DecisionTreeClassifier instance complying with depth <= 6.
    """
    classifier = DecisionTreeClassifier(
        criterion="gini",
        max_depth=max_depth,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=random_seed,
    )
    classifier.fit(x_train, y_train)
    return classifier
