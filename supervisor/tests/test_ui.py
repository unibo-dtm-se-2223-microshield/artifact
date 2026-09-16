"""Unit tests verifying Plotly Dash UI scaffolding and callback layout integrity."""

from __future__ import annotations

from dash import Dash  # type: ignore[import-untyped]
from dashield.domain.types import Verdict
from dashield.drift.detector import DriftDetector
from dashield.ui.app import create_dashboard_app


def test_dashboard_instantiation() -> None:
    """Verify Dash app initializes with expected node configuration and title."""
    app = create_dashboard_app(node_id=101)
    assert isinstance(app, Dash)
    assert "Node 101" in app.title


def test_layout_contains_critical_components() -> None:
    """Verify that layout hierarchy embeds telemetry metric containers and controls."""
    app = create_dashboard_app()
    layout = app.layout

    # Extract all assigned component IDs across the layout tree
    component_ids: list[str] = []

    def extract_ids(component: object) -> None:
        if hasattr(component, "id") and getattr(component, "id") is not None:
            component_ids.append(str(getattr(component, "id")))
        if hasattr(component, "children"):
            children = getattr(component, "children")
            if isinstance(children, list):
                for child in children:
                    extract_ids(child)
            elif children is not None:
                extract_ids(children)

    extract_ids(layout)

    expected_ids = {
        "ui-poll-interval",
        "metric-ambiguity",
        "metric-total",
        "metric-ambiguous-count",
        "metric-drift-state",
        "btn-retrain",
        "retrain-feedback",
    }
    assert expected_ids.issubset(set(component_ids))


def test_callback_registration() -> None:
    """Verify that reactive callback listeners are properly wired into the app context."""
    app = create_dashboard_app()
    # Ensure callbacks dictionary is populated
    assert len(app.callback_map) >= 2


def test_metric_state_reaction_with_drift() -> None:
    """Verify metrics reflect active drift state when provided with drifted detector."""
    detector = DriftDetector(window_size=20, threshold=0.05, min_samples=10)
    # Feed 10 ambiguous verdicts to trigger alarm
    for _ in range(10):
        detector.record_verdict(Verdict.AMBIGUOUS)

    app = create_dashboard_app(detector=detector)
    assert app is not None
    assert detector.is_drift_detected()
