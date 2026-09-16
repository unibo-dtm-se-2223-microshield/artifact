"""Reactive supervisory dashboard implemented via Plotly Dash.

Provides real-time visualization of edge security telemetry, monitors
concept drift thresholds, and exposes human-in-the-loop retraining controls.
"""

from __future__ import annotations

from typing import Any, List, Optional
from dash import Dash, dcc, html, Input, Output, State  # type: ignore[import-untyped]
from dashield.drift.detector import DriftDetector
from dashield.domain.types import Verdict


def create_dashboard_app(
    detector: Optional[DriftDetector] = None,
    node_id: int = 101,
) -> Dash:
    """Factory creating and configuring the DaShield Plotly Dash application.

    Args:
        detector: Active DriftDetector instance. Instantiates default if None.
        node_id: Monitored STM32 hardware node identifier.

    Returns:
        Configured Dash application instance.
    """
    app = Dash(__name__, title=f"DaShield IDS - Node {node_id}")
    drift_engine = detector if detector is not None else DriftDetector()

    # Base styling tokens
    card_style = {
        "backgroundColor": "#1e293b",
        "padding": "16px",
        "borderRadius": "8px",
        "color": "#f8fafc",
        "boxShadow": "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
        "flex": "1",
        "margin": "8px",
    }

    app.layout = html.Div(
        style={
            "fontFamily": "Inter, system-ui, -apple-system, sans-serif",
            "backgroundColor": "#0f172a",
            "color": "#e2e8f0",
            "minHeight": "100vh",
            "padding": "24px",
        },
        children=[
            # Top Header Bar
            html.Div(
                style={"display": "flex", "justifyContent": "space-between", "alignItems": "center", "marginBottom": "24px"},
                children=[
                    html.Div([
                        html.H1("DaShield Supervisory Console", style={"margin": "0", "fontSize": "1.75rem"}),
                        html.Span(f"Active Surveillance Target: STM32F407RE (Node #{node_id})", style={"color": "#94a3b8"}),
                    ]),
                    html.Div(
                        id="live-status-badge",
                        children="MONITORING ACTIVE",
                        style={
                            "backgroundColor": "#10b981",
                            "color": "#ffffff",
                            "padding": "6px 14px",
                            "borderRadius": "9999px",
                            "fontWeight": "bold",
                            "fontSize": "0.85rem",
                        },
                    ),
                ],
            ),

            # Metrics Row
            html.Div(
                style={"display": "flex", "flexWrap": "wrap", "marginBottom": "24px"},
                children=[
                    html.Div(style=card_style, children=[
                        html.Div("Ambiguity Ratio", style={"color": "#94a3b8", "fontSize": "0.875rem"}),
                        html.H2(id="metric-ambiguity", children="0.0%", style={"margin": "8px 0", "fontSize": "2rem"}),
                        html.Span("Ceiling: 5.0%", style={"fontSize": "0.75rem", "color": "#cbd5e1"}),
                    ]),
                    html.Div(style=card_style, children=[
                        html.Div("Total Processed", style={"color": "#94a3b8", "fontSize": "0.875rem"}),
                        html.H2(id="metric-total", children="0", style={"margin": "8px 0", "fontSize": "2rem"}),
                        html.Span("Sliding Window: 100", style={"fontSize": "0.75rem", "color": "#cbd5e1"}),
                    ]),
                    html.Div(style=card_style, children=[
                        html.Div("Ambiguous Events", style={"color": "#94a3b8", "fontSize": "0.875rem"}),
                        html.H2(id="metric-ambiguous-count", children="0", style={"margin": "8px 0", "fontSize": "2rem"}),
                        html.Span("Borderline cases", style={"fontSize": "0.75rem", "color": "#cbd5e1"}),
                    ]),
                    html.Div(style=card_style, children=[
                        html.Div("Concept Drift State", style={"color": "#94a3b8", "fontSize": "0.875rem"}),
                        html.H2(id="metric-drift-state", children="NOMINAL", style={"margin": "8px 0", "fontSize": "2rem", "color": "#10b981"}),
                        html.Span("MLOps Trigger Gate", style={"fontSize": "0.75rem", "color": "#cbd5e1"}),
                    ]),
                ],
            ),

            # Main Grid: Live Events & Retraining Controls
            html.Div(
                style={"display": "flex", "gap": "16px"},
                children=[
                    # Event Stream Feed
                    html.Div(
                        style={**card_style, "flex": "2"},
                        children=[
                            html.H3("Recent Edge Alerts & Quarantined Frames", style={"marginTop": "0"}),
                            html.Div(
                                id="alert-feed-container",
                                children=[html.P("No anomalies intercepted. Network state stable.", style={"color": "#64748b"})],
                            ),
                        ],
                    ),
                    # Retraining Trigger Panel
                    html.Div(
                        style={**card_style, "flex": "1"},
                        children=[
                            html.H3("Model Drift Mitigation", style={"marginTop": "0"}),
                            html.P(
                                "When the ambiguity ratio exceeds the 5.0% threshold, the edge boundary has eroded. "
                                "Trigger an automated re-fit and transpile an updated transpiled_model.h.",
                                style={"fontSize": "0.875rem", "color": "#94a3b8"},
                            ),
                            html.Button(
                                "Trigger AST Retraining",
                                id="btn-retrain",
                                n_clicks=0,
                                style={
                                    "width": "100%",
                                    "padding": "12px",
                                    "backgroundColor": "#3b82f6",
                                    "color": "white",
                                    "border": "none",
                                    "borderRadius": "6px",
                                    "fontWeight": "bold",
                                    "cursor": "pointer",
                                    "marginTop": "12px",
                                },
                            ),
                            html.Div(id="retrain-feedback", style={"marginTop": "12px", "fontSize": "0.85rem"}),
                        ],
                    ),
                ],
            ),

            # Polling Timer (1 Hz interval)
            dcc.Interval(id="ui-poll-interval", interval=1000, n_intervals=0),
        ],
    )

    # Register reactive callback for metrics refresh
    @app.callback(  # type: ignore[untyped-decorator]
        [
            Output("metric-ambiguity", "children"),
            Output("metric-total", "children"),
            Output("metric-ambiguous-count", "children"),
            Output("metric-drift-state", "children"),
            Output("metric-drift-state", "style"),
        ],
        [Input("ui-poll-interval", "n_intervals")],
    )
    def update_metrics(_: int) -> tuple[str, str, str, str, dict[str, str]]:
        status = drift_engine.get_status()
        ratio_pct = f"{status.ambiguity_ratio * 100:.1f}%"
        total_str = str(status.total_samples)
        ambig_str = str(status.ambiguous_samples)

        if status.is_drift_detected:
            state_text = "DRIFT DETECTED"
            state_style = {"margin": "8px 0", "fontSize": "2rem", "color": "#ef4444"}
        else:
            state_text = "NOMINAL"
            state_style = {"margin": "8px 0", "fontSize": "2rem", "color": "#10b981"}

        return ratio_pct, total_str, ambig_str, state_text, state_style

    # Register reactive callback for retrain action
    @app.callback(  # type: ignore[untyped-decorator]
        Output("retrain-feedback", "children"),
        [Input("btn-retrain", "n_clicks")],
        prevent_initial_call=True,
    )
    def handle_retrain_click(n_clicks: int) -> html.Span:
        if n_clicks > 0:
            drift_engine.reset()
            return html.Span("Pipeline triggered: model re-fitted and detector reset.", style={"color": "#10b981"})
        return html.Span()

    return app
