"""
Advanced scanner services module exports.
"""
from .correlation_engine import analyze_risk_correlations, get_risk_heatmap_data

__all__ = [
    'analyze_risk_correlations',
    'get_risk_heatmap_data',
]
