"""
Access control for advanced scanner features.
All features in this module require paid subscription.
"""
from core.permissions import require_paid_feature, require_paid_feature_api, is_paid_feature


def check_advanced_scanner_access() -> bool:
    """Check if advanced scanner features are available."""
    return is_paid_feature('advanced_scanner')


# Convenience decorators for this module
def require_advanced_scanner(view_func):
    """Decorator requiring advanced_scanner access."""
    return require_paid_feature('advanced_scanner')(view_func)


def require_advanced_scanner_api(view_method):
    """Decorator for DRF views requiring advanced_scanner access."""
    return require_paid_feature_api('advanced_scanner')(view_method)
