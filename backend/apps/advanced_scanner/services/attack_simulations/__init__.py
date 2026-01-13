"""
Attack simulation module exports.
"""
from .clickjacking_test import test_clickjacking_risk
from .cors_misuse import test_cors_misuse
from .csrf_risk import test_csrf_risk
from .open_redirect import test_open_redirect
from .host_header_injection import test_host_header_injection

__all__ = [
    'test_clickjacking_risk',
    'test_cors_misuse', 
    'test_csrf_risk',
    'test_open_redirect',
    'test_host_header_injection',
]
