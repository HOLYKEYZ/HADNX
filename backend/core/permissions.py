"""
Feature Gating System for Hadnx.

Controls access to paid features based on HADNX_MODE setting.
- OSS: Open-source mode, only FREE features
- SAAS: Full SaaS mode with paid features

Usage:
    from core.permissions import is_paid_feature, require_paid_feature
    
    # Check if feature is available
    if is_paid_feature('advanced_scanner'):
        run_advanced_scan()
    
    # Decorator for views
    @require_paid_feature('compliance')
    def compliance_report(request):
        ...
"""
import functools
from django.conf import settings
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework import status


# Available paid features
PAID_FEATURES = {
    # Advanced Scanner
    'advanced_scanner': {
        'name': 'Advanced Security Scanner',
        'description': 'Attack simulations, fingerprinting, and endpoint exposure detection',
    },
    'attack_simulations': {
        'name': 'Attack Simulations',
        'description': 'Safe, passive attack risk detection',
    },
    'clickjacking_test': {
        'name': 'Clickjacking Risk Detection',
        'description': 'Test for X-Frame-Options and CSP frame-ancestors',
    },
    'cors_misuse': {
        'name': 'CORS Misconfiguration Detection',
        'description': 'Detect dangerous CORS policies',
    },
    'csrf_risk': {
        'name': 'CSRF Risk Analysis',
        'description': 'Detect CSRF vulnerabilities',
    },
    'open_redirect': {
        'name': 'Open Redirect Detection',
        'description': 'Find potential open redirect issues',
    },
    'host_header_injection': {
        'name': 'Host Header Injection Check',
        'description': 'Passive host header analysis',
    },
    
    # Compliance
    'compliance': {
        'name': 'Compliance Mapping',
        'description': 'OWASP, NIST, and ISO 27001 compliance reports',
    },
    'owasp_mapping': {
        'name': 'OWASP Top 10 Mapping',
        'description': 'Map findings to OWASP Top 10',
    },
    'nist_mapping': {
        'name': 'NIST 800-53 Mapping',
        'description': 'Map findings to NIST controls',
    },
    'iso27001_mapping': {
        'name': 'ISO 27001 Mapping',
        'description': 'Map findings to ISO 27001 clauses',
    },
    
    # Risk Correlation
    'risk_correlation': {
        'name': 'Risk Correlation Engine',
        'description': 'Combine issues into attack chains',
    },
    
    # History & Export
    'scan_history': {
        'name': 'Scan History',
        'description': 'View and compare past scans',
    },
    'export_pdf': {
        'name': 'PDF Export',
        'description': 'Export reports as PDF',
    },
    'export_json': {
        'name': 'JSON Export',
        'description': 'Export reports as JSON',
    },
    
    # Monitoring
    'continuous_monitoring': {
        'name': 'Continuous Monitoring',
        'description': 'Scheduled recurring scans',
    },
    'custom_policies': {
        'name': 'Custom Policies',
        'description': 'Define custom security policies',
    },
}


def get_hadnx_mode() -> str:
    """
    Get the current Hadnx mode.
    
    Returns:
        'OSS' or 'SAAS'
    """
    return getattr(settings, 'HADNX_MODE', 'OSS')


def is_saas_mode() -> bool:
    """Check if running in SaaS mode."""
    return get_hadnx_mode() == 'SAAS'


def is_oss_mode() -> bool:
    """Check if running in OSS mode."""
    return get_hadnx_mode() == 'OSS'


def is_paid_feature(feature_name: str) -> bool:
    """
    Check if a paid feature is available in current mode.
    
    In OSS mode, all paid features return False.
    In SAAS mode, returns True (subscription check happens elsewhere).
    
    Args:
        feature_name: Name of the feature to check
        
    Returns:
        True if feature is available, False otherwise
    """
    if feature_name not in PAID_FEATURES:
        # Unknown feature, allow by default (might be FREE)
        return True
    
    return is_saas_mode()


def get_feature_info(feature_name: str) -> dict:
    """Get information about a feature."""
    return PAID_FEATURES.get(feature_name, {
        'name': feature_name,
        'description': 'Unknown feature',
    })


def require_paid_feature(feature_name: str):
    """
    Decorator to require a paid feature for a view.
    
    Usage:
        @require_paid_feature('advanced_scanner')
        def advanced_scan_view(request):
            ...
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # 1. Staff/Superusers always bypass
            if request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser):
                return view_func(request, *args, **kwargs)
                
            # 2. If feature is not available in this mode (Global Lock)
            # In SAAS mode, is_paid_feature returns True for paid features
            # In OSS mode, it returns False for paid features
            available_in_mode = is_paid_feature(feature_name)
            
            if not available_in_mode and is_oss_mode():
                 # Strictly unavailable in OSS
                 feature_info = get_feature_info(feature_name)
                 raise PermissionDenied({
                    'error': 'feature_not_available',
                    'feature': feature_name,
                    'message': f"Feature not available in OSS mode: {feature_info.get('name')}"
                })
            
            # 3. If SAAS mode, check user subscription
            if is_saas_mode():
                # We need to import here to avoid circular dependencies
                from apps.subscriptions.services import SubscriptionService
                
                # Check subscription
                sub = SubscriptionService.get_or_create_subscription(request.user)
                if not sub.is_valid:
                    feature_info = get_feature_info(feature_name)
                    raise PermissionDenied({
                        'error': 'paid_feature_required',
                        'feature': feature_name,
                        'feature_name': feature_info.get('name'),
                        'feature_description': feature_info.get('description'),
                        'message': f"This feature requires a paid subscription: {feature_info.get('name')}",
                        'upgrade_url': '/pricing',
                    })

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_paid_feature_api(feature_name: str):
    """
    Decorator for DRF APIView methods.
    
    Usage:
        class AdvancedScanView(APIView):
            @require_paid_feature_api('advanced_scanner')
            def post(self, request):
                ...
    """
    def decorator(view_method):
        @functools.wraps(view_method)
        def wrapper(self, request, *args, **kwargs):
            # 1. Staff/Superusers always bypass
            if request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser):
                return view_method(self, request, *args, **kwargs)

            # 2. Mode check
            available_in_mode = is_paid_feature(feature_name)
            
            if not available_in_mode and is_oss_mode():
                 return Response({'error': 'Feature not available in OSS mode'}, status=status.HTTP_404_NOT_FOUND)

            # 3. Subscription check in SAAS mode
            if is_saas_mode():
                from apps.subscriptions.services import SubscriptionService
                sub = SubscriptionService.get_or_create_subscription(request.user)
                
                if not sub.is_valid:
                    feature_info = get_feature_info(feature_name)
                    return Response({
                        'error': 'paid_feature_required',
                        'feature': feature_name,
                        'feature_name': feature_info.get('name'),
                        'feature_description': feature_info.get('description'),
                        'message': f"This feature requires a paid subscription: {feature_info.get('name')}",
                        'upgrade_url': '/pricing',
                    }, status=status.HTTP_402_PAYMENT_REQUIRED)
            
            return view_method(self, request, *args, **kwargs)
        return wrapper
    return decorator


def get_available_features() -> dict:
    """
    Get all features and their availability status.
    
    Returns:
        Dict of feature_name -> {info, available}
    """
    result = {}
    for feature_name, info in PAID_FEATURES.items():
        result[feature_name] = {
            **info,
            'available': is_paid_feature(feature_name),
            'is_paid': True,
        }
    return result


def get_mode_config() -> dict:
    """
    Get current mode configuration for frontend.
    
    Returns:
        Dict with mode info and feature availability
    """
    return {
        'mode': get_hadnx_mode(),
        'is_saas': is_saas_mode(),
        'is_oss': is_oss_mode(),
        'features': get_available_features(),
    }
