"""
URL configuration for Hadnx.
"""
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from django.conf import settings
from apps.users.views import health_check
from core.permissions import get_mode_config, is_saas_mode


def config_view(request):
    """Return current mode configuration for frontend."""
    return JsonResponse(get_mode_config())


urlpatterns = [
    # Health check at root
    path('', health_check, name='health'),
    path('api/health/', health_check, name='api-health'),
    
    # Config endpoint for frontend
    path('api/config/', config_view, name='api-config'),
    
    # Admin
    path('admin/', admin.site.urls),
    
    # API endpoints (FREE - always available)
    path('api/auth/', include('apps.users.urls')),
    path('api/scans/', include('apps.scanner.urls')),
    path('api/reports/', include('apps.reports.urls')),
    
    # PAID features - URLs always registered, gating handled by view decorators
    # This allows admins to access features in any mode
    path('api/advanced/', include('apps.advanced_scanner.urls')),
    path('api/compliance/', include('apps.compliance.urls')),
]

# Subscriptions only in SAAS mode (no admin bypass needed for this)
# if is_saas_mode():
#     urlpatterns += [
#         path('api/subscriptions/', include('apps.subscriptions.urls')),
#     ]
