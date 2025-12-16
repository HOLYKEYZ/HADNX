"""
URL configuration for Hadnx.
"""
from django.contrib import admin
from django.urls import path, include
from apps.users.views import health_check

urlpatterns = [
    # Health check at root
    path('', health_check, name='health'),
    path('api/health/', health_check, name='api-health'),
    
    # Admin
    path('admin/', admin.site.urls),
    
    # API endpoints
    path('api/auth/', include('apps.users.urls')),
    path('api/scans/', include('apps.scanner.urls')),
    path('api/reports/', include('apps.reports.urls')),
]
