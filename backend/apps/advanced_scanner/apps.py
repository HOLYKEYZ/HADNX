"""
Advanced Scanner App Configuration.
This app contains PAID-only features for advanced security scanning.
"""
from django.apps import AppConfig


class AdvancedScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.advanced_scanner'
    verbose_name = 'Advanced Security Scanner'
