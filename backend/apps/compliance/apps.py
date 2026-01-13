"""
Compliance App Configuration.
This app contains PAID-only features for compliance mapping.
"""
from django.apps import AppConfig


class ComplianceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.compliance'
    verbose_name = 'Compliance Mapping'
