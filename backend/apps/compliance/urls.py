"""
URL configuration for compliance app.
"""
from django.urls import path
from .views import (
    ComplianceReportView,
    OWASPReportView,
    NISTReportView,
    ISO27001ReportView,
)

urlpatterns = [
    path('<uuid:scan_id>/', ComplianceReportView.as_view(), name='compliance-report'),
    path('<uuid:scan_id>/owasp/', OWASPReportView.as_view(), name='owasp-report'),
    path('<uuid:scan_id>/nist/', NISTReportView.as_view(), name='nist-report'),
    path('<uuid:scan_id>/iso27001/', ISO27001ReportView.as_view(), name='iso27001-report'),
]
