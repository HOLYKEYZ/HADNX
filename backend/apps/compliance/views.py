"""
Compliance API Views.
All endpoints require paid subscription access.
"""
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from core.permissions import require_paid_feature, require_paid_feature_api
from apps.scanner.models import Scan
from .report_generator import generate_compliance_report
from .mappings import get_owasp_summary, get_nist_summary, get_iso27001_summary


class ComplianceReportView(APIView):
    """
    Generate compliance report for a scan.
    Requires paid subscription.
    """
    
    @require_paid_feature_api('compliance')
    def get(self, request, scan_id):
        """
        Get full compliance report for a scan.
        """
        try:
            scan = Scan.objects.get(pk=scan_id)
        except Scan.DoesNotExist:
            return Response(
                {'error': 'Scan not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get findings from scan
        findings = []
        for finding in scan.findings.all():
            findings.append({
                'issue': finding.issue,
                'severity': finding.severity,
                'category': finding.category,
                'impact': finding.impact,
                'recommendation': finding.recommendation,
            })
        
        report = generate_compliance_report(findings)
        report['scan_id'] = str(scan.id)
        report['url'] = scan.url
        report['domain'] = scan.domain
        
        return Response(report)


class OWASPReportView(APIView):
    """OWASP Top 10 compliance report."""
    
    @require_paid_feature_api('owasp_mapping')
    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(pk=scan_id)
        except Scan.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
        
        findings = [{'issue': f.issue, 'severity': f.severity} for f in scan.findings.all()]
        summary = get_owasp_summary(findings)
        summary['scan_id'] = str(scan.id)
        
        return Response(summary)


class NISTReportView(APIView):
    """NIST 800-53 compliance report."""
    
    @require_paid_feature_api('nist_mapping')
    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(pk=scan_id)
        except Scan.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
        
        findings = [{'issue': f.issue, 'severity': f.severity} for f in scan.findings.all()]
        summary = get_nist_summary(findings)
        summary['scan_id'] = str(scan.id)
        
        return Response(summary)


class ISO27001ReportView(APIView):
    """ISO 27001 compliance report."""
    
    @require_paid_feature_api('iso27001_mapping')
    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(pk=scan_id)
        except Scan.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
        
        findings = [{'issue': f.issue, 'severity': f.severity} for f in scan.findings.all()]
        summary = get_iso27001_summary(findings)
        summary['scan_id'] = str(scan.id)
        
        return Response(summary)
