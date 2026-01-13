"""
API views for reports app.
"""
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404

from .models import Report
from .serializers import ReportSerializer
from apps.scanner.models import Scan


class ReportViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for security reports.
    
    list: GET /api/reports/ - List all reports
    retrieve: GET /api/reports/{id}/ - Get report details
    """
    queryset = Report.objects.select_related('scan').all()
    serializer_class = ReportSerializer
    
    @action(detail=False, methods=['get'], url_path='scan/(?P<scan_id>[^/.]+)')
    def scan(self, request, scan_id=None):
        """Get report by scan ID."""
        report = get_object_or_404(Report, scan__id=scan_id)
        serializer = self.get_serializer(report)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'], url_path='(?P<scan_id>[^/.]+)/export')
    def export(self, request, scan_id=None):
        """
        Export report.
        Requires paid subscription for PDF/JSON export.
        """
        # Check feature access
        from core.permissions import is_paid_feature
        
        fmt = request.query_params.get('format', 'json')
        feature_name = f'export_{fmt}'
        
        if not is_paid_feature(feature_name):
             return Response(
                {'error': f'Export to {fmt.upper()} is a paid feature', 'feature': feature_name},
                status=403
            )

        # Get or create report for this scan
        scan = get_object_or_404(Scan, pk=scan_id)
        report, _ = Report.objects.get_or_create(scan=scan)
        
        if fmt == 'pdf':
            # PDF generation to be implemented
            # For now return JSON with a flag
            return Response({
                'message': 'PDF export simulation',
                'scan_id': str(scan.id),
                'status': 'success'
            })
            
        serializer = self.get_serializer(report)
        return Response(serializer.data)
