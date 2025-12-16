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
    
    @action(detail=True, methods=['get'])
    def export(self, request, pk=None):
        """Export report as JSON."""
        report = get_object_or_404(Report, pk=pk)
        serializer = self.get_serializer(report)
        return Response(serializer.data)
