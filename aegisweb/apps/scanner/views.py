"""
API views for scanner app.
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404

from .models import Scan
from .serializers import (
    ScanListSerializer, ScanDetailSerializer,
    ScanCreateSerializer, ScanStatusSerializer
)
from .tasks import run_security_scan


class ScanViewSet(viewsets.ModelViewSet):
    """
    API endpoint for security scans.
    
    list: GET /api/scans/ - List all scans
    create: POST /api/scans/ - Start a new scan
    retrieve: GET /api/scans/{id}/ - Get scan details
    status: GET /api/scans/{id}/status/ - Poll scan status
    """
    queryset = Scan.objects.all()
    
    def get_serializer_class(self):
        if self.action == 'list':
            return ScanListSerializer
        elif self.action == 'create':
            return ScanCreateSerializer
        elif self.action == 'status':
            return ScanStatusSerializer
        return ScanDetailSerializer
    
    def create(self, request, *args, **kwargs):
        """Start a new security scan."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        url = serializer.validated_data['url']
        
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Create scan record
        scan = Scan.objects.create(
            url=url,
            domain=domain,
            status=Scan.Status.PENDING
        )
        
        # In DEBUG mode, run synchronously (no Celery needed)
        # In production, queue async task
        from django.conf import settings
        if getattr(settings, 'DEBUG', False):
            # Run scan synchronously for development
            run_security_scan(str(scan.id))
            # Refresh from DB to get updated data
            scan.refresh_from_db()
        else:
            # Queue async scan task (requires Celery)
            run_security_scan.delay(str(scan.id))
        
        return Response(
            ScanDetailSerializer(scan).data,
            status=status.HTTP_202_ACCEPTED
        )
    
    @action(detail=True, methods=['get'])
    def status(self, request, pk=None):
        """Poll scan status (lightweight endpoint for polling)."""
        scan = get_object_or_404(Scan, pk=pk)
        serializer = ScanStatusSerializer(scan)
        return Response(serializer.data)
    
    def destroy(self, request, *args, **kwargs):
        """Delete a scan and its findings."""
        return super().destroy(request, *args, **kwargs)
