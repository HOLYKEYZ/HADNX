"""
API views for scanner app.
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import FileResponse
import io

from .services.pdf_generator import PDFGenerator

from .models import Scan
from .serializers import (
    ScanListSerializer, ScanDetailSerializer,
    ScanCreateSerializer, ScanStatusSerializer
)
from .tasks import run_security_scan


@method_decorator(csrf_exempt, name='dispatch')
class ScanViewSet(viewsets.ModelViewSet):
    """
    API endpoint for security scans.
    
    list: GET /api/scans/ - List all scans
    create: POST /api/scans/ - Start a new scan
    retrieve: GET /api/scans/{id}/ - Get scan details
    status: GET /api/scans/{id}/status/ - Poll scan status
    """
    queryset = Scan.objects.all()
    
    def get_queryset(self):
        """
        Filter scans by user to ensure data isolation.
        - Authenticated users see only their scans.
        - Anonymous users see only scans from their current session.
        """
        user = self.request.user
        if user.is_authenticated:
            # Admins see all scans to monitor the system
            if user.is_staff or user.is_superuser:
                 return Scan.objects.all()
            
            # Regular users see only their scans
            return Scan.objects.filter(user=user)
        else:
            # Anonymous users: usage logic is session-based.
            # We must filter by something present in the session or a list of IDs stored in session.
            # Storing Scan IDs in session is the standard pattern for anonymous ownership.
            scan_ids = self.request.session.get('scan_ids', [])
            return Scan.objects.filter(id__in=scan_ids)
    
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

        # Trial Limit for Anonymous Users
        if not request.user.is_authenticated:
            # Get IP address
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')
            
            # Count recent scans from this IP (or session if possible, but IP is safer for anon)
            # Ideally we'd store IP on Scan model. If Scan doesn't have user, it's anonymous.
            # Assuming 'user' field is null for anonymous scans. 
            # Storing IP is privacy sensitive, but needed for rate limiting. 
            # If we don't store IP, we can't limit effectively without a session.
            # Let's check session scan count first as it's less intrusive.
            
            session_scans = request.session.get('scan_count', 0)
            if session_scans >= 2:
                 return Response({
                    'error': 'trial_limit_exceeded',
                    'message': 'You have reached the limit of 2 free trial scans. Please sign up to continue scanning.',
                    'limit_reached': True
                }, status=status.HTTP_403_FORBIDDEN)
            
            request.session['scan_count'] = session_scans + 1
        
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Create scan record
        scan = Scan.objects.create(
            url=url,
            domain=domain,
            user=request.user if request.user.is_authenticated else None,
            status=Scan.Status.PENDING
        )
        
        # Determine strict limit for anonymous users (2 trials)
        if not request.user.is_authenticated:
            # Save scan ID to session for retrieval
            scan_ids = request.session.get('scan_ids', [])
            scan_ids.append(str(scan.id))
            request.session['scan_ids'] = scan_ids
        
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

    @action(detail=True, methods=['get'], url_path='export/pdf')
    def export_pdf(self, request, pk=None):
        """Export scan report as PDF."""
        scan = self.get_object()
        
        pdf_content = PDFGenerator.generate_report(scan)
        
        if not pdf_content:
            return Response(
                {"error": "Failed to generate PDF"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
        filename = f"Hadnx_Report_{scan.domain}_{scan.created_at.strftime('%Y%m%d')}.pdf"
        
        response = FileResponse(
            io.BytesIO(pdf_content),
            as_attachment=True,
            filename=filename,
            content_type='application/pdf'
        )
        return response
    
    
    def destroy(self, request, *args, **kwargs):
        """Delete a scan and its findings."""
        return super().destroy(request, *args, **kwargs)
