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
from .services.pdf_generator import PDFGenerator
from .services.ai_service import AIService
from rest_framework.views import APIView
import requests
import time
from .services.exploit.scope_validator import ScopeValidator
from .services.tools.nuclei_service import NucleiService
from .services.tools.sqlmap_service import SQLMapService

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
    queryset = Scan.objects.all().order_by('-created_at')
    
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
            if session_scans >= 100:  # Temporarily increased limit for production debugging
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
        
        exploitation_enabled = serializer.validated_data.get('exploitation_enabled', False)

        # Create scan record
        scan = Scan.objects.create(
            url=url,
            domain=domain,
            user=request.user if request.user.is_authenticated else None,
            status=Scan.Status.PENDING,
            exploitation_enabled=exploitation_enabled
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

    @action(detail=True, methods=['post'])
    def chat(self, request, pk=None):
        """
        Chat with AI about the scan.
        Body: { messages: [...] }
        """
        scan = self.get_object()
        messages = request.data.get('messages', [])
        
        # Build context from scan summary
        context = f"""
        Scan for: {scan.domain} ({scan.url})
        Overall Grade: {scan.grade} (Score: {scan.overall_score})
        Findings: {scan.findings.count()} total.
        Critical: {scan.findings.filter(severity='CRITICAL').count()}
        High: {scan.findings.filter(severity='HIGH').count()}
        """
        
        response = AIService.chat(messages, context=context)
        return Response(response)

    @action(detail=True, methods=['post'])
    def analyze_finding(self, request, pk=None):
        """
        Get expert analysis for a specific finding.
        Body: { finding_id: <int> }
        """
        scan = self.get_object()
        finding_id = request.data.get('finding_id')
        
        try:
            finding = scan.findings.get(id=finding_id)
            finding_data = {
                'issue': finding.issue,
                'category': finding.category,
                'severity': finding.severity,
                'affected_element': finding.affected_element,
                'description': finding.description,
                'evidence': finding.evidence
            }
            
            response = AIService.analyze_finding(finding_data)
            return Response(response)
            
        except Scan.findings.model.DoesNotExist:
            return Response({'error': 'Finding not found'}, status=404)
        serializer = ScanStatusSerializer(scan)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='export/pdf')
    def export_pdf(self, request, pk=None):
        """Export scan report as PDF."""
        scan = self.get_object()
        buffer = PDFGenerator.generate(scan)
        filename = f"hadnx_scan_{scan.domain}.pdf"
        
        return FileResponse(
            buffer,
            as_attachment=True,
            filename=filename,
            content_type='application/pdf'
        )
    
    def destroy(self, request, *args, **kwargs):
        """Delete a scan and its findings."""
        return super().destroy(request, *args, **kwargs)


@method_decorator(csrf_exempt, name='dispatch')
class RepeaterView(APIView):
    """
    Interactive Repeater Tool.
    Allows Users (Admins) to manually send HTTP requests to Authorized Domains.
    """
    
    def post(self, request):
        url = request.data.get('url')
        method = request.data.get('method', 'GET').upper()
        headers = request.data.get('headers', {})
        body = request.data.get('body', None)
        follow_redirects = request.data.get('follow_redirects', True)
        
        if not url:
            return Response({'error': 'URL is required'}, status=400)
            
        # 1. Scope Validation
        try:
            ScopeValidator.validate_or_raise(url, request.user)
        except PermissionError as e:
            return Response({'error': str(e)}, status=403)
            
        # 2. Add User-Agent if missing
        if 'User-Agent' not in headers:
            headers['User-Agent'] = 'Hadnxjs/1.0 (Security Scanner)'
            
        # 3. Execute Request
        try:
            start_time = time.time()
            resp = requests.request(
                method,
                url,
                headers=headers,
                data=body,
                allow_redirects=follow_redirects,
                timeout=10,
                verify=False
            )
            elapsed_ms = int((time.time() - start_time) * 1000)
            
            return Response({
                'status': resp.status_code,
                'status_text': resp.reason,
                'headers': dict(resp.headers),
                'body': resp.text,
                'elapsed': elapsed_ms,
                'url': resp.url
            })
            
        except requests.RequestException as e:
            return Response({'error': f"Request failed: {str(e)}"}, status=502)


@method_decorator(csrf_exempt, name='dispatch')
class ScriptRunnerView(APIView):
    """
    Executes arbitrary Python scripts provided by the user.
    WARNING: RCE capability. Admin only.
    """
    
    def post(self, request):
        script_code = request.data.get('script')
        if not script_code:
            return Response({'error': 'Script code is required'}, status=400)
            
        import subprocess
        import tempfile
        import os
        
        # Security: In a real prod environment, this should be sandboxed (Docker/nsjail).
        # For this 'Pentest Partner' tool, we assume the user is the authorized admin.
        
        try:
            # Create temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
                tmp.write(script_code)
                tmp_path = tmp.name
                
            # Run it
            start_time = time.time()
            process = subprocess.run(
                ['python', tmp_path],
                capture_output=True,
                text=True,
                timeout=30 # 30s timeout
            )
            elapsed = time.time() - start_time
            
            # Cleanup
            os.remove(tmp_path)
            
            return Response({
                'stdout': process.stdout,
                'stderr': process.stderr,
                'returncode': process.returncode,
                'elapsed': round(elapsed, 2)
            })
            
        except subprocess.TimeoutExpired:
            return Response({'error': 'Script execution timed out (30s limit)', 'stderr': '', 'stdout': ''}, status=408)
        except Exception as e:
            return Response({'error': str(e), 'stderr': str(e), 'stdout': ''}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class NucleiScanView(APIView):
    """
    Runs a Nuclei Scan on a target.
    Requires 'nuclei' binary installed on server.
    """
    
    def post(self, request):
        target = request.data.get('url')
        if not target:
            return Response({'error': 'Target URL is required'}, status=400)
            
        # 1. Scope Validation (Strict)
        try:
            ScopeValidator.validate_or_raise(target, request.user)
        except PermissionError as e:
            return Response({'error': str(e)}, status=403)
            
        # 2. Run Scan
        result = NucleiService.run_scan(target)
        
        # 3. Handle Errors
        if 'error' in result:
             status_code = 500 if 'Execution Failed' in result.get('error', '') else 400
             if 'Nuclei CLI not found' in result.get('error'):
                 status_code = 503 # Service Unavailable
             return Response(result, status=status_code)
             
        return Response(result)


@method_decorator(csrf_exempt, name='dispatch')
class SQLMapScanView(APIView):
    """
    Runs SQLMap Scan.
    Requires sqlmap cloned in backend/tools/sqlmap.
    """
    def post(self, request):
        target = request.data.get('url')
        if not target:
             return Response({'error': 'Target URL is required'}, status=400)
             
        # 1. Scope Validation
        try:
             ScopeValidator.validate_or_raise(target, request.user)
        except PermissionError as e:
             return Response({'error': str(e)}, status=403)
             
        # 2. Run Scan
        result = SQLMapService.run_scan(target)
        
        # 3. Handle Errors
        if 'error' in result:
             status_code = 500
             if 'SQLMap not found' in result.get('error', ''):
                 status_code = 503
             return Response(result, status=status_code)
             
        return Response(result)
