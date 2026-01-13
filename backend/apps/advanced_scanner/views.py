"""
Advanced Scanner API Views.
All endpoints require paid subscription access.
"""
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from .access import require_advanced_scanner_api
from .services.attack_simulations import (
    test_clickjacking_risk,
    test_cors_misuse,
    test_csrf_risk,
    test_open_redirect,
    test_host_header_injection,
)


class AdvancedScanView(APIView):
    """
    Run advanced security scans on a URL.
    Requires paid subscription.
    """
    
    @require_advanced_scanner_api
    def post(self, request):
        """
        Run all advanced attack simulations.
        
        Request body:
            url: Target URL
            headers: Response headers from target (optional)
            cookies: List of Set-Cookie values (optional)
            html_content: HTML content (optional)
        """
        url = request.data.get('url')
        if not url:
            return Response(
                {'error': 'URL is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        headers = request.data.get('headers', {})
        cookies = request.data.get('cookies', [])
        html_content = request.data.get('html_content', '')
        
        results = []
        
        # Run all attack simulations
        try:
            # Clickjacking
            result = test_clickjacking_risk(url, headers)
            results.append({
                'test': 'clickjacking',
                **result.to_dict()
            })
            
            # CORS
            result = test_cors_misuse(url, headers)
            results.append({
                'test': 'cors_misuse',
                **result.to_dict()
            })
            
            # CSRF
            result = test_csrf_risk(url, headers, cookies, html_content)
            results.append({
                'test': 'csrf_risk',
                **result.to_dict()
            })
            
            # Open Redirect
            result = test_open_redirect(url, html_content)
            results.append({
                'test': 'open_redirect',
                **result.to_dict()
            })
            
            # Host Header Injection
            result = test_host_header_injection(url, headers, html_content)
            results.append({
                'test': 'host_header_injection',
                **result.to_dict()
            })
            
        except Exception as e:
            return Response(
                {'error': f'Scan failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Summary
        detected_issues = [r for r in results if r.get('detected')]
        critical_count = len([r for r in detected_issues if r.get('severity') == 'CRITICAL'])
        high_count = len([r for r in detected_issues if r.get('severity') == 'HIGH'])
        medium_count = len([r for r in detected_issues if r.get('severity') == 'MEDIUM'])
        
        return Response({
            'url': url,
            'results': results,
            'summary': {
                'total_tests': len(results),
                'issues_detected': len(detected_issues),
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
            }
        })


class IndividualScanView(APIView):
    """
    Run individual attack simulation tests.
    """
    
    @require_advanced_scanner_api
    def post(self, request, test_name):
        """Run a specific test."""
        url = request.data.get('url')
        headers = request.data.get('headers', {})
        cookies = request.data.get('cookies', [])
        html_content = request.data.get('html_content', '')
        
        if not url:
            return Response(
                {'error': 'URL is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        tests = {
            'clickjacking': lambda: test_clickjacking_risk(url, headers),
            'cors': lambda: test_cors_misuse(url, headers),
            'csrf': lambda: test_csrf_risk(url, headers, cookies, html_content),
            'open_redirect': lambda: test_open_redirect(url, html_content),
            'host_header': lambda: test_host_header_injection(url, headers, html_content),
        }
        
        if test_name not in tests:
            return Response(
                {'error': f'Unknown test: {test_name}', 'available_tests': list(tests.keys())},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            result = tests[test_name]()
            return Response({
                'url': url,
                'test': test_name,
                **result.to_dict()
            })
        except Exception as e:
            return Response(
                {'error': f'Test failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
