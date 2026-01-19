"""
Authentication API views.
"""
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import login, logout
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt

from .serializers import UserSerializer, RegisterSerializer, LoginSerializer


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Health check endpoint for the API."""
    return Response({
        'status': 'ok',
        'service': 'Hadnx Security Scanner API',
        'version': '1.0.0'
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    """Register a new user."""
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        login(request, user)
        return Response({
            'user': UserSerializer(user).data,
            'message': 'Registration successful'
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """Login user."""
    try:
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)
            return Response({
                'user': UserSerializer(user).data,
                'message': 'Login successful'
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        import traceback
        print(traceback.format_exc()) # Log to console for Render
        return Response({'detail': f"Server Error: {str(e)}", 'trace': str(traceback.format_exc())}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout user."""
    logout(request)
    return Response({'message': 'Logged out successfully'})


@csrf_exempt
@api_view(['GET'])
@permission_classes([AllowAny])
def me_view(request):
    """Get current authenticated user. Returns empty object if not authenticated."""
    if request.user.is_authenticated:
        from apps.scanner.services.exploit.scope_validator import is_exploitation_admin
        user_data = UserSerializer(request.user).data
        # Add exploitation admin status and domains
        user_data['is_exploitation_admin'] = is_exploitation_admin(request.user)
        user_data['authorized_domains'] = request.user.authorized_domains or []
        return Response(user_data)
    return Response({})  # Return empty object, not None (which creates empty body)


@api_view(['GET'])
@permission_classes([AllowAny])
def csrf_view(request):
    """Get CSRF token for forms."""
    return Response({'csrfToken': get_token(request)})


@api_view(['GET', 'POST', 'DELETE'])
@permission_classes([IsAuthenticated])
def authorized_domains_view(request):
    """
    Manage authorized domains for exploitation.
    Only available to exploitation admin.
    """
    from apps.scanner.services.exploit.scope_validator import is_exploitation_admin
    
    # Check admin status
    if not is_exploitation_admin(request.user):
        return Response(
            {'error': 'Exploitation features are restricted to authorized administrators'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    if request.method == 'GET':
        # Return current list
        return Response({
            'domains': request.user.authorized_domains or [],
            'is_admin': True
        })
    
    elif request.method == 'POST':
        # Add domain
        domain = request.data.get('domain', '').strip().lower()
        if not domain:
            return Response({'error': 'Domain is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        domains = request.user.authorized_domains or []
        if domain not in domains:
            domains.append(domain)
            request.user.authorized_domains = domains
            request.user.save()
        
        return Response({
            'domains': request.user.authorized_domains,
            'message': f'Domain {domain} added'
        })
    
    elif request.method == 'DELETE':
        # Remove domain
        domain = request.data.get('domain', '').strip().lower()
        if not domain:
            return Response({'error': 'Domain is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        domains = request.user.authorized_domains or []
        if domain in domains:
            domains.remove(domain)
            request.user.authorized_domains = domains
            request.user.save()
        
        return Response({
            'domains': request.user.authorized_domains,
            'message': f'Domain {domain} removed'
        })

