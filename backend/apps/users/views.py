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
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        login(request, user)
        return Response({
            'user': UserSerializer(user).data,
            'message': 'Login successful'
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
        return Response(UserSerializer(request.user).data)
    return Response({})  # Return empty object, not None (which creates empty body)


@api_view(['GET'])
@permission_classes([AllowAny])
def csrf_view(request):
    """Get CSRF token for forms."""
    return Response({'csrfToken': get_token(request)})
