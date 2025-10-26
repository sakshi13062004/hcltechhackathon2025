"""
Views for registration app
"""
import logging
from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate
from django.db import transaction
from django.utils import timezone
from django.core.paginator import Paginator
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from .models import User, Role, UserRole, KYCDocument, AuditLog, SecurityEvent, Notification
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer,
    UserUpdateSerializer, KYCDocumentSerializer, KYCDocumentListSerializer,
    AdminKYCDocumentSerializer, AdminKYCReviewSerializer, AuditLogSerializer,
    SecurityEventSerializer, NotificationSerializer, UserListSerializer,
    PasswordChangeSerializer
)
from .utils import (
    AuditService, CacheService, SecurityService, send_admin_notification,
    validate_kyc_completeness
)
from .tasks import (
    process_kyc_document, notify_admin_new_registration, send_kyc_approval_email
)

logger = logging.getLogger(__name__)


@extend_schema_view(
    post=extend_schema(
        tags=['Authentication'],
        summary='Register a new user',
        description='Create a new user account with encrypted personal information',
        examples=[
            OpenApiExample(
                'Registration Example',
                value={
                    'username': 'john_doe',
                    'email': 'john@example.com',
                    'password': 'SecurePass123!',
                    'confirm_password': 'SecurePass123!',
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'phone_number': '+1234567890',
                    'date_of_birth': '1990-01-15',
                    'ssn': '123-45-6789',
                    'address': '123 Main St, New York, NY 10001'
                }
            )
        ]
    )
)
class UserRegistrationView(APIView):
    """User registration endpoint"""
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Register a new user"""
        try:
            serializer = UserRegistrationSerializer(data=request.data)
            
            if serializer.is_valid():
                with transaction.atomic():
                    # Create user
                    user = serializer.save()
                    
                    # Log audit event
                    AuditService.log_action(
                        user=user,
                        action_type='CREATE',
                        target_model='User',
                        description=f"User registered: {user.username}",
                        request=request,
                        target_id=str(user.id)
                    )
                    
                    # Cache user data
                    CacheService.cache_user_data(user)
                    
                    # Notify admin (Celery disabled)
                    # notify_admin_new_registration.delay(user.id)
                    
                    # Return user data (without sensitive information)
                    response_data = {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'customer_id': user.customer_id,
                        'kyc_status': user.kyc_status,
                        'risk_profile': user.risk_profile,
                        'is_account_verified': user.is_account_verified,
                        'created_at': user.created_at
                    }
                    
                    return Response(response_data, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return Response(
                {'error': 'Registration failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@extend_schema_view(
    post=extend_schema(
        tags=['Authentication'],
        summary='User login',
        description='Authenticate user and return JWT access and refresh tokens',
        examples=[
            OpenApiExample(
                'Login Example',
                value={
                    'username': 'john_doe',
                    'password': 'SecurePass123!'
                }
            )
        ]
    )
)
class UserLoginView(TokenObtainPairView):
    """User login endpoint with JWT tokens"""
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        """Login user and return JWT tokens"""
        try:
            serializer = UserLoginSerializer(data=request.data, context={'request': request})
            
            if serializer.is_valid():
                user = serializer.validated_data['user']
                
                # Update last login
                user.last_login = timezone.now()
                user.last_login_ip = SecurityService.get_client_ip(request)
                user.save(update_fields=['last_login', 'last_login_ip'])
                
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token
                
                # Add custom claims
                access_token['user_id'] = user.id
                access_token['username'] = user.username
                access_token['kyc_status'] = user.kyc_status
                access_token['roles'] = [role.role.name for role in user.user_roles.filter(is_active=True)]
                
                # Log audit event
                AuditService.log_action(
                    user=user,
                    action_type='LOGIN',
                    target_model='User',
                    description=f"User logged in: {user.username}",
                    request=request,
                    target_id=str(user.id)
                )
                
                # Cache user data
                CacheService.cache_user_data(user)
                
                response_data = {
                    'access': str(access_token),
                    'refresh': str(refresh),
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'customer_id': user.customer_id,
                        'kyc_status': user.kyc_status,
                        'risk_profile': user.risk_profile,
                        'roles': [role.role.name for role in user.user_roles.filter(is_active=True)]
                    }
                }
                
                return Response(response_data, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return Response(
                {'error': 'Login failed. Please check your credentials.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """User profile endpoint"""
    
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        """Get current user"""
        return self.request.user
    
    def get(self, request, *args, **kwargs):
        """Get user profile"""
        try:
            # Try to get cached data first
            cached_data = CacheService.get_cached_user_data(request.user.id)
            
            if cached_data:
                return Response(cached_data, status=status.HTTP_200_OK)
            
            # Fallback to database
            serializer = self.get_serializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Profile retrieval error: {e}")
            return Response(
                {'error': 'Failed to retrieve profile.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def put(self, request, *args, **kwargs):
        """Update user profile"""
        try:
            serializer = UserUpdateSerializer(request.user, data=request.data, partial=True)
            
            if serializer.is_valid():
                with transaction.atomic():
                    # Log old values
                    old_values = {
                        'first_name': request.user.first_name,
                        'last_name': request.user.last_name,
                        'phone_number': request.user.phone_number
                    }
                    
                    # Update user
                    user = serializer.save()
                    
                    # Log audit event
                    AuditService.log_action(
                        user=user,
                        action_type='UPDATE',
                        target_model='User',
                        description=f"User profile updated: {user.username}",
                        request=request,
                        target_id=str(user.id),
                        old_values=old_values,
                        new_values=serializer.validated_data
                    )
                    
                    # Update cache
                    CacheService.cache_user_data(user)
                    
                    return Response(serializer.data, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Profile update error: {e}")
            return Response(
                {'error': 'Failed to update profile.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@extend_schema_view(
    post=extend_schema(
        tags=['KYC Documents'],
        summary='Upload KYC document',
        description='Upload and encrypt KYC documents (Government ID, Passport, etc.)',
        examples=[
            OpenApiExample(
                'KYC Upload Example',
                value={
                    'document_type': 'GOVERNMENT_ID',
                    'document_number': 'A1234567',
                    'document_file': '<file_data>'
                }
            )
        ]
    )
)
class KYCDocumentUploadView(generics.CreateAPIView):
    """KYC document upload endpoint"""
    
    serializer_class = KYCDocumentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def create(self, request, *args, **kwargs):
        """Upload KYC document"""
        try:
            # Check if user can upload documents
            if request.user.kyc_status not in ['INCOMPLETE', 'PENDING', 'REJECTED']:
                return Response(
                    {'error': 'KYC documents can only be uploaded for incomplete, pending, or rejected applications.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid():
                with transaction.atomic():
                    # Check for duplicate document type
                    document_type = serializer.validated_data['document_type']
                    existing_doc = KYCDocument.objects.filter(
                        user=request.user,
                        document_type=document_type,
                        verification_status='PENDING'
                    ).first()
                    
                    if existing_doc:
                        return Response(
                            {'error': f'{document_type} document already uploaded.'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    # Create document
                    kyc_document = serializer.save()
                    
                    # Process document synchronously (Celery disabled for now)
                    # process_kyc_document.delay(kyc_document.id)
                    
                    # Simple synchronous processing
                    kyc_document.verification_status = 'PENDING'
                    kyc_document.validation_score = 85  # Simulate validation score
                    kyc_document.save()
                    
                    # Update user KYC status from INCOMPLETE to PENDING when first document is uploaded
                    if request.user.kyc_status == 'INCOMPLETE':
                        request.user.kyc_status = 'PENDING'
                        request.user.save()
                    
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"KYC upload error: {e}")
            return Response(
                {'error': 'Failed to upload document.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class KYCDocumentListView(generics.ListAPIView):
    """List user's KYC documents"""
    
    serializer_class = KYCDocumentListSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get user's KYC documents"""
        return KYCDocument.objects.filter(user=self.request.user).order_by('-upload_date')


class PasswordChangeView(APIView):
    """Password change endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Change user password"""
        try:
            serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
            
            if serializer.is_valid():
                user = request.user
                new_password = serializer.validated_data['new_password']
                
                # Update password
                user.set_password(new_password)
                user.save()
                
                # Log audit event
                AuditService.log_action(
                    user=user,
                    action_type='PASSWORD_CHANGE',
                    target_model='User',
                    description=f"Password changed for user: {user.username}",
                    request=request,
                    target_id=str(user.id)
                )
                
                return Response(
                    {'message': 'Password changed successfully.'},
                    status=status.HTTP_200_OK
                )
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Password change error: {e}")
            return Response(
                {'error': 'Failed to change password.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# Admin Views
class AdminUserListView(generics.ListAPIView):
    """List all users (admin only)"""
    
    serializer_class = UserListSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get all users"""
        # Check if user is admin
        if not self.request.user.user_roles.filter(role__name='BANK_ADMIN', is_active=True).exists():
            return User.objects.none()
        
        return User.objects.all().order_by('-created_at')
    
    def list(self, request, *args, **kwargs):
        """List users with pagination"""
        try:
            queryset = self.get_queryset()
            
            # Pagination
            page = request.GET.get('page', 1)
            paginator = Paginator(queryset, 20)
            users = paginator.get_page(page)
            
            serializer = self.get_serializer(users, many=True)
            
            return Response({
                'count': paginator.count,
                'next': users.next_page_number() if users.has_next() else None,
                'previous': users.previous_page_number() if users.has_previous() else None,
                'results': serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Admin user list error: {e}")
            return Response(
                {'error': 'Failed to retrieve users.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminKYCDocumentListView(generics.ListAPIView):
    """List all KYC documents (admin only)"""
    
    serializer_class = AdminKYCDocumentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get all KYC documents"""
        # Check if user is admin
        if not self.request.user.user_roles.filter(role__name='BANK_ADMIN', is_active=True).exists():
            return KYCDocument.objects.none()
        
        return KYCDocument.objects.all().order_by('-upload_date')


class AdminKYCReviewView(APIView):
    """Admin KYC review endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, user_id):
        """Review user's KYC"""
        try:
            # Check if user is admin
            if not request.user.user_roles.filter(role__name='BANK_ADMIN', is_active=True).exists():
                return Response(
                    {'error': 'Admin access required.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Get user
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response(
                    {'error': 'User not found.'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Check if KYC is pending
            if user.kyc_status != 'PENDING':
                return Response(
                    {'error': 'KYC is not pending review.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            serializer = AdminKYCReviewSerializer(data=request.data)
            
            if serializer.is_valid():
                with transaction.atomic():
                    action = serializer.validated_data['action']
                    
                    # Update KYC status
                    if action == 'approve':
                        user.kyc_status = 'APPROVED'
                        user.is_account_verified = True
                        user.kyc_rejection_reason = None
                    else:
                        user.kyc_status = 'REJECTED'
                        user.kyc_rejection_reason = serializer.validated_data.get('rejection_reason', '')
                    
                    user.kyc_reviewed_by = request.user
                    user.kyc_reviewed_at = timezone.now()
                    user.save()
                    
                    # Update all KYC documents
                    KYCDocument.objects.filter(user=user).update(
                        verification_status='VERIFIED' if action == 'approve' else 'REJECTED',
                        verified_by=request.user,
                        verified_at=timezone.now(),
                        rejection_reason=serializer.validated_data.get('rejection_reason', '') if action == 'reject' else None
                    )
                    
                    # Log audit event
                    AuditService.log_action(
                        user=request.user,
                        action_type='KYC_APPROVE' if action == 'approve' else 'KYC_REJECT',
                        target_model='User',
                        description=f"KYC {action}d for user: {user.username}",
                        request=request,
                        target_id=str(user.id)
                    )
                    
                    # Send email notification (Celery disabled)
                    # send_kyc_approval_email.delay(user.id, action == 'approve')
                    
                    return Response({
                        'message': f'KYC {action}d successfully.',
                        'user': {
                            'id': user.id,
                            'username': user.username,
                            'kyc_status': user.kyc_status
                        }
                    }, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"KYC review error: {e}")
            return Response(
                {'error': 'Failed to review KYC.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminAuditLogView(generics.ListAPIView):
    """Admin audit log endpoint"""
    
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get audit logs"""
        # Check if user is admin or auditor
        user_roles = request.user.user_roles.filter(is_active=True).values_list('role__name', flat=True)
        if not any(role in ['BANK_ADMIN', 'AUDITOR'] for role in user_roles):
            return AuditLog.objects.none()
        
        return AuditLog.objects.all().order_by('-timestamp')


class AdminSecurityEventView(generics.ListAPIView):
    """Admin security events endpoint"""
    
    serializer_class = SecurityEventSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get security events"""
        # Check if user is admin or auditor
        user_roles = self.request.user.user_roles.filter(is_active=True).values_list('role__name', flat=True)
        if not any(role in ['BANK_ADMIN', 'AUDITOR'] for role in user_roles):
            return SecurityEvent.objects.none()
        
        return SecurityEvent.objects.all().order_by('-created_at')


class AdminNotificationView(generics.ListAPIView):
    """Admin notifications endpoint"""
    
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get admin notifications"""
        # Check if user is admin
        if not self.request.user.user_roles.filter(role__name='BANK_ADMIN', is_active=True).exists():
            return Notification.objects.none()
        
        return Notification.objects.all().order_by('-created_at')


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def dashboard_stats(request):
    """Get dashboard statistics (admin only)"""
    try:
        # Check if user is admin
        if not request.user.user_roles.filter(role__name='BANK_ADMIN', is_active=True).exists():
            return Response(
                {'error': 'Admin access required.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        from datetime import timedelta
        
        # Get statistics
        total_users = User.objects.count()
        pending_kyc = User.objects.filter(kyc_status='PENDING').count()
        approved_kyc = User.objects.filter(kyc_status='APPROVED').count()
        rejected_kyc = User.objects.filter(kyc_status='REJECTED').count()
        
        # Recent activity (last 24 hours)
        recent_registrations = User.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=1)
        ).count()
        
        recent_security_events = SecurityEvent.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=1)
        ).count()
        
        unread_notifications = Notification.objects.filter(is_read=False).count()
        
        stats = {
            'total_users': total_users,
            'pending_kyc': pending_kyc,
            'approved_kyc': approved_kyc,
            'rejected_kyc': rejected_kyc,
            'recent_registrations': recent_registrations,
            'recent_security_events': recent_security_events,
            'unread_notifications': unread_notifications
        }
        
        return Response(stats, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return Response(
            {'error': 'Failed to retrieve dashboard statistics.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
