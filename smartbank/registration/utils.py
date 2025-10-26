"""
Utility functions for registration app
"""
import re
import hashlib
import logging
from datetime import datetime, date
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.core.cache import cache
from django.db import transaction
from rest_framework.response import Response
from rest_framework import status
from .models import User, AuditLog, SecurityEvent

logger = logging.getLogger(__name__)


class EncryptionService:
    """Service for handling data encryption and decryption"""
    
    def __init__(self):
        self.ssn_key = settings.ENCRYPTION_KEY_SSN.encode()
        self.address_key = settings.ENCRYPTION_KEY_ADDRESS.encode()
        self.document_key = settings.ENCRYPTION_KEY_DOCUMENTS.encode()
    
    def encrypt_ssn(self, ssn: str) -> str:
        """Encrypt SSN using Fernet encryption"""
        try:
            # Clean SSN (remove dashes and spaces)
            clean_ssn = re.sub(r'[-\s]', '', ssn)
            
            # Validate SSN format
            if not re.match(r'^\d{9}$', clean_ssn):
                raise ValidationError("Invalid SSN format")
            
            # Check for invalid SSNs
            invalid_ssns = ['000000000', '123456789', '111111111', '999999999']
            if clean_ssn in invalid_ssns:
                raise ValidationError("Invalid SSN number")
            
            f = Fernet(self.ssn_key)
            encrypted_data = f.encrypt(clean_ssn.encode())
            return encrypted_data.decode()
        except Exception as e:
            logger.error(f"SSN encryption failed: {e}")
            raise ValidationError("Failed to encrypt SSN")
    
    def decrypt_ssn(self, encrypted_ssn: str) -> str:
        """Decrypt SSN"""
        try:
            f = Fernet(self.ssn_key)
            decrypted_data = f.decrypt(encrypted_ssn.encode())
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"SSN decryption failed: {e}")
            raise ValidationError("Failed to decrypt SSN")
    
    def check_duplicate_ssn(self, ssn: str) -> bool:
        """Check if SSN already exists in the database"""
        try:
            # Clean SSN (remove dashes and spaces)
            clean_ssn = re.sub(r'[-\s]', '', ssn)
            
            # Encrypt the SSN to compare with stored encrypted SSNs
            encrypted_ssn = self.encrypt_ssn(clean_ssn)
            
            # Check if any user has this encrypted SSN
            return User.objects.filter(ssn_encrypted=encrypted_ssn).exists()
            
        except Exception as e:
            logger.error(f"SSN duplicate check failed: {e}")
            # If there's an error, assume it's not a duplicate to avoid blocking valid registrations
            return False
    
    def encrypt_address(self, address: str) -> str:
        """Encrypt address"""
        try:
            f = Fernet(self.address_key)
            encrypted_data = f.encrypt(address.encode())
            return encrypted_data.decode()
        except Exception as e:
            logger.error(f"Address encryption failed: {e}")
            raise ValidationError("Failed to encrypt address")
    
    def decrypt_address(self, encrypted_address: str) -> str:
        """Decrypt address"""
        try:
            f = Fernet(self.address_key)
            decrypted_data = f.decrypt(encrypted_address.encode())
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Address decryption failed: {e}")
            raise ValidationError("Failed to decrypt address")
    
    def encrypt_document(self, file_content: bytes) -> bytes:
        """Encrypt document file"""
        try:
            f = Fernet(self.document_key)
            return f.encrypt(file_content)
        except Exception as e:
            logger.error(f"Document encryption failed: {e}")
            raise ValidationError("Failed to encrypt document")


class ValidationService:
    """Service for data validation"""
    
    @staticmethod
    def validate_age(date_of_birth: date) -> bool:
        """Validate user age (must be 18+)"""
        today = date.today()
        age = today.year - date_of_birth.year
        
        # Handle leap year edge case
        if today.month < date_of_birth.month or \
           (today.month == date_of_birth.month and today.day < date_of_birth.day):
            age -= 1
        
        if age < 18:
            raise ValidationError("Must be at least 18 years old")
        
        if age > 120:
            raise ValidationError("Invalid birth date")
        
        if date_of_birth > today:
            raise ValidationError("Birth date cannot be in the future")
        
        return True
    
    @staticmethod
    def validate_phone_number(phone: str) -> bool:
        """Validate phone number format"""
        pattern = r'^\+?1?\d{9,15}$'
        if not re.match(pattern, phone):
            raise ValidationError("Invalid phone number format")
        return True
    
    @staticmethod
    def validate_password_strength(password: str) -> bool:
        """Validate password strength"""
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one number")
        
        return True
    
    @staticmethod
    def validate_file_type(file_name: str) -> bool:
        """Validate uploaded file type"""
        allowed_extensions = settings.ALLOWED_FILE_TYPES
        file_extension = file_name.split('.')[-1].lower()
        
        if file_extension not in allowed_extensions:
            raise ValidationError(f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}")
        
        return True
    
    @staticmethod
    def validate_file_size(file_size: int) -> bool:
        """Validate uploaded file size"""
        max_size = settings.MAX_UPLOAD_SIZE
        
        if file_size > max_size:
            raise ValidationError(f"File too large. Maximum size is {max_size // (1024*1024)}MB")
        
        return True


class SecurityService:
    """Service for security-related operations"""
    
    @staticmethod
    def get_client_ip(request) -> str:
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    @staticmethod
    def get_user_agent(request) -> str:
        """Get user agent from request"""
        return request.META.get('HTTP_USER_AGENT', '')
    
    @staticmethod
    def calculate_file_hash(file_content: bytes) -> str:
        """Calculate SHA-256 hash of file content"""
        return hashlib.sha256(file_content).hexdigest()
    
    @staticmethod
    def check_duplicate_ssn(ssn: str) -> bool:
        """Check if SSN already exists in database"""
        encryption_service = EncryptionService()
        
        # Get all users and check their encrypted SSNs
        users = User.objects.all()
        for user in users:
            try:
                decrypted_ssn = encryption_service.decrypt_ssn(user.ssn_encrypted)
                if decrypted_ssn == ssn:
                    return True
            except:
                continue
        
        return False


class AuditService:
    """Service for audit logging"""
    
    @staticmethod
    def log_action(
        user: Optional[User],
        action_type: str,
        target_model: str,
        description: str,
        request=None,
        target_id: Optional[str] = None,
        old_values: Optional[Dict] = None,
        new_values: Optional[Dict] = None
    ) -> AuditLog:
        """Log user action for audit trail"""
        try:
            ip_address = SecurityService.get_client_ip(request) if request else '127.0.0.1'
            user_agent = SecurityService.get_user_agent(request) if request else ''
            
            audit_log = AuditLog.objects.create(
                user=user,
                action_type=action_type,
                target_model=target_model,
                target_id=target_id,
                description=description,
                ip_address=ip_address,
                user_agent=user_agent,
                old_values=old_values,
                new_values=new_values
            )
            
            logger.info(f"Audit log created: {action_type} - {description}")
            return audit_log
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
            raise
    
    @staticmethod
    def log_security_event(
        event_type: str,
        description: str,
        user: Optional[User] = None,
        request=None,
        severity: str = 'MEDIUM',
        metadata: Optional[Dict] = None
    ) -> SecurityEvent:
        """Log security event"""
        try:
            ip_address = SecurityService.get_client_ip(request) if request else '127.0.0.1'
            user_agent = SecurityService.get_user_agent(request) if request else ''
            
            security_event = SecurityEvent.objects.create(
                event_type=event_type,
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                severity=severity,
                description=description,
                metadata=metadata
            )
            
            logger.warning(f"Security event logged: {event_type} - {description}")
            return security_event
            
        except Exception as e:
            logger.error(f"Failed to create security event: {e}")
            raise


class CacheService:
    """Service for Redis caching operations"""
    
    @staticmethod
    def cache_user_data(user: User, ttl: int = 3600) -> None:
        """Cache user data in Redis"""
        try:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'customer_id': user.customer_id,
                'kyc_status': user.kyc_status,
                'risk_profile': user.risk_profile,
                'is_account_verified': user.is_account_verified,
                'roles': [role.role.name for role in user.user_roles.filter(is_active=True)]
            }
            
            cache.set(f"user:{user.id}", user_data, ttl)
            logger.debug(f"User data cached for user {user.id}")
            
        except Exception as e:
            logger.error(f"Failed to cache user data: {e}")
    
    @staticmethod
    def get_cached_user_data(user_id: int) -> Optional[Dict]:
        """Get cached user data from Redis"""
        try:
            return cache.get(f"user:{user_id}")
        except Exception as e:
            logger.error(f"Failed to get cached user data: {e}")
            return None
    
    @staticmethod
    def invalidate_user_cache(user_id: int) -> None:
        """Invalidate user cache"""
        try:
            cache.delete(f"user:{user_id}")
            logger.debug(f"User cache invalidated for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to invalidate user cache: {e}")


class RateLimitService:
    """Service for rate limiting operations"""
    
    @staticmethod
    def check_rate_limit(identifier: str, endpoint: str, limit_config: Dict) -> tuple[bool, str]:
        """Check if request is within rate limit"""
        try:
            key = f"rate_limit:{identifier}:{endpoint}"
            current_time = timezone.now().timestamp()
            window_start = current_time - limit_config['window']
            
            # Get current request count from Redis
            current_count = cache.get(key, 0)
            
            if current_count >= limit_config['requests']:
                # Check if user is blocked
                block_key = f"block:{identifier}:{endpoint}"
                block_until = cache.get(block_key)
                
                if block_until and current_time < block_until:
                    return False, "Rate limit exceeded. Account temporarily blocked."
                
                # Apply lockout if configured
                if limit_config.get('lockout', 0) > 0:
                    cache.set(block_key, current_time + limit_config['lockout'], limit_config['lockout'])
                
                return False, f"Rate limit exceeded. Maximum {limit_config['requests']} requests per {limit_config['window']} seconds."
            
            # Increment counter
            cache.set(key, current_count + 1, limit_config['window'])
            
            remaining = limit_config['requests'] - current_count - 1
            return True, f"{remaining} requests remaining"
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # Allow request if rate limiting fails
            return True, "Rate limit check failed, allowing request"
    
    @staticmethod
    def get_rate_limit_info(identifier: str, endpoint: str, limit_config: Dict) -> Dict:
        """Get rate limit information for response headers"""
        try:
            key = f"rate_limit:{identifier}:{endpoint}"
            current_count = cache.get(key, 0)
            remaining = max(0, limit_config['requests'] - current_count)
            
            return {
                'limit': limit_config['requests'],
                'remaining': remaining,
                'reset_time': int(timezone.now().timestamp() + limit_config['window'])
            }
        except Exception as e:
            logger.error(f"Failed to get rate limit info: {e}")
            return {
                'limit': limit_config['requests'],
                'remaining': limit_config['requests'],
                'reset_time': int(timezone.now().timestamp() + limit_config['window'])
            }


def custom_exception_handler(exc, context):
    """Custom exception handler for DRF"""
    from rest_framework.views import exception_handler
    from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, ValidationError
    
    response = exception_handler(exc, context)
    
    if response is not None:
        # Handle authentication errors properly
        if isinstance(exc, (AuthenticationFailed, NotAuthenticated)):
            custom_response_data = {
                'error': True,
                'message': 'Authentication failed',
                'details': response.data
            }
            response.data = custom_response_data
            # Keep the original status code (401) for auth errors
        elif isinstance(exc, ValidationError):
            # For validation errors, return the original data without wrapping
            # This preserves the correct 400 status code and error format
            return response
        else:
            custom_response_data = {
                'error': True,
                'message': 'An error occurred',
                'details': response.data
            }
            response.data = custom_response_data
        
        # Log the exception
        logger.error(f"API Exception: {exc} - {context}")
    
    return response


def get_or_create_roles():
    """Create default roles if they don't exist"""
    from .models import Role
    
    default_roles = [
        {
            'name': 'CUSTOMER',
            'description': 'Bank Customer',
            'permissions': [
                'view_own_profile',
                'update_own_profile',
                'upload_kyc_documents',
                'view_own_kyc_status'
            ]
        },
        {
            'name': 'BANK_ADMIN',
            'description': 'Bank Administrator',
            'permissions': [
                'view_all_users',
                'approve_kyc',
                'reject_kyc',
                'view_audit_logs',
                'manage_users',
                'view_security_events'
            ]
        },
        {
            'name': 'AUDITOR',
            'description': 'System Auditor',
            'permissions': [
                'view_audit_logs',
                'view_security_events',
                'view_system_reports'
            ]
        }
    ]
    
    for role_data in default_roles:
        role, created = Role.objects.get_or_create(
            name=role_data['name'],
            defaults={
                'description': role_data['description'],
                'permissions': role_data['permissions']
            }
        )
        if created:
            logger.info(f"Created role: {role.name}")


def assign_default_role(user: User):
    """Assign default customer role to new user"""
    from .models import Role, UserRole
    
    try:
        customer_role = Role.objects.get(name='CUSTOMER')
        UserRole.objects.get_or_create(
            user=user,
            role=customer_role,
            defaults={'is_active': True}
        )
        logger.info(f"Assigned CUSTOMER role to user {user.username}")
    except Role.DoesNotExist:
        logger.error("CUSTOMER role not found. Please run get_or_create_roles() first.")


def send_admin_notification(notification_type: str, title: str, message: str, 
                          user: Optional[User] = None, priority: str = 'NORMAL'):
    """Send notification to admin users"""
    from .models import Notification, User, UserRole, Role
    
    try:
        # Get admin users
        admin_role = Role.objects.get(name='BANK_ADMIN')
        admin_users = User.objects.filter(
            user_roles__role=admin_role,
            user_roles__is_active=True
        )
        
        # Create notification for each admin
        for admin in admin_users:
            Notification.objects.create(
                notification_type=notification_type,
                title=title,
                message=message,
                priority=priority,
                user=user
            )
        
        logger.info(f"Admin notification sent: {notification_type}")
        
    except Exception as e:
        logger.error(f"Failed to send admin notification: {e}")


def validate_kyc_completeness(user: User) -> bool:
    """Validate if user has completed all required KYC documents"""
    required_documents = ['GOVERNMENT_ID', 'UTILITY_BILL']
    
    uploaded_types = user.kyc_documents.filter(
        verification_status='PENDING'
    ).values_list('document_type', flat=True)
    
    return all(doc_type in uploaded_types for doc_type in required_documents)
