import uuid
import hashlib
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.utils import timezone
from django.conf import settings


class User(AbstractUser):
    """Custom User model with banking-specific fields"""
    
    # Basic Information
    email = models.EmailField(unique=True)
    phone_number = models.CharField(
        max_length=15, 
        unique=True,
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$',
            message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
        )]
    )
    date_of_birth = models.DateField()
    
    # Encrypted Sensitive Data
    ssn_encrypted = models.TextField()
    address_encrypted = models.TextField()
    
    # Banking Information
    customer_id = models.CharField(max_length=20, unique=True, blank=True)
    kyc_status = models.CharField(
        max_length=20,
        choices=[
            ('INCOMPLETE', 'Incomplete - Documents Required'),
            ('PENDING', 'Pending Review'),
            ('APPROVED', 'Approved'),
            ('REJECTED', 'Rejected'),
            ('EXPIRED', 'Expired')
        ],
        default='INCOMPLETE'
    )
    risk_profile = models.CharField(
        max_length=10,
        choices=[
            ('LOW', 'Low Risk'),
            ('MEDIUM', 'Medium Risk'),
            ('HIGH', 'High Risk')
        ],
        default='LOW'
    )
    
    # Security Fields
    is_account_verified = models.BooleanField(default=False)
    two_factor_enabled = models.BooleanField(default=False)
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    # KYC Review Fields
    kyc_reviewed_by = models.ForeignKey(
        'self', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='kyc_reviews'
    )
    kyc_reviewed_at = models.DateTimeField(null=True, blank=True)
    kyc_rejection_reason = models.TextField(null=True, blank=True)
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'phone_number', 'date_of_birth']
    
    class Meta:
        db_table = 'auth_user'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['customer_id']),
            models.Index(fields=['kyc_status']),
            models.Index(fields=['created_at']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.customer_id:
            self.customer_id = self.generate_customer_id()
        super().save(*args, **kwargs)
    
    def generate_customer_id(self):
        """Generate unique customer ID"""
        return f"CUST{str(uuid.uuid4().hex[:10]).upper()}"
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until:
            return timezone.now() < self.account_locked_until
        return False
    
    def lock_account(self, duration_minutes=30):
        """Lock account for specified duration"""
        self.account_locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save(update_fields=['account_locked_until'])
    
    def unlock_account(self):
        """Unlock account and reset failed attempts"""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['account_locked_until', 'failed_login_attempts'])
    
    def increment_failed_login(self):
        """Increment failed login attempts"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.lock_account()
        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])
    
    def reset_failed_login(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.save(update_fields=['failed_login_attempts'])
    
    def __str__(self):
        return f"{self.username} ({self.customer_id})"


class Role(models.Model):
    """Role model for role-based access control"""
    
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    permissions = models.JSONField(default=list)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'auth_role'
        ordering = ['name']
    
    def __str__(self):
        return self.name


class UserRole(models.Model):
    """Many-to-many relationship between User and Role"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_roles')
    assigned_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='role_assignments'
    )
    assigned_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'auth_user_role'
        unique_together = ['user', 'role']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['role', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.role.name}"


class KYCDocument(models.Model):
    """KYC Document model for storing uploaded documents"""
    
    DOCUMENT_TYPE_CHOICES = [
        ('GOVERNMENT_ID', 'Government ID'),
        ('PASSPORT', 'Passport'),
        ('DRIVER_LICENSE', 'Driver License'),
        ('UTILITY_BILL', 'Utility Bill'),
        ('BANK_STATEMENT', 'Bank Statement'),
        ('OTHER', 'Other')
    ]
    
    VERIFICATION_STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('VERIFIED', 'Verified'),
        ('REJECTED', 'Rejected')
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='kyc_documents')
    document_type = models.CharField(max_length=50, choices=DOCUMENT_TYPE_CHOICES)
    document_number = models.CharField(max_length=100)
    document_file_path = models.CharField(max_length=500)
    file_hash = models.CharField(max_length=64)  # SHA-256 hash
    file_size = models.BigIntegerField()
    upload_date = models.DateTimeField(auto_now_add=True)
    verification_status = models.CharField(
        max_length=20,
        choices=VERIFICATION_STATUS_CHOICES,
        default='PENDING'
    )
    verified_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='verified_documents'
    )
    verified_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)
    ocr_text = models.TextField(null=True, blank=True)  # Extracted text from document
    validation_score = models.IntegerField(null=True, blank=True)  # 0-100 score
    
    class Meta:
        db_table = 'kyc_document'
        indexes = [
            models.Index(fields=['user', 'verification_status']),
            models.Index(fields=['document_type']),
            models.Index(fields=['upload_date']),
        ]
        ordering = ['-upload_date']
    
    def __str__(self):
        return f"{self.user.username} - {self.document_type}"


class AuditLog(models.Model):
    """Audit log for tracking all user actions"""
    
    ACTION_TYPE_CHOICES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('KYC_APPROVE', 'KYC Approve'),
        ('KYC_REJECT', 'KYC Reject'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('ROLE_ASSIGN', 'Role Assign'),
        ('DOCUMENT_UPLOAD', 'Document Upload'),
        ('ACCOUNT_LOCK', 'Account Lock'),
        ('ACCOUNT_UNLOCK', 'Account Unlock'),
    ]
    
    log_id = models.CharField(max_length=50, unique=True, default=uuid.uuid4)
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='audit_logs'
    )
    action_type = models.CharField(max_length=20, choices=ACTION_TYPE_CHOICES)
    target_model = models.CharField(max_length=50)
    target_id = models.CharField(max_length=50, null=True, blank=True)
    description = models.TextField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(null=True, blank=True)
    old_values = models.JSONField(null=True, blank=True)
    new_values = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'audit_log'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action_type']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"{self.action_type} - {self.user.username if self.user else 'System'}"


class RateLimit(models.Model):
    """Rate limiting model for tracking request limits"""
    
    identifier = models.CharField(max_length=100)  # IP or User ID
    endpoint = models.CharField(max_length=200)
    request_count = models.IntegerField(default=1)
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    is_blocked = models.BooleanField(default=False)
    block_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'rate_limit'
        unique_together = ['identifier', 'endpoint', 'window_start']
        indexes = [
            models.Index(fields=['identifier', 'endpoint']),
            models.Index(fields=['window_start', 'window_end']),
        ]
    
    def __str__(self):
        return f"{self.identifier} - {self.endpoint}"


class SecurityEvent(models.Model):
    """Security event model for tracking security-related events"""
    
    EVENT_TYPE_CHOICES = [
        ('FAILED_LOGIN', 'Failed Login'),
        ('ACCOUNT_LOCKED', 'Account Locked'),
        ('SUSPICIOUS_ACTIVITY', 'Suspicious Activity'),
        ('RATE_LIMIT_EXCEEDED', 'Rate Limit Exceeded'),
        ('UNAUTHORIZED_ACCESS', 'Unauthorized Access'),
        ('PASSWORD_RESET', 'Password Reset'),
        ('2FA_ENABLED', '2FA Enabled'),
        ('2FA_DISABLED', '2FA Disabled'),
        ('DATA_CORRUPTION', 'Data Corruption'),
        ('MALICIOUS_FILE', 'Malicious File Upload'),
    ]
    
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical')
    ]
    
    event_type = models.CharField(max_length=50, choices=EVENT_TYPE_CHOICES)
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='security_events'
    )
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(null=True, blank=True)
    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default='MEDIUM'
    )
    description = models.TextField()
    metadata = models.JSONField(null=True, blank=True)
    resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='resolved_events'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'security_event'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'event_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['resolved']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.user.username if self.user else 'System'}"


class Notification(models.Model):
    """Notification model for admin notifications"""
    
    NOTIFICATION_TYPE_CHOICES = [
        ('NEW_REGISTRATION', 'New Registration'),
        ('KYC_UPLOAD', 'KYC Document Upload'),
        ('KYC_READY_REVIEW', 'KYC Ready for Review'),
        ('SECURITY_ALERT', 'Security Alert'),
        ('SYSTEM_ALERT', 'System Alert'),
    ]
    
    PRIORITY_CHOICES = [
        ('LOW', 'Low'),
        ('NORMAL', 'Normal'),
        ('HIGH', 'High'),
        ('URGENT', 'Urgent')
    ]
    
    notification_type = models.CharField(max_length=50, choices=NOTIFICATION_TYPE_CHOICES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='NORMAL')
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        related_name='notifications'
    )
    metadata = models.JSONField(null=True, blank=True)
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'notification'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['notification_type']),
            models.Index(fields=['priority']),
            models.Index(fields=['is_read']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.notification_type} - {self.title}"
