from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from .models import (
    User, Role, UserRole, KYCDocument, AuditLog, 
    RateLimit, SecurityEvent, Notification
)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for User model"""
    
    list_display = [
        'username', 'email', 'customer_id', 'kyc_status', 
        'risk_profile', 'is_account_verified', 'created_at'
    ]
    list_filter = [
        'kyc_status', 'risk_profile', 'is_account_verified', 
        'is_active', 'created_at'
    ]
    search_fields = ['username', 'email', 'customer_id', 'first_name', 'last_name']
    readonly_fields = ['customer_id', 'created_at', 'updated_at', 'last_login']
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {
            'fields': ('first_name', 'last_name', 'email', 'phone_number', 'date_of_birth')
        }),
        ('Banking Info', {
            'fields': ('customer_id', 'kyc_status', 'risk_profile', 'is_account_verified')
        }),
        ('Security', {
            'fields': ('two_factor_enabled', 'failed_login_attempts', 'account_locked_until', 'last_login_ip')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2'),
        }),
    )


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    """Admin configuration for Role model"""
    
    list_display = ['name', 'description', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'description']


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    """Admin configuration for UserRole model"""
    
    list_display = ['user', 'role', 'assigned_by', 'assigned_at', 'is_active']
    list_filter = ['role', 'is_active', 'assigned_at']
    search_fields = ['user__username', 'role__name']


@admin.register(KYCDocument)
class KYCDocumentAdmin(admin.ModelAdmin):
    """Admin configuration for KYCDocument model"""
    
    list_display = [
        'user', 'document_type', 'verification_status', 
        'validation_score', 'upload_date'
    ]
    list_filter = [
        'document_type', 'verification_status', 'upload_date'
    ]
    search_fields = ['user__username', 'document_number']
    readonly_fields = ['file_hash', 'upload_date', 'verified_at']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'verified_by')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin configuration for AuditLog model"""
    
    list_display = [
        'action_type', 'user', 'target_model', 'ip_address', 'timestamp'
    ]
    list_filter = ['action_type', 'target_model', 'timestamp']
    search_fields = ['user__username', 'description', 'ip_address']
    readonly_fields = ['log_id', 'timestamp']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    """Admin configuration for SecurityEvent model"""
    
    list_display = [
        'event_type', 'user', 'severity', 'resolved', 'created_at'
    ]
    list_filter = ['event_type', 'severity', 'resolved', 'created_at']
    search_fields = ['user__username', 'description', 'ip_address']
    readonly_fields = ['created_at']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'resolved_by')


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    """Admin configuration for Notification model"""
    
    list_display = [
        'notification_type', 'title', 'priority', 'is_read', 'created_at'
    ]
    list_filter = ['notification_type', 'priority', 'is_read', 'created_at']
    search_fields = ['title', 'message']
    readonly_fields = ['created_at', 'read_at']


@admin.register(RateLimit)
class RateLimitAdmin(admin.ModelAdmin):
    """Admin configuration for RateLimit model"""
    
    list_display = [
        'identifier', 'endpoint', 'request_count', 'is_blocked', 'created_at'
    ]
    list_filter = ['endpoint', 'is_blocked', 'created_at']
    search_fields = ['identifier', 'endpoint']
    readonly_fields = ['created_at']


# Customize admin site
admin.site.site_header = "SmartBank Administration"
admin.site.site_title = "SmartBank Admin"
admin.site.index_title = "Welcome to SmartBank Administration"
