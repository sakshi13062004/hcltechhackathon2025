"""
URL configuration for registration app
"""
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

app_name = 'registration'

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', views.UserRegistrationView.as_view(), name='user-register'),
    path('auth/login/', views.UserLoginView.as_view(), name='user-login'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    
    # User profile endpoints
    path('profile/', views.UserProfileView.as_view(), name='user-profile'),
    path('profile/change-password/', views.PasswordChangeView.as_view(), name='change-password'),
    
    # KYC endpoints
    path('kyc/upload/', views.KYCDocumentUploadView.as_view(), name='kyc-upload'),
    path('kyc/documents/', views.KYCDocumentListView.as_view(), name='kyc-documents'),
    
    # Admin endpoints
    path('admin/users/', views.AdminUserListView.as_view(), name='admin-users'),
    path('admin/kyc/documents/', views.AdminKYCDocumentListView.as_view(), name='admin-kyc-documents'),
    path('admin/kyc/review/<int:user_id>/', views.AdminKYCReviewView.as_view(), name='admin-kyc-review'),
    path('admin/audit-logs/', views.AdminAuditLogView.as_view(), name='admin-audit-logs'),
    path('admin/security-events/', views.AdminSecurityEventView.as_view(), name='admin-security-events'),
    path('admin/notifications/', views.AdminNotificationView.as_view(), name='admin-notifications'),
    path('admin/dashboard/stats/', views.dashboard_stats, name='admin-dashboard-stats'),
]
