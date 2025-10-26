"""
Celery tasks for registration app
"""
import logging
from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone
from django.db import transaction
from .models import User, KYCDocument, Notification
from .utils import send_admin_notification, validate_kyc_completeness

logger = logging.getLogger(__name__)


@shared_task
def test_celery_task():
    """Simple test task to verify Celery is working"""
    logger.info("Celery test task executed successfully")
    return "Celery is working!"


@shared_task(bind=True, max_retries=3)
def process_kyc_document(self, document_id):
    """Process uploaded KYC document"""
    try:
        kyc_doc = KYCDocument.objects.get(id=document_id)
        
        # Update document status
        kyc_doc.verification_status = 'PENDING'
        kyc_doc.save()
        
        # Simulate document processing (OCR, validation, etc.)
        # In a real implementation, this would involve:
        # - OCR text extraction
        # - Document validation
        # - Fraud detection
        # - Risk assessment
        
        # Simulate processing time
        import time
        time.sleep(2)
        
        # Set validation score (simulated)
        kyc_doc.validation_score = 85  # Simulated score
        kyc_doc.save()
        
        # Check if all required documents are uploaded
        if validate_kyc_completeness(kyc_doc.user):
            # Notify admin that KYC is ready for review
            notify_admin_kyc_ready.delay(kyc_doc.user.id)
        
        logger.info(f"KYC document {document_id} processed successfully")
        return f"Document {document_id} processed"
        
    except KYCDocument.DoesNotExist:
        logger.error(f"KYC document {document_id} not found")
        return f"Document {document_id} not found"
    except Exception as exc:
        logger.error(f"Error processing KYC document {document_id}: {exc}")
        # Retry the task
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@shared_task
def notify_admin_new_registration(user_id):
    """Notify admin of new user registration"""
    try:
        user = User.objects.get(id=user_id)
        
        # Send admin notification
        send_admin_notification(
            notification_type='NEW_REGISTRATION',
            title='New User Registration',
            message=f'New user {user.username} ({user.customer_id}) has registered and needs KYC review.',
            user=user,
            priority='HIGH'
        )
        
        # Send email notification to admins
        send_registration_email.delay(user_id)
        
        logger.info(f"Admin notification sent for new registration: {user.username}")
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} not found for registration notification")
    except Exception as e:
        logger.error(f"Error sending registration notification: {e}")


@shared_task
def notify_admin_kyc_ready(user_id):
    """Notify admin that KYC is ready for review"""
    try:
        user = User.objects.get(id=user_id)
        
        # Send admin notification
        send_admin_notification(
            notification_type='KYC_READY_REVIEW',
            title='KYC Ready for Review',
            message=f'User {user.username} ({user.customer_id}) has completed KYC document upload and is ready for review.',
            user=user,
            priority='HIGH'
        )
        
        logger.info(f"Admin notification sent for KYC ready: {user.username}")
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} not found for KYC ready notification")
    except Exception as e:
        logger.error(f"Error sending KYC ready notification: {e}")


@shared_task
def send_registration_email(user_id):
    """Send email notification to admins about new registration"""
    try:
        user = User.objects.get(id=user_id)
        
        # Get admin emails
        admin_emails = get_admin_emails()
        
        if admin_emails:
            subject = f'New User Registration - {user.username}'
            message = f'''
            A new user has registered and needs KYC review:
            
            Username: {user.username}
            Customer ID: {user.customer_id}
            Email: {user.email}
            Registration Date: {user.created_at}
            
            Please review the KYC documents in the admin panel.
            '''
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                fail_silently=False,
            )
            
            logger.info(f"Registration email sent to admins for user: {user.username}")
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} not found for email notification")
    except Exception as e:
        logger.error(f"Error sending registration email: {e}")


@shared_task
def send_kyc_approval_email(user_id, approved=True):
    """Send email to user about KYC approval/rejection"""
    try:
        user = User.objects.get(id=user_id)
        
        if approved:
            subject = 'KYC Verification Approved'
            message = f'''
            Dear {user.first_name},
            
            Your KYC verification has been approved. Your account is now fully activated.
            
            You can now:
            - Create bank accounts
            - Perform transactions
            - Access all banking features
            
            Thank you for choosing our bank.
            '''
        else:
            subject = 'KYC Verification Rejected'
            message = f'''
            Dear {user.first_name},
            
            Your KYC verification has been rejected. Please contact our support team for more information.
            
            You can re-upload your documents or contact us for assistance.
            
            Thank you.
            '''
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        
        logger.info(f"KYC {approved and 'approval' or 'rejection'} email sent to user: {user.username}")
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} not found for KYC email notification")
    except Exception as e:
        logger.error(f"Error sending KYC email: {e}")


@shared_task
def cleanup_expired_data():
    """Cleanup expired rate limit data and old notifications"""
    try:
        from django.core.cache import cache
        from .models import RateLimit, Notification
        
        # Clean expired rate limit data
        expired_rate_limits = RateLimit.objects.filter(
            window_end__lt=timezone.now()
        )
        expired_count = expired_rate_limits.count()
        expired_rate_limits.delete()
        
        # Clean old notifications (older than 30 days)
        from datetime import timedelta
        cutoff_date = timezone.now() - timedelta(days=30)
        old_notifications = Notification.objects.filter(
            created_at__lt=cutoff_date,
            is_read=True
        )
        old_notifications_count = old_notifications.count()
        old_notifications.delete()
        
        # Clean Redis cache
        try:
            # Clean expired rate limit keys
            cache.delete_many(cache.keys("rate_limit:*"))
            cache.delete_many(cache.keys("block:*"))
        except Exception as e:
            logger.warning(f"Error cleaning Redis cache: {e}")
        
        logger.info(f"Cleanup completed: {expired_count} rate limits, {old_notifications_count} notifications")
        
    except Exception as e:
        logger.error(f"Error in cleanup task: {e}")


@shared_task
def generate_daily_reports():
    """Generate daily reports for admins"""
    try:
        from datetime import timedelta
        from django.db.models import Count
        
        # Get yesterday's date
        yesterday = timezone.now().date() - timedelta(days=1)
        
        # Count new registrations
        new_registrations = User.objects.filter(
            created_at__date=yesterday
        ).count()
        
        # Count KYC approvals/rejections
        kyc_approvals = User.objects.filter(
            kyc_reviewed_at__date=yesterday,
            kyc_status='APPROVED'
        ).count()
        
        kyc_rejections = User.objects.filter(
            kyc_reviewed_at__date=yesterday,
            kyc_status='REJECTED'
        ).count()
        
        # Count security events
        security_events = SecurityEvent.objects.filter(
            created_at__date=yesterday
        ).count()
        
        # Create report
        report_data = {
            'date': yesterday,
            'new_registrations': new_registrations,
            'kyc_approvals': kyc_approvals,
            'kyc_rejections': kyc_rejections,
            'security_events': security_events
        }
        
        # Send report to admins
        send_daily_report_email.delay(report_data)
        
        logger.info(f"Daily report generated for {yesterday}")
        
    except Exception as e:
        logger.error(f"Error generating daily report: {e}")


@shared_task
def send_daily_report_email(report_data):
    """Send daily report email to admins"""
    try:
        admin_emails = get_admin_emails()
        
        if admin_emails:
            subject = f'Daily Report - {report_data["date"]}'
            message = f'''
            Daily Banking System Report - {report_data["date"]}
            
            New Registrations: {report_data["new_registrations"]}
            KYC Approvals: {report_data["kyc_approvals"]}
            KYC Rejections: {report_data["kyc_rejections"]}
            Security Events: {report_data["security_events"]}
            
            Please review the admin panel for detailed information.
            '''
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                fail_silently=False,
            )
            
            logger.info(f"Daily report email sent for {report_data['date']}")
        
    except Exception as e:
        logger.error(f"Error sending daily report email: {e}")


@shared_task
def monitor_system_health():
    """Monitor system health and send alerts if needed"""
    try:
        from django.db import connection
        from django.core.cache import cache
        
        health_issues = []
        
        # Check database connection
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
        except Exception as e:
            health_issues.append(f"Database connection issue: {e}")
        
        # Check Redis connection
        try:
            cache.set('health_check', 'ok', 10)
            if cache.get('health_check') != 'ok':
                health_issues.append("Redis connection issue")
        except Exception as e:
            health_issues.append(f"Redis connection issue: {e}")
        
        # Check for high number of pending KYC documents
        pending_kyc = KYCDocument.objects.filter(
            verification_status='PENDING'
        ).count()
        
        if pending_kyc > 100:  # Threshold for alert
            health_issues.append(f"High number of pending KYC documents: {pending_kyc}")
        
        # Check for high number of security events
        from datetime import timedelta
        recent_security_events = SecurityEvent.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        if recent_security_events > 50:  # Threshold for alert
            health_issues.append(f"High number of security events: {recent_security_events}")
        
        # Send alert if issues found
        if health_issues:
            send_system_health_alert.delay(health_issues)
        
        logger.info(f"System health check completed. Issues: {len(health_issues)}")
        
    except Exception as e:
        logger.error(f"Error in system health monitoring: {e}")


@shared_task
def send_system_health_alert(health_issues):
    """Send system health alert to admins"""
    try:
        admin_emails = get_admin_emails()
        
        if admin_emails:
            subject = 'System Health Alert'
            message = f'''
            System Health Alert - {timezone.now()}
            
            The following issues have been detected:
            
            {chr(10).join(f"- {issue}" for issue in health_issues)}
            
            Please investigate these issues immediately.
            '''
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                fail_silently=False,
            )
            
            logger.warning(f"System health alert sent: {health_issues}")
        
    except Exception as e:
        logger.error(f"Error sending system health alert: {e}")


def get_admin_emails():
    """Get list of admin email addresses"""
    try:
        from .models import User, UserRole, Role
        
        admin_role = Role.objects.get(name='BANK_ADMIN')
        admin_users = User.objects.filter(
            user_roles__role=admin_role,
            user_roles__is_active=True
        )
        
        return [user.email for user in admin_users if user.email]
        
    except Exception as e:
        logger.error(f"Error getting admin emails: {e}")
        return []
