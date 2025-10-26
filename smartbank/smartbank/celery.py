"""
Celery configuration for smartbank project
"""
import os
from celery import Celery
from celery.signals import worker_ready, worker_shutdown

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartbank.settings')

# Create Celery app with explicit configuration
app = Celery('smartbank')

# Configure Celery with explicit settings
app.conf.update(
    # Basic configuration
    broker_url='redis://localhost:6379/0',
    result_backend='redis://localhost:6379/0',
    
    # Task configuration
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    result_accept_content=['json'],
    
    # Timezone configuration
    timezone='UTC',
    enable_utc=True,
    
    # Worker configuration
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    worker_disable_rate_limits=True,
    worker_hijack_root_logger=False,
    worker_log_color=False,
    
    # Task execution configuration
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=60,  # 1 minute
    task_always_eager=False,
    task_eager_propagates=True,
    task_ignore_result=False,
    result_expires=3600,  # 1 hour
    
    # Beat scheduler configuration
    beat_scheduler='django_celery_beat.schedulers:DatabaseScheduler',
    beat_schedule={
        'cleanup-expired-data': {
            'task': 'registration.tasks.cleanup_expired_data',
            'schedule': 3600.0,  # Run every hour
        },
    },
    
    # Security configuration
    worker_send_task_events=True,
    task_send_sent_event=True,
    
    # Error handling
    task_acks_late=True,
    worker_reject_on_worker_lost=True,
)

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Signal handlers for better error handling
@worker_ready.connect
def worker_ready_handler(sender=None, **kwargs):
    """Handle worker ready signal"""
    print("Celery worker is ready!")

@worker_shutdown.connect
def worker_shutdown_handler(sender=None, **kwargs):
    """Handle worker shutdown signal"""
    print("Celery worker is shutting down!")

@app.task(bind=True)
def debug_task(self):
    """Debug task to test Celery functionality"""
    print(f'Request: {self.request!r}')
    return f'Debug task executed: {self.request.id}'
