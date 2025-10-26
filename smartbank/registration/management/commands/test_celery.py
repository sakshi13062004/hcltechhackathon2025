"""
Django management command to test Celery functionality
"""
from django.core.management.base import BaseCommand
from registration.tasks import test_celery_task

class Command(BaseCommand):
    help = 'Test Celery functionality'

    def handle(self, *args, **options):
        self.stdout.write('Testing Celery...')
        
        try:
            # Submit a test task
            result = test_celery_task.delay()
            self.stdout.write(f'Task submitted: {result.id}')
            
            # Wait for result
            task_result = result.get(timeout=10)
            self.stdout.write(
                self.style.SUCCESS(f'✅ Celery is working! Result: {task_result}')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Celery test failed: {e}')
            )
