"""
Django management command to check Celery health
"""
from django.core.management.base import BaseCommand
from django.conf import settings
import redis
import time

class Command(BaseCommand):
    help = 'Check Celery health and configuration'

    def handle(self, *args, **options):
        self.stdout.write('🔍 Checking Celery health...')
        
        # Check Redis connection
        try:
            r = redis.Redis(host='localhost', port=6379, db=0)
            r.ping()
            self.stdout.write(
                self.style.SUCCESS('✅ Redis connection: OK')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Redis connection failed: {e}')
            )
            return
        
        # Check Celery configuration
        try:
            from smartbank.celery import app
            self.stdout.write(
                self.style.SUCCESS('✅ Celery app: OK')
            )
            
            # Check broker URL
            broker_url = app.conf.broker_url
            self.stdout.write(f'📡 Broker URL: {broker_url}')
            
            # Check result backend
            result_backend = app.conf.result_backend
            self.stdout.write(f'💾 Result Backend: {result_backend}')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Celery configuration error: {e}')
            )
            return
        
        # Check registered tasks
        try:
            from registration.tasks import test_celery_task
            self.stdout.write(
                self.style.SUCCESS('✅ Tasks registration: OK')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Task registration error: {e}')
            )
        
        # Test task execution
        try:
            self.stdout.write('🧪 Testing task execution...')
            result = test_celery_task.delay()
            
            # Wait for result with timeout
            try:
                task_result = result.get(timeout=10)
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Task execution: OK - {task_result}')
                )
            except Exception as e:
                self.stdout.write(
                    self.style.WARNING(f'⚠️  Task execution timeout: {e}')
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Task execution error: {e}')
            )
        
        # Check Celery worker status
        try:
            from celery import current_app
            inspect = current_app.control.inspect()
            stats = inspect.stats()
            
            if stats:
                self.stdout.write(
                    self.style.SUCCESS('✅ Celery worker: Active')
                )
                for worker, stat in stats.items():
                    self.stdout.write(f'   Worker: {worker}')
            else:
                self.stdout.write(
                    self.style.WARNING('⚠️  No active Celery workers found')
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f'⚠️  Could not check worker status: {e}')
            )
        
        self.stdout.write(
            self.style.SUCCESS('🎉 Celery health check completed!')
        )
