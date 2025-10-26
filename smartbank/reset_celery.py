#!/usr/bin/env python
"""
Reset Celery configuration and clear all data
"""
import os
import sys
import subprocess
import time

def reset_celery():
    """Reset Celery completely"""
    print("🔄 Resetting Celery...")
    
    # Kill existing Celery processes
    try:
        print("🛑 Stopping existing Celery processes...")
        subprocess.run(['pkill', '-f', 'celery'], check=False)
        time.sleep(2)
    except Exception as e:
        print(f"Note: {e}")
    
    # Clear Redis data
    try:
        print("🧹 Clearing Redis data...")
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.flushall()
        print("✅ Redis cleared")
    except Exception as e:
        print(f"⚠️  Could not clear Redis: {e}")
    
    # Clear Django cache
    try:
        print("🧹 Clearing Django cache...")
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartbank.settings')
        import django
        django.setup()
        
        from django.core.cache import cache
        cache.clear()
        print("✅ Django cache cleared")
    except Exception as e:
        print(f"⚠️  Could not clear Django cache: {e}")
    
    # Clear rate limits
    try:
        print("🧹 Clearing rate limits...")
        from registration.models import RateLimit
        deleted_count = RateLimit.objects.all().delete()[0]
        print(f"✅ Cleared {deleted_count} rate limit records")
    except Exception as e:
        print(f"⚠️  Could not clear rate limits: {e}")
    
    print("🎉 Celery reset completed!")
    print("\nNext steps:")
    print("1. Start Redis: redis-server")
    print("2. Start Celery worker: python start_celery_worker.py worker")
    print("3. Start Celery beat: python start_celery_worker.py beat")
    print("4. Start Django: python manage.py runserver")

if __name__ == "__main__":
    reset_celery()
