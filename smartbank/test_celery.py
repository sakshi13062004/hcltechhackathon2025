#!/usr/bin/env python
"""
Simple Celery test script to verify Celery is working correctly
"""
import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartbank.settings')
django.setup()

from registration.tasks import test_celery_task

def test_celery():
    """Test Celery task execution"""
    print("Testing Celery...")
    
    try:
        # Test the simple task
        result = test_celery_task.delay()
        print(f"Task submitted: {result.id}")
        
        # Wait for result (with timeout)
        try:
            task_result = result.get(timeout=10)
            print(f"Task result: {task_result}")
            print("✅ Celery is working correctly!")
            return True
        except Exception as e:
            print(f"❌ Task execution failed: {e}")
            return False
            
    except Exception as e:
        print(f"❌ Celery test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_celery()
    sys.exit(0 if success else 1)
