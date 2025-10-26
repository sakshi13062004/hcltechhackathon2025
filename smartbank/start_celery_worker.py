#!/usr/bin/env python
"""
Robust Celery worker startup script
"""
import os
import sys
import subprocess
import time
import signal
from pathlib import Path

def check_redis():
    """Check if Redis is running"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        print("✅ Redis is running")
        return True
    except Exception as e:
        print(f"❌ Redis is not running: {e}")
        print("Please start Redis first:")
        print("  - Windows: redis-server")
        print("  - Docker: docker run -d -p 6379:6379 redis:alpine")
        return False

def check_django():
    """Check if Django is properly configured"""
    try:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smartbank.settings')
        import django
        django.setup()
        print("✅ Django is properly configured")
        return True
    except Exception as e:
        print(f"❌ Django configuration error: {e}")
        return False

def start_celery_worker():
    """Start Celery worker with proper error handling"""
    print("Starting Celery worker...")
    
    # Check prerequisites
    if not check_redis():
        return False
    
    if not check_django():
        return False
    
    try:
        # Start Celery worker with explicit configuration
        cmd = [
            sys.executable, '-m', 'celery',
            '-A', 'smartbank',
            'worker',
            '--loglevel=info',
            '--concurrency=2',
            '--pool=solo',  # Use solo pool to avoid multiprocessing issues
            '--without-gossip',
            '--without-mingle',
            '--without-heartbeat'
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        
        # Start the process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Monitor output
        try:
            for line in iter(process.stdout.readline, ''):
                print(line.rstrip())
                if 'ready' in line.lower():
                    print("🎉 Celery worker is ready!")
                    break
        except KeyboardInterrupt:
            print("\n🛑 Stopping Celery worker...")
            process.terminate()
            process.wait()
            print("✅ Celery worker stopped")
        
        return True
        
    except Exception as e:
        print(f"❌ Error starting Celery worker: {e}")
        return False

def start_celery_beat():
    """Start Celery beat scheduler"""
    print("Starting Celery beat...")
    
    try:
        cmd = [
            sys.executable, '-m', 'celery',
            '-A', 'smartbank',
            'beat',
            '--loglevel=info',
            '--scheduler=django_celery_beat.schedulers:DatabaseScheduler'
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        try:
            for line in iter(process.stdout.readline, ''):
                print(line.rstrip())
        except KeyboardInterrupt:
            print("\n🛑 Stopping Celery beat...")
            process.terminate()
            process.wait()
            print("✅ Celery beat stopped")
        
        return True
        
    except Exception as e:
        print(f"❌ Error starting Celery beat: {e}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Start Celery services')
    parser.add_argument('service', choices=['worker', 'beat', 'both'], 
                       help='Which Celery service to start')
    
    args = parser.parse_args()
    
    # Change to project directory
    project_dir = Path(__file__).parent
    os.chdir(project_dir)
    
    if args.service == 'worker':
        start_celery_worker()
    elif args.service == 'beat':
        start_celery_beat()
    elif args.service == 'both':
        print("Starting both Celery worker and beat...")
        print("Note: Run each in separate terminals for production")
        start_celery_worker()
