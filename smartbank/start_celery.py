#!/usr/bin/env python
"""
Celery startup script for SmartBank
"""
import os
import sys
import subprocess

def start_celery_worker():
    """Start Celery worker"""
    print("Starting Celery worker...")
    try:
        subprocess.run([
            sys.executable, '-m', 'celery', 
            '-A', 'smartbank', 
            'worker', 
            '--loglevel=info',
            '--concurrency=4'
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error starting Celery worker: {e}")
        return False
    return True

def start_celery_beat():
    """Start Celery beat scheduler"""
    print("Starting Celery beat...")
    try:
        subprocess.run([
            sys.executable, '-m', 'celery', 
            '-A', 'smartbank', 
            'beat', 
            '--loglevel=info'
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error starting Celery beat: {e}")
        return False
    return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Start Celery services')
    parser.add_argument('service', choices=['worker', 'beat', 'both'], 
                       help='Which Celery service to start')
    
    args = parser.parse_args()
    
    if args.service == 'worker':
        start_celery_worker()
    elif args.service == 'beat':
        start_celery_beat()
    elif args.service == 'both':
        print("Starting both Celery worker and beat...")
        # In production, you'd use a process manager like supervisor
        print("Note: In production, use a process manager to run both services")
        start_celery_worker()
