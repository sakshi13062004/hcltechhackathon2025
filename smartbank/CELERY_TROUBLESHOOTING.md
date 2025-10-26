# Celery Troubleshooting Guide

## 🔧 **Common Celery Issues and Solutions**

### **Issue 1: "ValueError: not enough values to unpack (expected 3, got 0)"**

**Cause**: This error typically occurs when Celery can't properly initialize or when there are configuration issues.

**Solutions**:

1. **Check Redis Connection**:
   ```bash
   # Test Redis connection
   redis-cli ping
   # Should return: PONG
   ```

2. **Verify Celery Configuration**:
   ```bash
   # Test Celery configuration
   python manage.py shell
   >>> from celery import current_app
   >>> print(current_app.conf.broker_url)
   ```

3. **Clear Celery Cache**:
   ```bash
   # Clear any cached Celery data
   python manage.py shell
   >>> from django.core.cache import cache
   >>> cache.clear()
   ```

### **Issue 2: Celery Worker Won't Start**

**Solutions**:

1. **Check Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Verify Django Setup**:
   ```bash
   python manage.py check
   ```

3. **Test Celery Import**:
   ```bash
   python manage.py shell
   >>> from smartbank.celery import app
   >>> print(app.conf.broker_url)
   ```

### **Issue 3: Tasks Not Executing**

**Solutions**:

1. **Check Worker Status**:
   ```bash
   # Start worker with verbose logging
   celery -A smartbank worker --loglevel=debug
   ```

2. **Test Task Submission**:
   ```bash
   python manage.py test_celery
   ```

3. **Check Redis Connection**:
   ```bash
   # Verify Redis is running
   redis-cli info
   ```

## 🚀 **Starting Celery Services**

### **Development Setup**

1. **Start Redis** (if not running):
   ```bash
   # Windows (if Redis is installed)
   redis-server
   
   # Or use Docker
   docker run -d -p 6379:6379 redis:alpine
   ```

2. **Start Celery Worker**:
   ```bash
   cd smartbank
   celery -A smartbank worker --loglevel=info
   ```

3. **Start Celery Beat** (in another terminal):
   ```bash
   cd smartbank
   celery -A smartbank beat --loglevel=info
   ```

4. **Start Django Server**:
   ```bash
   cd smartbank
   python manage.py runserver
   ```

### **Testing Celery**

1. **Test Basic Functionality**:
   ```bash
   python manage.py test_celery
   ```

2. **Test from Django Shell**:
   ```bash
   python manage.py shell
   >>> from registration.tasks import test_celery_task
   >>> result = test_celery_task.delay()
   >>> print(result.get())
   ```

3. **Monitor Celery**:
   ```bash
   # Install flower for monitoring
   pip install flower
   celery -A smartbank flower
   # Access at: http://localhost:5555
   ```

## 🛠️ **Configuration Fixes**

### **Updated Celery Settings**

The following settings have been added to fix common issues:

```python
# In settings.py
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes
CELERY_TASK_SOFT_TIME_LIMIT = 60  # 1 minute
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000
CELERY_TASK_ALWAYS_EAGER = False  # Set to True for testing
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_WORKER_DISABLE_RATE_LIMITS = True
CELERY_TASK_IGNORE_RESULT = False
CELERY_RESULT_EXPIRES = 3600  # 1 hour
```

### **Updated Celery App Configuration**

```python
# In celery.py
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,
    task_soft_time_limit=60,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    task_always_eager=False,
    task_eager_propagates=True,
    worker_disable_rate_limits=True,
    task_ignore_result=False,
    result_expires=3600,
)
```

## 🔍 **Debugging Commands**

### **Check Celery Status**
```bash
# Check if Celery is working
python manage.py shell
>>> from celery import current_app
>>> print(current_app.conf.broker_url)
>>> print(current_app.conf.result_backend)
```

### **Test Redis Connection**
```bash
# Test Redis directly
redis-cli ping
redis-cli info server
```

### **Monitor Celery Tasks**
```bash
# Install and use flower
pip install flower
celery -A smartbank flower
```

### **Check Task Registration**
```bash
# List registered tasks
celery -A smartbank inspect registered
```

## 🚨 **Emergency Fixes**

### **If Celery Completely Fails**

1. **Reset Everything**:
   ```bash
   # Stop all Celery processes
   pkill -f celery
   
   # Clear Redis
   redis-cli flushall
   
   # Restart services
   redis-server &
   celery -A smartbank worker --loglevel=info &
   celery -A smartbank beat --loglevel=info &
   ```

2. **Use Synchronous Mode for Testing**:
   ```python
   # In settings.py (for testing only)
   CELERY_TASK_ALWAYS_EAGER = True
   CELERY_TASK_EAGER_PROPAGATES = True
   ```

3. **Check Logs**:
   ```bash
   # Check Celery logs
   tail -f logs/smartbank.log
   
   # Check Redis logs
   redis-cli monitor
   ```

## 📋 **Verification Checklist**

- [ ] Redis is running and accessible
- [ ] Django settings are correct
- [ ] Celery app is properly configured
- [ ] Tasks are registered
- [ ] Worker can connect to broker
- [ ] Beat scheduler is working
- [ ] Tasks execute successfully

## 🆘 **Still Having Issues?**

1. **Check the logs**: Look at `logs/smartbank.log` for detailed error messages
2. **Verify Redis**: Ensure Redis is running and accessible
3. **Test basic functionality**: Use the test commands provided
4. **Check dependencies**: Ensure all packages are installed correctly
5. **Restart services**: Sometimes a simple restart fixes issues

**Common Commands for Quick Fixes**:
```bash
# Quick restart
pkill -f celery && celery -A smartbank worker --loglevel=info

# Test everything
python manage.py test_celery

# Check status
celery -A smartbank inspect active
```
