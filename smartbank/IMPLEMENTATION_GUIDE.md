# SmartBank - User Registration & KYC Implementation Guide

## 🚀 Complete Implementation

This guide provides the complete implementation of the user registration and KYC use case with all security features as discussed.

## 📁 Project Structure

```
smartbank/
├── smartbank/
│   ├── __init__.py
│   ├── settings.py          # Django settings with all configurations
│   ├── urls.py             # Main URL configuration
│   ├── wsgi.py
│   ├── asgi.py
│   └── celery.py           # Celery configuration
├── registration/
│   ├── __init__.py
│   ├── models.py           # All database models
│   ├── views.py            # API views and endpoints
│   ├── serializers.py      # DRF serializers
│   ├── urls.py             # Registration app URLs
│   ├── utils.py            # Utility functions and services
│   ├── middleware.py       # Rate limiting and security middleware
│   ├── tasks.py            # Celery background tasks
│   ├── admin.py            # Django admin configuration
│   ├── tests.py            # Comprehensive test suite
│   └── management/
│       └── commands/
│           └── setup_roles.py
├── requirements.txt        # All dependencies
├── pytest.ini            # Test configuration
└── env_template.txt       # Environment variables template
```

## 🔧 Installation & Setup

### 1. Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Redis (Ubuntu/Debian)
sudo apt-get install redis-server

# Install PostgreSQL (Ubuntu/Debian)
sudo apt-get install postgresql postgresql-contrib
```

### 2. Environment Configuration

```bash
# Copy environment template
cp env_template.txt .env

# Edit .env file with your settings
nano .env
```

### 3. Database Setup

```bash
# Create PostgreSQL database
sudo -u postgres createdb smartbank_db

# Run migrations
python manage.py makemigrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Setup default roles
python manage.py setup_roles
```

### 4. Start Services

```bash
# Terminal 1: Start Django server
python manage.py runserver

# Terminal 2: Start Redis
redis-server

# Terminal 3: Start Celery worker
celery -A smartbank worker --loglevel=info

# Terminal 4: Start Celery beat (scheduler)
celery -A smartbank beat --loglevel=info
```

## 🔐 Security Features Implemented

### 1. **JWT Authentication**
- Access tokens (60 minutes)
- Refresh tokens (7 days)
- Token rotation on refresh
- Custom claims for user roles and KYC status

### 2. **Password Security**
- bcrypt hashing with salt
- Password strength validation
- Failed login attempt tracking
- Account lockout after 5 failed attempts

### 3. **Data Encryption**
- SSN encryption using Fernet
- Address encryption using Fernet
- Document file encryption
- Separate encryption keys for different data types

### 4. **Rate Limiting**
- IP-based rate limiting
- User-based rate limiting
- Different limits per endpoint
- Progressive penalties for violations

### 5. **Role-Based Access Control**
- Customer, Bank Admin, Auditor roles
- Granular permissions per role
- Admin-only endpoints protection
- Audit trail for all actions

### 6. **Audit Logging**
- All user actions logged
- IP address tracking
- User agent logging
- Change tracking (old vs new values)

### 7. **Security Monitoring**
- Security event logging
- Suspicious activity detection
- Failed login monitoring
- Rate limit violation tracking

## 📡 API Endpoints

### Authentication Endpoints

#### Register User
```bash
POST /api/auth/register/
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123!",
  "confirm_password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "date_of_birth": "1990-01-15",
  "ssn": "123-45-6789",
  "address": "123 Main St, City, State, ZIP"
}
```

#### Login User
```bash
POST /api/auth/login/
Content-Type: application/json

{
  "username": "john_doe",
  "password": "SecurePass123!"
}
```

#### Refresh Token
```bash
POST /api/auth/refresh/
Content-Type: application/json

{
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### User Profile Endpoints

#### Get Profile
```bash
GET /api/profile/
Authorization: Bearer <access_token>
```

#### Update Profile
```bash
PUT /api/profile/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "first_name": "John",
  "last_name": "Doe Updated",
  "phone_number": "+1234567890"
}
```

#### Change Password
```bash
POST /api/profile/change-password/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "old_password": "OldPass123!",
  "new_password": "NewPass123!",
  "confirm_password": "NewPass123!"
}
```

### KYC Endpoints

#### Upload KYC Document
```bash
POST /api/kyc/upload/
Authorization: Bearer <access_token>
Content-Type: multipart/form-data

{
  "document_type": "GOVERNMENT_ID",
  "document_number": "A1234567",
  "document_file": <file_data>
}
```

#### List KYC Documents
```bash
GET /api/kyc/documents/
Authorization: Bearer <access_token>
```

### Admin Endpoints

#### List All Users
```bash
GET /api/admin/users/
Authorization: Bearer <admin_access_token>
```

#### List KYC Documents (Admin)
```bash
GET /api/admin/kyc/documents/
Authorization: Bearer <admin_access_token>
```

#### Review KYC
```bash
POST /api/admin/kyc/review/{user_id}/
Authorization: Bearer <admin_access_token>
Content-Type: application/json

{
  "action": "approve"  // or "reject"
  "rejection_reason": "Invalid document"  // required for rejection
}
```

#### Dashboard Statistics
```bash
GET /api/admin/dashboard/stats/
Authorization: Bearer <admin_access_token>
```

#### Audit Logs
```bash
GET /api/admin/audit-logs/
Authorization: Bearer <admin_access_token>
```

#### Security Events
```bash
GET /api/admin/security-events/
Authorization: Bearer <admin_access_token>
```

#### Notifications
```bash
GET /api/admin/notifications/
Authorization: Bearer <admin_access_token>
```

## 🧪 Testing

### Run All Tests
```bash
# Run tests with coverage
pytest --cov=registration --cov-report=html

# Run specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m api          # API tests only
```

### Test Coverage
```bash
# Generate coverage report
coverage run --source='.' manage.py test
coverage report
coverage html
```

### Test Categories

1. **Model Tests** - Test database models and relationships
2. **Utility Tests** - Test encryption, validation, and security services
3. **Serializer Tests** - Test data serialization and validation
4. **API Tests** - Test all API endpoints
5. **Integration Tests** - Test complete user flows
6. **Rate Limit Tests** - Test rate limiting functionality
7. **Celery Task Tests** - Test background tasks

## 🔄 Complete User Flow

### 1. User Registration Flow
```
User submits registration → Validation → Encryption → Database storage → 
Redis caching → Admin notification → Celery task processing
```

### 2. KYC Upload Flow
```
User uploads document → File validation → Encryption → Secure storage → 
Database metadata → Celery processing → Admin notification
```

### 3. Admin Review Flow
```
Admin reviews KYC → Approve/Reject → Update user status → 
Email notification → Audit logging → Cache update
```

## 🛡️ Security Implementation Details

### Rate Limiting Configuration
```python
RATE_LIMIT_SETTINGS = {
    'REGISTRATION': {
        'requests': 3,
        'window': 3600,  # 1 hour
        'lockout': 3600,  # 1 hour
    },
    'LOGIN': {
        'requests': 5,
        'window': 60,  # 1 minute
        'lockout': 1800,  # 30 minutes
    },
    'KYC_UPLOAD': {
        'requests': 10,
        'window': 300,  # 5 minutes
        'lockout': 0,
    }
}
```

### Encryption Implementation
```python
# SSN Encryption
encrypted_ssn = encryption_service.encrypt_ssn("123-45-6789")
decrypted_ssn = encryption_service.decrypt_ssn(encrypted_ssn)

# Address Encryption
encrypted_address = encryption_service.encrypt_address("123 Main St")
decrypted_address = encryption_service.decrypt_address(encrypted_address)
```

### JWT Token Structure
```python
{
    "user_id": 1,
    "username": "john_doe",
    "kyc_status": "PENDING",
    "roles": ["CUSTOMER"],
    "exp": 1234567890
}
```

## 📊 Monitoring & Logging

### Audit Logs
- All user actions are logged with timestamps
- IP addresses and user agents tracked
- Change tracking for data modifications
- Searchable and filterable logs

### Security Events
- Failed login attempts
- Rate limit violations
- Suspicious activity patterns
- Account lockouts and unlocks

### System Health Monitoring
- Database connection monitoring
- Redis connection monitoring
- Celery task monitoring
- File storage monitoring

## 🚀 Production Deployment

### Environment Variables
```bash
# Security
SECRET_KEY=your-production-secret-key
DEBUG=False
ALLOWED_HOSTS=yourdomain.com

# Database
DB_NAME=smartbank_prod
DB_USER=smartbank_user
DB_PASSWORD=secure-password
DB_HOST=localhost
DB_PORT=5432

# Redis
REDIS_URL=redis://localhost:6379/0

# Encryption Keys (Generate new ones for production)
ENCRYPTION_KEY_SSN=your-production-ssn-key
ENCRYPTION_KEY_ADDRESS=your-production-address-key
ENCRYPTION_KEY_DOCUMENTS=your-production-document-key
```

### Production Commands
```bash
# Collect static files
python manage.py collectstatic

# Run with Gunicorn
gunicorn smartbank.wsgi:application --bind 0.0.0.0:8000

# Start Celery worker
celery -A smartbank worker --loglevel=info --concurrency=4

# Start Celery beat
celery -A smartbank beat --loglevel=info
```

## 🔍 Troubleshooting

### Common Issues

1. **Redis Connection Error**
   ```bash
   # Check Redis status
   redis-cli ping
   
   # Start Redis
   redis-server
   ```

2. **Database Connection Error**
   ```bash
   # Check PostgreSQL status
   sudo systemctl status postgresql
   
   # Start PostgreSQL
   sudo systemctl start postgresql
   ```

3. **Celery Task Not Running**
   ```bash
   # Check Celery worker
   celery -A smartbank inspect active
   
   # Restart Celery worker
   celery -A smartbank worker --loglevel=info
   ```

4. **File Upload Issues**
   ```bash
   # Check media directory permissions
   chmod 755 media/
   
   # Check file size limits
   # Update MAX_UPLOAD_SIZE in settings.py
   ```

## 📈 Performance Optimization

### Database Optimization
- Proper indexing on frequently queried fields
- Database connection pooling
- Query optimization with select_related and prefetch_related

### Caching Strategy
- Redis caching for user data
- Session data caching
- Rate limit data caching
- File upload progress caching

### Background Processing
- Celery for heavy operations
- Document processing in background
- Email notifications asynchronously
- Data cleanup tasks

## 🔒 Security Best Practices

1. **Encryption Keys** - Rotate encryption keys regularly
2. **Password Policy** - Enforce strong password requirements
3. **Rate Limiting** - Monitor and adjust rate limits
4. **Audit Logs** - Regular review of audit logs
5. **Security Events** - Monitor security events dashboard
6. **File Validation** - Strict file type and size validation
7. **Input Validation** - Comprehensive input validation
8. **Error Handling** - Secure error messages without sensitive data

## 📝 API Documentation

The API follows RESTful principles with proper HTTP status codes:

- `200 OK` - Successful GET, PUT requests
- `201 Created` - Successful POST requests
- `400 Bad Request` - Validation errors
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server errors

## 🎯 Success Metrics

- **Security**: Zero data breaches, all sensitive data encrypted
- **Performance**: Sub-second API response times
- **Reliability**: 99.9% uptime with proper error handling
- **Compliance**: Full audit trail for regulatory compliance
- **User Experience**: Smooth registration and KYC process

This implementation provides a production-ready, secure, and scalable user registration and KYC system with comprehensive security features, monitoring, and testing coverage.
