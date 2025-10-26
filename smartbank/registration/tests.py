"""
Comprehensive tests for registration app
"""
import json
import tempfile
from datetime import date, timedelta
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from unittest.mock import patch, MagicMock

from .models import User, Role, UserRole, KYCDocument, AuditLog, SecurityEvent, Notification
from .utils import EncryptionService, ValidationService, SecurityService, AuditService
from .serializers import UserRegistrationSerializer, KYCDocumentSerializer

User = get_user_model()


class ModelTests(TestCase):
    """Test cases for models"""
    
    def setUp(self):
        """Set up test data"""
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123',
            'first_name': 'Test',
            'last_name': 'User',
            'phone_number': '+1234567890',
            'date_of_birth': date(1990, 1, 1),
            'ssn_encrypted': 'encrypted_ssn',
            'address_encrypted': 'encrypted_address'
        }
    
    def test_user_creation(self):
        """Test user creation"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(user.customer_id.startswith('CUST'))
        self.assertEqual(user.kyc_status, 'PENDING')
        self.assertEqual(user.risk_profile, 'LOW')
    
    def test_user_customer_id_generation(self):
        """Test customer ID generation"""
        user = User.objects.create_user(**self.user_data)
        self.assertTrue(user.customer_id.startswith('CUST'))
        self.assertEqual(len(user.customer_id), 14)  # CUST + 10 chars
    
    def test_user_account_locking(self):
        """Test account locking functionality"""
        user = User.objects.create_user(**self.user_data)
        
        # Test account lock
        user.lock_account(30)
        self.assertTrue(user.is_account_locked())
        
        # Test account unlock
        user.unlock_account()
        self.assertFalse(user.is_account_locked())
        self.assertEqual(user.failed_login_attempts, 0)
    
    def test_user_failed_login_increment(self):
        """Test failed login attempt increment"""
        user = User.objects.create_user(**self.user_data)
        
        # Test failed login attempts
        for i in range(4):
            user.increment_failed_login()
            self.assertEqual(user.failed_login_attempts, i + 1)
        
        # Test account lock after 5 failed attempts
        user.increment_failed_login()
        self.assertTrue(user.is_account_locked())
    
    def test_role_creation(self):
        """Test role creation"""
        role = Role.objects.create(
            name='TEST_ROLE',
            description='Test Role',
            permissions=['test_permission']
        )
        self.assertEqual(role.name, 'TEST_ROLE')
        self.assertEqual(role.permissions, ['test_permission'])
    
    def test_user_role_assignment(self):
        """Test user role assignment"""
        user = User.objects.create_user(**self.user_data)
        role = Role.objects.create(
            name='TEST_ROLE',
            description='Test Role'
        )
        
        user_role = UserRole.objects.create(
            user=user,
            role=role,
            is_active=True
        )
        
        self.assertEqual(user_role.user, user)
        self.assertEqual(user_role.role, role)
        self.assertTrue(user_role.is_active)
    
    def test_kyc_document_creation(self):
        """Test KYC document creation"""
        user = User.objects.create_user(**self.user_data)
        
        kyc_doc = KYCDocument.objects.create(
            user=user,
            document_type='GOVERNMENT_ID',
            document_number='A1234567',
            document_file_path='/path/to/file.pdf',
            file_hash='abc123',
            file_size=1024
        )
        
        self.assertEqual(kyc_doc.user, user)
        self.assertEqual(kyc_doc.document_type, 'GOVERNMENT_ID')
        self.assertEqual(kyc_doc.verification_status, 'PENDING')
    
    def test_audit_log_creation(self):
        """Test audit log creation"""
        user = User.objects.create_user(**self.user_data)
        
        audit_log = AuditLog.objects.create(
            user=user,
            action_type='CREATE',
            target_model='User',
            description='Test action',
            ip_address='127.0.0.1'
        )
        
        self.assertEqual(audit_log.user, user)
        self.assertEqual(audit_log.action_type, 'CREATE')
        self.assertIsNotNone(audit_log.log_id)
    
    def test_security_event_creation(self):
        """Test security event creation"""
        user = User.objects.create_user(**self.user_data)
        
        security_event = SecurityEvent.objects.create(
            event_type='FAILED_LOGIN',
            user=user,
            ip_address='127.0.0.1',
            description='Test security event'
        )
        
        self.assertEqual(security_event.user, user)
        self.assertEqual(security_event.event_type, 'FAILED_LOGIN')
        self.assertEqual(security_event.severity, 'MEDIUM')


class UtilityTests(TestCase):
    """Test cases for utility functions"""
    
    def setUp(self):
        """Set up test data"""
        self.encryption_service = EncryptionService()
        self.validation_service = ValidationService()
    
    def test_ssn_encryption_decryption(self):
        """Test SSN encryption and decryption"""
        ssn = '123456789'
        
        # Test encryption
        encrypted_ssn = self.encryption_service.encrypt_ssn(ssn)
        self.assertNotEqual(encrypted_ssn, ssn)
        
        # Test decryption
        decrypted_ssn = self.encryption_service.decrypt_ssn(encrypted_ssn)
        self.assertEqual(decrypted_ssn, ssn)
    
    def test_address_encryption_decryption(self):
        """Test address encryption and decryption"""
        address = '123 Main St, City, State 12345'
        
        # Test encryption
        encrypted_address = self.encryption_service.encrypt_address(address)
        self.assertNotEqual(encrypted_address, address)
        
        # Test decryption
        decrypted_address = self.encryption_service.decrypt_address(encrypted_address)
        self.assertEqual(decrypted_address, address)
    
    def test_age_validation(self):
        """Test age validation"""
        # Test valid age (18+)
        valid_birth_date = date(1990, 1, 1)
        self.assertTrue(self.validation_service.validate_age(valid_birth_date))
        
        # Test invalid age (< 18)
        invalid_birth_date = date(2010, 1, 1)
        with self.assertRaises(Exception):
            self.validation_service.validate_age(invalid_birth_date)
        
        # Test future birth date
        future_birth_date = date(2030, 1, 1)
        with self.assertRaises(Exception):
            self.validation_service.validate_age(future_birth_date)
    
    def test_phone_validation(self):
        """Test phone number validation"""
        # Test valid phone numbers
        valid_phones = ['+1234567890', '1234567890', '+1234567890123']
        for phone in valid_phones:
            self.assertTrue(self.validation_service.validate_phone_number(phone))
        
        # Test invalid phone numbers
        invalid_phones = ['123', 'abc123', '+123-456-7890']
        for phone in invalid_phones:
            with self.assertRaises(Exception):
                self.validation_service.validate_phone_number(phone)
    
    def test_password_validation(self):
        """Test password strength validation"""
        # Test valid password
        valid_password = 'SecurePass123'
        self.assertTrue(self.validation_service.validate_password_strength(valid_password))
        
        # Test invalid passwords
        invalid_passwords = ['123', 'password', 'PASSWORD', 'Password']
        for password in invalid_passwords:
            with self.assertRaises(Exception):
                self.validation_service.validate_password_strength(password)
    
    def test_file_validation(self):
        """Test file type and size validation"""
        # Test valid file types
        valid_files = ['document.pdf', 'image.jpg', 'file.png', 'doc.docx']
        for filename in valid_files:
            self.assertTrue(self.validation_service.validate_file_type(filename))
        
        # Test invalid file types
        invalid_files = ['script.exe', 'file.bat', 'malware.vbs']
        for filename in invalid_files:
            with self.assertRaises(Exception):
                self.validation_service.validate_file_type(filename)
        
        # Test file size validation
        self.assertTrue(self.validation_service.validate_file_size(1024))  # 1KB
        with self.assertRaises(Exception):
            self.validation_service.validate_file_size(11 * 1024 * 1024)  # 11MB
    
    def test_security_service(self):
        """Test security service functions"""
        # Test file hash calculation
        content = b'test content'
        hash_value = SecurityService.calculate_file_hash(content)
        self.assertEqual(len(hash_value), 64)  # SHA-256 hash length
        
        # Test duplicate SSN check
        user_data = {
            'username': 'testuser1',
            'email': 'test1@example.com',
            'password': 'testpass123',
            'first_name': 'Test',
            'last_name': 'User',
            'phone_number': '+1234567891',
            'date_of_birth': date(1990, 1, 1),
            'ssn_encrypted': self.encryption_service.encrypt_ssn('123456789'),
            'address_encrypted': 'encrypted_address'
        }
        User.objects.create_user(**user_data)
        
        # Test duplicate SSN detection
        self.assertTrue(SecurityService.check_duplicate_ssn('123456789'))
        self.assertFalse(SecurityService.check_duplicate_ssn('987654321'))


class SerializerTests(TestCase):
    """Test cases for serializers"""
    
    def test_user_registration_serializer(self):
        """Test user registration serializer"""
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'SecurePass123',
            'confirm_password': 'SecurePass123',
            'first_name': 'Test',
            'last_name': 'User',
            'phone_number': '+1234567890',
            'date_of_birth': '1990-01-01',
            'ssn': '123456789',
            'address': '123 Main St, City, State 12345'
        }
        
        serializer = UserRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        user = serializer.save()
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
    
    def test_user_registration_serializer_validation_errors(self):
        """Test user registration serializer validation errors"""
        # Test password mismatch
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'SecurePass123',
            'confirm_password': 'DifferentPass123',
            'first_name': 'Test',
            'last_name': 'User',
            'phone_number': '+1234567890',
            'date_of_birth': '1990-01-01',
            'ssn': '123456789',
            'address': '123 Main St, City, State 12345'
        }
        
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('confirm_password', serializer.errors)
        
        # Test weak password
        data['confirm_password'] = 'SecurePass123'
        data['password'] = 'weak'
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)


class APITests(APITestCase):
    """Test cases for API endpoints"""
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'SecurePass123',
            'confirm_password': 'SecurePass123',
            'first_name': 'Test',
            'last_name': 'User',
            'phone_number': '+1234567890',
            'date_of_birth': '1990-01-01',
            'ssn': '123456789',
            'address': '123 Main St, City, State 12345'
        }
        
        # Create test user
        self.user = User.objects.create_user(
            username='existinguser',
            email='existing@example.com',
            password='SecurePass123',
            first_name='Existing',
            last_name='User',
            phone_number='+1234567891',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn',
            address_encrypted='encrypted_address'
        )
        
        # Create admin user
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='SecurePass123',
            first_name='Admin',
            last_name='User',
            phone_number='+1234567892',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn_admin',
            address_encrypted='encrypted_address_admin',
            is_staff=True
        )
        
        # Create admin role
        self.admin_role = Role.objects.create(
            name='BANK_ADMIN',
            description='Bank Administrator',
            permissions=['view_all_users', 'approve_kyc']
        )
        
        # Assign admin role
        UserRole.objects.create(
            user=self.admin_user,
            role=self.admin_role,
            is_active=True
        )
    
    def test_user_registration_success(self):
        """Test successful user registration"""
        response = self.client.post('/api/auth/register/', self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('customer_id', response.data)
        self.assertEqual(response.data['kyc_status'], 'PENDING')
    
    def test_user_registration_validation_errors(self):
        """Test user registration validation errors"""
        # Test duplicate email
        self.user_data['email'] = 'existing@example.com'
        response = self.client.post('/api/auth/register/', self.user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Test invalid phone number
        self.user_data['email'] = 'new@example.com'
        self.user_data['phone_number'] = 'invalid'
        response = self.client.post('/api/auth/register/', self.user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_user_login_success(self):
        """Test successful user login"""
        login_data = {
            'username': 'existinguser',
            'password': 'SecurePass123'
        }
        response = self.client.post('/api/auth/login/', login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
    
    def test_user_login_invalid_credentials(self):
        """Test user login with invalid credentials"""
        login_data = {
            'username': 'existinguser',
            'password': 'wrongpassword'
        }
        response = self.client.post('/api/auth/login/', login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_user_profile_retrieval(self):
        """Test user profile retrieval"""
        # Get JWT token
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        response = self.client.get('/api/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'existinguser')
    
    def test_user_profile_update(self):
        """Test user profile update"""
        # Get JWT token
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        update_data = {
            'first_name': 'Updated',
            'last_name': 'Name'
        }
        
        response = self.client.put('/api/profile/', update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Updated')
    
    def test_kyc_document_upload(self):
        """Test KYC document upload"""
        # Get JWT token
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        # Create test file
        test_file = SimpleUploadedFile(
            "test_document.pdf",
            b"file_content",
            content_type="application/pdf"
        )
        
        upload_data = {
            'document_type': 'GOVERNMENT_ID',
            'document_number': 'A1234567',
            'document_file': test_file
        }
        
        response = self.client.post('/api/kyc/upload/', upload_data, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['document_type'], 'GOVERNMENT_ID')
    
    def test_kyc_document_list(self):
        """Test KYC document list"""
        # Create KYC document
        KYCDocument.objects.create(
            user=self.user,
            document_type='GOVERNMENT_ID',
            document_number='A1234567',
            document_file_path='/path/to/file.pdf',
            file_hash='abc123',
            file_size=1024
        )
        
        # Get JWT token
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        response = self.client.get('/api/kyc/documents/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
    
    def test_admin_user_list(self):
        """Test admin user list"""
        # Get JWT token for admin
        refresh = RefreshToken.for_user(self.admin_user)
        access_token = str(refresh.access_token)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        response = self.client.get('/api/admin/users/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
    
    def test_admin_kyc_review(self):
        """Test admin KYC review"""
        # Get JWT token for admin
        refresh = RefreshToken.for_user(self.admin_user)
        access_token = str(refresh.access_token)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        review_data = {
            'action': 'approve'
        }
        
        response = self.client.post(f'/api/admin/kyc/review/{self.user.id}/', review_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
    
    def test_dashboard_stats(self):
        """Test dashboard statistics"""
        # Get JWT token for admin
        refresh = RefreshToken.for_user(self.admin_user)
        access_token = str(refresh.access_token)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        response = self.client.get('/api/admin/dashboard/stats/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('total_users', response.data)
        self.assertIn('pending_kyc', response.data)
    
    def test_unauthorized_access(self):
        """Test unauthorized access to protected endpoints"""
        response = self.client.get('/api/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        response = self.client.get('/api/admin/users/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_forbidden_access(self):
        """Test forbidden access to admin endpoints"""
        # Get JWT token for regular user
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        response = self.client.get('/api/admin/users/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # Returns empty queryset
        
        response = self.client.get('/api/admin/dashboard/stats/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class IntegrationTests(TestCase):
    """Integration test cases"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePass123',
            first_name='Test',
            last_name='User',
            phone_number='+1234567890',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn',
            address_encrypted='encrypted_address'
        )
    
    @patch('registration.tasks.process_kyc_document.delay')
    def test_complete_registration_flow(self, mock_task):
        """Test complete registration and KYC flow"""
        # Register user
        registration_data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'SecurePass123',
            'confirm_password': 'SecurePass123',
            'first_name': 'New',
            'last_name': 'User',
            'phone_number': '+1234567891',
            'date_of_birth': '1990-01-01',
            'ssn': '987654321',
            'address': '456 Oak St, City, State 54321'
        }
        
        response = self.client.post('/api/auth/register/', registration_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Login user
        login_data = {
            'username': 'newuser',
            'password': 'SecurePass123'
        }
        
        response = self.client.post('/api/auth/login/', login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        access_token = response.data['access']
        
        # Upload KYC document
        test_file = SimpleUploadedFile(
            "test_document.pdf",
            b"file_content",
            content_type="application/pdf"
        )
        
        upload_data = {
            'document_type': 'GOVERNMENT_ID',
            'document_number': 'B9876543',
            'document_file': test_file
        }
        
        headers = {'HTTP_AUTHORIZATION': f'Bearer {access_token}'}
        response = self.client.post('/api/kyc/upload/', upload_data, format='multipart', **headers)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Verify task was called
        mock_task.assert_called_once()
    
    def test_audit_logging(self):
        """Test audit logging functionality"""
        # Create audit log
        audit_log = AuditService.log_action(
            user=self.user,
            action_type='CREATE',
            target_model='User',
            description='Test audit log',
            target_id=str(self.user.id)
        )
        
        self.assertIsNotNone(audit_log)
        self.assertEqual(audit_log.user, self.user)
        self.assertEqual(audit_log.action_type, 'CREATE')
    
    def test_security_event_logging(self):
        """Test security event logging"""
        # Create security event
        security_event = AuditService.log_security_event(
            event_type='FAILED_LOGIN',
            description='Test security event',
            user=self.user,
            severity='HIGH'
        )
        
        self.assertIsNotNone(security_event)
        self.assertEqual(security_event.user, self.user)
        self.assertEqual(security_event.event_type, 'FAILED_LOGIN')
        self.assertEqual(security_event.severity, 'HIGH')


class RateLimitTests(TestCase):
    """Test cases for rate limiting"""
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
    
    @patch('registration.middleware.RateLimitService.check_rate_limit')
    def test_rate_limiting_middleware(self, mock_check_rate_limit):
        """Test rate limiting middleware"""
        # Mock rate limit check to return allowed
        mock_check_rate_limit.return_value = (True, "Request allowed")
        
        response = self.client.get('/api/auth/register/')
        # Should not be rate limited
        self.assertNotEqual(response.status_code, 429)
        
        # Mock rate limit check to return blocked
        mock_check_rate_limit.return_value = (False, "Rate limit exceeded")
        
        response = self.client.get('/api/auth/register/')
        # Should be rate limited
        self.assertEqual(response.status_code, 429)
    
    def test_rate_limit_headers(self):
        """Test rate limit headers in response"""
        with patch('registration.middleware.RateLimitService.check_rate_limit') as mock_check:
            mock_check.return_value = (True, "Request allowed")
            
            # Mock rate limit info
            with patch('registration.middleware.RateLimitService.get_rate_limit_info') as mock_info:
                mock_info.return_value = {
                    'limit': 5,
                    'remaining': 4,
                    'reset_time': 1234567890
                }
                
                response = self.client.get('/api/auth/register/')
                
                # Check if headers are present
                self.assertIn('X-RateLimit-Limit', response)
                self.assertIn('X-RateLimit-Remaining', response)
                self.assertIn('X-RateLimit-Reset', response)


class ValidationTests(TestCase):
    """Test cases for enhanced validation logic"""
    
    def setUp(self):
        """Set up test data"""
        self.encryption_service = EncryptionService()
        self.validation_service = ValidationService()
    
    def test_ssn_duplicate_prevention(self):
        """Test SSN duplicate prevention"""
        # Create first user with SSN
        user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='TestPass123!',
            first_name='User',
            last_name='One',
            phone_number='+1234567890',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted=self.encryption_service.encrypt_ssn('123-45-6789'),
            address_encrypted='encrypted_address'
        )
        
        # Try to create second user with same SSN
        user2_data = {
            'username': 'user2',
            'email': 'user2@example.com',
            'password': 'TestPass123!',
            'confirm_password': 'TestPass123!',
            'first_name': 'User',
            'last_name': 'Two',
            'phone_number': '+1234567891',
            'date_of_birth': '1990-01-01',
            'ssn': '123-45-6789',  # Same SSN
            'address': '123 Test St'
        }
        
        serializer = UserRegistrationSerializer(data=user2_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('ssn', serializer.errors)
        self.assertIn('already exists', str(serializer.errors['ssn']))
    
    def test_enhanced_validation_messages(self):
        """Test enhanced validation error messages"""
        # Test invalid email format
        data = {
            'username': 'testuser',
            'email': 'invalid-email',
            'password': 'TestPass123!',
            'confirm_password': 'TestPass123!',
            'first_name': 'Test',
            'last_name': 'User',
            'phone_number': '+1234567890',
            'date_of_birth': '1990-01-01',
            'ssn': '123-45-6789',
            'address': '123 Test St'
        }
        
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertIn('valid email', str(serializer.errors['email']))
        
        # Test weak password
        data['email'] = 'test@example.com'
        data['password'] = 'weak'
        data['confirm_password'] = 'weak'
        
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
        self.assertIn('uppercase', str(serializer.errors['password']))
    
    def test_kyc_document_validation(self):
        """Test KYC document validation"""
        user = User.objects.create_user(
            username='kycuser',
            email='kyc@example.com',
            password='TestPass123!',
            first_name='KYC',
            last_name='User',
            phone_number='+1234567890',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn',
            address_encrypted='encrypted_address'
        )
        
        # Mock request context
        class MockRequest:
            def __init__(self, user):
                self.user = user
                self.META = {'REMOTE_ADDR': '127.0.0.1'}
        
        mock_request = MockRequest(user)
        
        # Test invalid file type
        invalid_data = {
            'document_type': 'GOVERNMENT_ID',
            'document_number': 'ABC123456',
            'document_file': SimpleUploadedFile(
                "test.txt",
                b"test content",
                content_type="text/plain"
            )
        }
        
        serializer = KYCDocumentSerializer(
            data=invalid_data,
            context={'request': mock_request}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('document_file', serializer.errors)
        self.assertIn('not supported', str(serializer.errors['document_file']))
        
        # Test duplicate document type
        KYCDocument.objects.create(
            user=user,
            document_type='GOVERNMENT_ID',
            document_number='EXISTING123',
            document_file_path='test_path',
            file_hash='test_hash',
            file_size=1024
        )
        
        valid_data = {
            'document_type': 'GOVERNMENT_ID',  # Duplicate type
            'document_number': 'NEW123456',
            'document_file': SimpleUploadedFile(
                "test.pdf",
                b"test content",
                content_type="application/pdf"
            )
        }
        
        serializer = KYCDocumentSerializer(
            data=valid_data,
            context={'request': mock_request}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('document_type', serializer.errors)
        self.assertIn('already uploaded', str(serializer.errors['document_type']))
    
    def test_document_number_duplicate_prevention(self):
        """Test document number duplicate prevention across users"""
        user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='TestPass123!',
            first_name='User',
            last_name='One',
            phone_number='+1234567890',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn1',
            address_encrypted='encrypted_address1'
        )
        
        user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='TestPass123!',
            first_name='User',
            last_name='Two',
            phone_number='+1234567891',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn2',
            address_encrypted='encrypted_address2'
        )
        
        # Create KYC document for user1
        KYCDocument.objects.create(
            user=user1,
            document_type='PASSPORT',
            document_number='DOC123456',
            document_file_path='test_path',
            file_hash='test_hash',
            file_size=1024,
            verification_status='PENDING'
        )
        
        # Try to create KYC document for user2 with same document number
        class MockRequest:
            def __init__(self, user):
                self.user = user
                self.META = {'REMOTE_ADDR': '127.0.0.1'}
        
        mock_request = MockRequest(user2)
        
        duplicate_data = {
            'document_type': 'GOVERNMENT_ID',
            'document_number': 'DOC123456',  # Same document number
            'document_file': SimpleUploadedFile(
                "test.pdf",
                b"test content",
                content_type="application/pdf"
            )
        }
        
        serializer = KYCDocumentSerializer(
            data=duplicate_data,
            context={'request': mock_request}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('document_number', serializer.errors)
        self.assertIn('already been used', str(serializer.errors['document_number']))


class RateLimitDisabledTests(TestCase):
    """Test cases for rate limiting being disabled"""
    
    def setUp(self):
        """Set up test data"""
        self.client = APIClient()
    
    def test_rate_limiting_disabled(self):
        """Test that rate limiting is disabled"""
        # Make multiple rapid requests to registration endpoint
        for i in range(10):
            data = {
                'username': f'rate_test_{i}',
                'email': f'rate_test_{i}@example.com',
                'password': 'TestPass123!',
                'confirm_password': 'TestPass123!',
                'first_name': 'Rate',
                'last_name': 'Test',
                'phone_number': f'+123456789{i}',
                'date_of_birth': '1990-01-01',
                'ssn': f'123-45-678{i}',
                'address': '123 Test St'
            }
            
            response = self.client.post('/api/auth/register/', data)
            
            # Should not get rate limited (429 status)
            self.assertNotEqual(response.status_code, 429, 
                              f"Rate limiting is still enabled! Got 429 on request {i+1}")
            
            # Should get either success (201) or validation error (400)
            self.assertIn(response.status_code, [201, 400], 
                         f"Unexpected status code {response.status_code} on request {i+1}")
    
    def test_login_rate_limiting_disabled(self):
        """Test that login rate limiting is disabled"""
        # Make multiple rapid login requests with invalid credentials
        for i in range(10):
            data = {
                'username': 'nonexistent_user',
                'password': 'wrong_password'
            }
            
            response = self.client.post('/api/auth/login/', data)
            
            # Should not get rate limited (429 status)
            self.assertNotEqual(response.status_code, 429, 
                              f"Login rate limiting is still enabled! Got 429 on request {i+1}")
            
            # Should get authentication error (401) or validation error (400)
            self.assertIn(response.status_code, [401, 400], 
                         f"Unexpected status code {response.status_code} on request {i+1}")


class CeleryTaskTests(TestCase):
    """Test cases for Celery tasks"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePass123',
            first_name='Test',
            last_name='User',
            phone_number='+1234567890',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn',
            address_encrypted='encrypted_address'
        )
    
    @patch('registration.tasks.send_mail')
    def test_notify_admin_new_registration(self, mock_send_mail):
        """Test admin notification for new registration"""
        from registration.tasks import notify_admin_new_registration
        
        # Create admin role and user
        admin_role = Role.objects.create(
            name='BANK_ADMIN',
            description='Bank Administrator'
        )
        
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='SecurePass123',
            first_name='Admin',
            last_name='User',
            phone_number='+1234567891',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn_admin',
            address_encrypted='encrypted_address_admin'
        )
        
        UserRole.objects.create(
            user=admin_user,
            role=admin_role,
            is_active=True
        )
        
        # Run task
        notify_admin_new_registration(self.user.id)
        
        # Verify email was sent
        mock_send_mail.assert_called_once()
    
    @patch('registration.tasks.send_mail')
    def test_send_kyc_approval_email(self, mock_send_mail):
        """Test KYC approval email"""
        from registration.tasks import send_kyc_approval_email
        
        # Run task for approval
        send_kyc_approval_email(self.user.id, True)
        
        # Verify email was sent
        mock_send_mail.assert_called_once()
        
        # Check email content
        call_args = mock_send_mail.call_args
        self.assertIn('approved', call_args[1]['subject'].lower())
    
    def test_cleanup_expired_data(self):
        """Test cleanup of expired data"""
        from registration.tasks import cleanup_expired_data
        
        # Create expired rate limit data
        from registration.models import RateLimit
        from django.utils import timezone
        
        expired_rate_limit = RateLimit.objects.create(
            identifier='test_identifier',
            endpoint='/test/',
            request_count=5,
            window_start=timezone.now() - timedelta(hours=2),
            window_end=timezone.now() - timedelta(hours=1)
        )
        
        # Run cleanup task
        cleanup_expired_data()
        
        # Verify expired data was cleaned up
        self.assertFalse(RateLimit.objects.filter(id=expired_rate_limit.id).exists())


# Test configuration
class TestConfig:
    """Test configuration"""
    
    @staticmethod
    def create_test_user():
        """Create a test user"""
        return User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='SecurePass123',
            first_name='Test',
            last_name='User',
            phone_number='+1234567890',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn',
            address_encrypted='encrypted_address'
        )
    
    @staticmethod
    def create_test_admin():
        """Create a test admin user"""
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='SecurePass123',
            first_name='Admin',
            last_name='User',
            phone_number='+1234567891',
            date_of_birth=date(1990, 1, 1),
            ssn_encrypted='encrypted_ssn_admin',
            address_encrypted='encrypted_address_admin',
            is_staff=True
        )
        
        admin_role = Role.objects.create(
            name='BANK_ADMIN',
            description='Bank Administrator',
            permissions=['view_all_users', 'approve_kyc']
        )
        
        UserRole.objects.create(
            user=admin_user,
            role=admin_role,
            is_active=True
        )
        
        return admin_user
