"""
Serializers for registration app
"""
import logging
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User, Role, UserRole, KYCDocument, AuditLog, SecurityEvent, Notification
from .utils import ValidationService, EncryptionService, SecurityService

logger = logging.getLogger(__name__)


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration with comprehensive validation"""
    
    confirm_password = serializers.CharField(
        write_only=True,
        min_length=8,
        error_messages={
            'min_length': 'Password must be at least 8 characters long.',
            'blank': 'Password confirmation is required.',
        }
    )
    ssn = serializers.CharField(
        write_only=True,
        min_length=9,
        max_length=11,
        error_messages={
            'min_length': 'SSN must be at least 9 digits.',
            'max_length': 'SSN cannot exceed 11 characters (including dashes).',
            'blank': 'SSN is required.',
        }
    )
    address = serializers.CharField(
        write_only=True,
        min_length=10,
        max_length=200,
        error_messages={
            'min_length': 'Address must be at least 10 characters long.',
            'max_length': 'Address cannot exceed 200 characters.',
            'blank': 'Address is required.',
        }
    )
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'password', 'confirm_password',
            'first_name', 'last_name', 'phone_number', 'date_of_birth',
            'ssn', 'address'
        ]
        extra_kwargs = {
            'username': {
                'min_length': 3,
                'max_length': 30,
                'error_messages': {
                    'min_length': 'Username must be at least 3 characters long.',
                    'max_length': 'Username cannot exceed 30 characters.',
                    'blank': 'Username is required.',
                    'invalid': 'Username can only contain letters, numbers, and underscores.',
                }
            },
            'email': {
                'error_messages': {
                    'blank': 'Email address is required.',
                    'invalid': 'Please enter a valid email address.',
                }
            },
            'password': {
                'write_only': True,
                'min_length': 8,
                'error_messages': {
                    'min_length': 'Password must be at least 8 characters long.',
                    'blank': 'Password is required.',
                }
            },
            'first_name': {
                'min_length': 2,
                'max_length': 30,
                'error_messages': {
                    'min_length': 'First name must be at least 2 characters long.',
                    'max_length': 'First name cannot exceed 30 characters.',
                    'blank': 'First name is required.',
                }
            },
            'last_name': {
                'min_length': 2,
                'max_length': 30,
                'error_messages': {
                    'min_length': 'Last name must be at least 2 characters long.',
                    'max_length': 'Last name cannot exceed 30 characters.',
                    'blank': 'Last name is required.',
                }
            },
            'phone_number': {
                'min_length': 10,
                'max_length': 15,
                'error_messages': {
                    'min_length': 'Phone number must be at least 10 digits.',
                    'max_length': 'Phone number cannot exceed 15 characters.',
                    'blank': 'Phone number is required.',
                }
            },
            'date_of_birth': {
                'input_formats': ['%Y-%m-%d'],
                'error_messages': {
                    'blank': 'Date of birth is required.',
                    'invalid': 'Please enter date in YYYY-MM-DD format.',
                }
            }
        }
    
    def validate_username(self, value):
        """Validate username format"""
        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise serializers.ValidationError(
                "Username can only contain letters, numbers, and underscores."
            )
        if value.startswith('_') or value.endswith('_'):
            raise serializers.ValidationError(
                "Username cannot start or end with an underscore."
            )
        return value
    
    def validate_ssn(self, value):
        """Validate SSN format"""
        import re
        # Remove dashes and spaces
        clean_ssn = re.sub(r'[-\s]', '', value)
        
        # Check if it's all digits
        if not clean_ssn.isdigit():
            raise serializers.ValidationError(
                "SSN must contain only numbers and optional dashes."
            )
        
        # Check length
        if len(clean_ssn) != 9:
            raise serializers.ValidationError(
                "SSN must be exactly 9 digits."
            )
        
        # Check for invalid SSNs
        invalid_ssns = ['000000000', '111111111', '222222222', '333333333',
                       '444444444', '555555555', '666666666', '777777777',
                       '888888888', '999999999', '123456789']
        
        if clean_ssn in invalid_ssns:
            raise serializers.ValidationError(
                "This SSN is not valid. Please check and try again."
            )
        
        return value
    
    def validate_phone_number(self, value):
        """Validate phone number format"""
        import re
        # Remove all non-digit characters
        clean_phone = re.sub(r'[^\d]', '', value)
        
        # Check if it's a valid length
        if len(clean_phone) < 10 or len(clean_phone) > 15:
            raise serializers.ValidationError(
                "Phone number must be between 10 and 15 digits."
            )
        
        # Check for common invalid patterns
        if clean_phone.startswith('000') or clean_phone.startswith('111'):
            raise serializers.ValidationError(
                "Please enter a valid phone number."
            )
        
        return value
    
    def validate_date_of_birth(self, value):
        """Validate date of birth"""
        from datetime import date, timedelta
        
        # Check if date is not in the future
        if value > date.today():
            raise serializers.ValidationError(
                "Date of birth cannot be in the future."
            )
        
        # Check if person is at least 18 years old
        min_age_date = date.today() - timedelta(days=18*365)
        if value > min_age_date:
            raise serializers.ValidationError(
                "You must be at least 18 years old to register."
            )
        
        # Check if person is not too old (reasonable limit)
        max_age_date = date.today() - timedelta(days=120*365)
        if value < max_age_date:
            raise serializers.ValidationError(
                "Please enter a valid date of birth."
            )
        
        return value
    
    def validate(self, attrs):
        """Validate registration data"""
        errors = {}
        
        # Check password confirmation
        if attrs['password'] != attrs['confirm_password']:
            errors['confirm_password'] = "Password fields didn't match."
        
        # Validate password strength
        try:
            ValidationService.validate_password_strength(attrs['password'])
        except ValidationError as e:
            errors['password'] = str(e)
        
        # Check for duplicate email
        if User.objects.filter(email=attrs['email']).exists():
            errors['email'] = "A user with this email address already exists."
        
        # Check for duplicate phone
        if User.objects.filter(phone_number=attrs['phone_number']).exists():
            errors['phone_number'] = "A user with this phone number already exists."
        
        # Check for duplicate SSN
        try:
            encryption_service = EncryptionService()
            if encryption_service.check_duplicate_ssn(attrs['ssn']):
                errors['ssn'] = "A user with this Social Security Number already exists. Please check your SSN or contact support if you believe this is an error."
        except Exception as e:
            logger.error(f"SSN duplicate check error: {e}")
            errors['ssn'] = "Unable to verify SSN at this time. Please try again later or contact support."
        
        if errors:
            raise serializers.ValidationError(errors)
        
        return attrs
    
    def create(self, validated_data):
        """Create new user with encrypted data"""
        # Remove confirm_password and sensitive fields
        validated_data.pop('confirm_password')
        ssn = validated_data.pop('ssn')
        address = validated_data.pop('address')
        
        # Encrypt sensitive data
        encryption_service = EncryptionService()
        validated_data['ssn_encrypted'] = encryption_service.encrypt_ssn(ssn)
        validated_data['address_encrypted'] = encryption_service.encrypt_address(address)
        
        # Create user
        user = User.objects.create_user(**validated_data)
        
        # Assign default customer role
        from .utils import assign_default_role
        assign_default_role(user)
        
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate login credentials"""
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            # Check if user exists
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid username or password.")
            
            # Check if account is locked
            if user.is_account_locked():
                raise serializers.ValidationError("Account is temporarily locked due to too many failed login attempts.")
            
            # Authenticate user
            user = authenticate(username=username, password=password)
            if not user:
                # Increment failed login attempts
                user = User.objects.get(username=username)
                user.increment_failed_login()
                
                # Log security event
                from .utils import AuditService
                AuditService.log_security_event(
                    event_type='FAILED_LOGIN',
                    description=f"Failed login attempt for user {username}",
                    user=user,
                    request=self.context.get('request'),
                    severity='MEDIUM'
                )
                
                raise serializers.ValidationError("Invalid username or password.")
            
            # Reset failed login attempts on successful login
            user.reset_failed_login()
            
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError("Must include username and password.")


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile"""
    
    roles = serializers.SerializerMethodField()
    kyc_documents_count = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'phone_number', 'date_of_birth', 'customer_id', 'kyc_status',
            'risk_profile', 'is_account_verified', 'two_factor_enabled',
            'roles', 'kyc_documents_count', 'created_at', 'last_login'
        ]
        read_only_fields = [
            'id', 'customer_id', 'kyc_status', 'risk_profile',
            'is_account_verified', 'created_at', 'last_login'
        ]
    
    def get_roles(self, obj):
        """Get user roles"""
        return [
            {
                'id': role.role.id,
                'name': role.role.name,
                'description': role.role.description
            }
            for role in obj.user_roles.filter(is_active=True)
        ]
    
    def get_kyc_documents_count(self, obj):
        """Get count of KYC documents"""
        return obj.kyc_documents.count()
    
    def validate_phone_number(self, value):
        """Validate phone number"""
        ValidationService.validate_phone_number(value)
        return value


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile (limited fields)"""
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone_number']
    
    def validate_phone_number(self, value):
        """Validate phone number"""
        ValidationService.validate_phone_number(value)
        return value


class KYCDocumentSerializer(serializers.ModelSerializer):
    """Serializer for KYC document upload with comprehensive validation"""
    
    document_file = serializers.FileField(
        write_only=True,
        error_messages={
            'required': 'Please select a document to upload.',
            'invalid': 'Invalid file format. Please upload a valid document.',
            'empty': 'The uploaded file is empty. Please select a valid file.',
        }
    )
    file_name = serializers.CharField(read_only=True)
    file_size = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = KYCDocument
        fields = [
            'id', 'document_type', 'document_number', 'document_file',
            'file_name', 'file_size', 'upload_date', 'verification_status',
            'validation_score'
        ]
        read_only_fields = [
            'id', 'file_name', 'file_size', 'upload_date',
            'verification_status', 'validation_score'
        ]
        extra_kwargs = {
            'document_type': {
                'error_messages': {
                    'required': 'Please select a document type.',
                    'invalid_choice': 'Please select a valid document type.',
                }
            },
            'document_number': {
                'min_length': 3,
                'max_length': 50,
                'error_messages': {
                    'min_length': 'Document number must be at least 3 characters long.',
                    'max_length': 'Document number cannot exceed 50 characters.',
                    'required': 'Document number is required.',
                    'blank': 'Document number cannot be empty.',
                }
            }
        }
    
    def validate_document_file(self, value):
        """Validate uploaded file with detailed error messages"""
        import os
        
        # Check if file is empty
        if value.size == 0:
            raise serializers.ValidationError(
                "The uploaded file is empty. Please select a valid file."
            )
        
        # Check file extension
        file_extension = os.path.splitext(value.name)[1].lower()
        allowed_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.doc', '.docx']
        
        if file_extension not in allowed_extensions:
            raise serializers.ValidationError(
                f"File type '{file_extension}' is not supported. "
                f"Please upload one of the following: {', '.join(allowed_extensions)}"
            )
        
        # Check file size (10MB limit)
        max_size = 10 * 1024 * 1024  # 10MB
        if value.size > max_size:
            size_mb = value.size / (1024 * 1024)
            raise serializers.ValidationError(
                f"File size ({size_mb:.1f}MB) exceeds the maximum limit of 10MB. "
                f"Please upload a smaller file."
            )
        
        # Check for suspicious file names
        suspicious_patterns = ['..', '/', '\\', '<', '>', ':', '"', '|', '?', '*']
        if any(pattern in value.name for pattern in suspicious_patterns):
            raise serializers.ValidationError(
                "File name contains invalid characters. Please rename your file."
            )
        
        return value
    
    def validate_document_number(self, value):
        """Validate document number with format checking"""
        import re
        
        if not value or len(value.strip()) == 0:
            raise serializers.ValidationError("Document number is required.")
        
        value = value.strip()
        
        # Check for minimum length
        if len(value) < 3:
            raise serializers.ValidationError(
                "Document number must be at least 3 characters long."
            )
        
        # Check for maximum length
        if len(value) > 50:
            raise serializers.ValidationError(
                "Document number cannot exceed 50 characters."
            )
        
        # Check for invalid characters (only alphanumeric, spaces, hyphens, and underscores allowed)
        if not re.match(r'^[a-zA-Z0-9\s\-_]+$', value):
            raise serializers.ValidationError(
                "Document number can only contain letters, numbers, spaces, hyphens, and underscores."
            )
        
        # Check for common invalid patterns
        invalid_patterns = ['000000', '111111', '123456', 'abcdef', 'test', 'sample']
        if value.lower() in invalid_patterns:
            raise serializers.ValidationError(
                "Please enter a valid document number."
            )
        
        return value
    
    def validate_document_type(self, value):
        """Validate document type"""
        valid_types = ['GOVERNMENT_ID', 'PASSPORT', 'DRIVER_LICENSE', 'UTILITY_BILL', 'BANK_STATEMENT']
        
        if value not in valid_types:
            raise serializers.ValidationError(
                f"Invalid document type. Please select one of: {', '.join(valid_types)}"
            )
        
        return value
    
    def validate(self, attrs):
        """Validate KYC document data"""
        errors = {}
        
        # Check for duplicate document type for the same user
        user = self.context['request'].user
        document_type = attrs.get('document_type')
        
        if document_type:
            existing_doc = KYCDocument.objects.filter(
                user=user,
                document_type=document_type,
                verification_status__in=['PENDING', 'APPROVED']
            ).first()
            
            if existing_doc:
                doc_type_display = document_type.replace('_', ' ').title()
                errors['document_type'] = (
                    f"You have already uploaded a {doc_type_display} document. "
                    f"Document ID: {existing_doc.id}, Status: {existing_doc.verification_status}. "
                    f"Please select a different document type or contact support if you need to replace it."
                )
        
        # Check for duplicate document number
        document_number = attrs.get('document_number')
        if document_number:
            existing_doc_number = KYCDocument.objects.filter(
                document_number=document_number,
                verification_status__in=['PENDING', 'VERIFIED']
            ).exclude(user=user).exists()
            
            if existing_doc_number:
                errors['document_number'] = (
                    f"Document number '{document_number}' has already been used by another user. "
                    f"Please verify your document number or contact support if you believe this is an error."
                )
        
        # Check user's KYC status
        if user.kyc_status not in ['INCOMPLETE', 'PENDING', 'REJECTED']:
            errors['non_field_errors'] = [
                "KYC documents can only be uploaded for incomplete, pending, or rejected applications. "
                f"Your current status is: {user.kyc_status}. Please contact support if you need assistance."
            ]
        
        if errors:
            raise serializers.ValidationError(errors)
        
        return attrs
    
    def create(self, validated_data):
        """Create KYC document with encryption"""
        user = self.context['request'].user
        document_file = validated_data.pop('document_file')
        
        try:
            # Read file content once and store it
            file_content = document_file.read()
            
            # Reset file pointer for potential future reads
            document_file.seek(0)
            
            # Encrypt file content
            encryption_service = EncryptionService()
            encrypted_content = encryption_service.encrypt_document(file_content)
            
            # Calculate file hash
            file_hash = SecurityService.calculate_file_hash(file_content)
            
            # Generate secure file path
            import os
            import uuid
            file_extension = os.path.splitext(document_file.name)[1]
            secure_filename = f"{uuid.uuid4()}{file_extension}"
            file_path = os.path.join('kyc_documents', secure_filename)
            
            # Save encrypted file
            from django.core.files.storage import default_storage
            from django.core.files.base import ContentFile
            
            # Convert encrypted bytes to a file-like object
            encrypted_file = ContentFile(encrypted_content)
            default_storage.save(file_path, encrypted_file)
            
        except Exception as e:
            logger.error(f"KYC document processing error: {e}")
            raise serializers.ValidationError(f"Failed to process document: {str(e)}")
        
        # Create KYC document record
        kyc_document = KYCDocument.objects.create(
            user=user,
            document_type=validated_data['document_type'],
            document_number=validated_data['document_number'],
            document_file_path=file_path,
            file_hash=file_hash,
            file_size=document_file.size
        )
        
        # Log audit event
        from .utils import AuditService
        AuditService.log_action(
            user=user,
            action_type='DOCUMENT_UPLOAD',
            target_model='KYCDocument',
            description=f"Uploaded {validated_data['document_type']} document",
            request=self.context['request'],
            target_id=str(kyc_document.id)
        )
        
        return kyc_document


class KYCDocumentListSerializer(serializers.ModelSerializer):
    """Serializer for listing KYC documents"""
    
    class Meta:
        model = KYCDocument
        fields = [
            'id', 'document_type', 'document_number', 'upload_date',
            'verification_status', 'validation_score', 'rejection_reason'
        ]


class AdminKYCDocumentSerializer(serializers.ModelSerializer):
    """Serializer for admin KYC document review"""
    
    user = serializers.SerializerMethodField()
    
    class Meta:
        model = KYCDocument
        fields = [
            'id', 'user', 'document_type', 'document_number',
            'upload_date', 'verification_status', 'validation_score',
            'rejection_reason', 'ocr_text'
        ]
    
    def get_user(self, obj):
        """Get user information"""
        return {
            'id': obj.user.id,
            'username': obj.user.username,
            'customer_id': obj.user.customer_id,
            'kyc_status': obj.user.kyc_status
        }


class AdminKYCReviewSerializer(serializers.Serializer):
    """Serializer for admin KYC review"""
    
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    rejection_reason = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        """Validate review action"""
        if attrs['action'] == 'reject' and not attrs.get('rejection_reason'):
            raise serializers.ValidationError("Rejection reason is required when rejecting KYC.")
        return attrs


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for audit logs"""
    
    user = serializers.SerializerMethodField()
    
    class Meta:
        model = AuditLog
        fields = [
            'log_id', 'user', 'action_type', 'target_model',
            'description', 'ip_address', 'timestamp'
        ]
    
    def get_user(self, obj):
        """Get user information"""
        if obj.user:
            return {
                'id': obj.user.id,
                'username': obj.user.username,
                'customer_id': obj.user.customer_id
            }
        return None


class SecurityEventSerializer(serializers.ModelSerializer):
    """Serializer for security events"""
    
    user = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityEvent
        fields = [
            'id', 'event_type', 'user', 'severity', 'description',
            'metadata', 'resolved', 'created_at'
        ]
    
    def get_user(self, obj):
        """Get user information"""
        if obj.user:
            return {
                'id': obj.user.id,
                'username': obj.user.username,
                'customer_id': obj.user.customer_id
            }
        return None


class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for notifications"""
    
    class Meta:
        model = Notification
        fields = [
            'id', 'notification_type', 'title', 'message',
            'priority', 'is_read', 'created_at'
        ]


class UserListSerializer(serializers.ModelSerializer):
    """Serializer for listing users (admin only)"""
    
    roles = serializers.SerializerMethodField()
    kyc_documents_count = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'customer_id', 'kyc_status', 'risk_profile',
            'is_account_verified', 'roles', 'kyc_documents_count',
            'created_at', 'last_login'
        ]
    
    def get_roles(self, obj):
        """Get user roles"""
        return [
            {
                'id': role.role.id,
                'name': role.role.name,
                'description': role.role.description
            }
            for role in obj.user_roles.filter(is_active=True)
        ]
    
    def get_kyc_documents_count(self, obj):
        """Get count of KYC documents"""
        return obj.kyc_documents.count()


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change"""
    
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate password change"""
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("New password fields didn't match.")
        
        # Validate new password strength
        ValidationService.validate_password_strength(attrs['new_password'])
        
        return attrs
    
    def validate_old_password(self, value):
        """Validate old password"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value
