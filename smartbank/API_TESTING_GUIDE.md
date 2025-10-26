# SmartBank API Testing Guide

## 🧪 **Complete API Testing with Sample Payloads**

This guide provides sample request payloads for testing all SmartBank API endpoints.

---

## **🔐 Authentication Endpoints**

### **1. User Registration**
**Endpoint**: `POST /api/auth/register/`  
**Authentication**: None required

```json
{
    "username": "john_doe",
    "email": "john.doe@example.com",
    "password": "SecurePass123!",
    "confirm_password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+1234567890",
    "date_of_birth": "1990-01-15",
    "ssn": "123-45-6789",
    "address": "123 Main Street, New York, NY 10001"
}
```

**Expected Response**:
```json
{
    "message": "User registered successfully",
    "user": {
        "id": 1,
        "username": "john_doe",
        "email": "john.doe@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "customer_id": "CUSTA1B2C3D4E5",
        "kyc_status": "PENDING",
        "risk_profile": "LOW",
        "is_account_verified": false,
        "created_at": "2024-01-15T10:30:00Z"
    }
}
```

### **2. User Login**
**Endpoint**: `POST /api/auth/login/`  
**Authentication**: None required

```json
{
    "username": "john_doe",
    "password": "SecurePass123!"
}
```

**Expected Response**:
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "username": "john_doe",
        "email": "john.doe@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "kyc_status": "PENDING"
    }
}
```

### **3. Token Refresh**
**Endpoint**: `POST /api/auth/token/refresh/`  
**Authentication**: None required

```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Expected Response**:
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### **4. Password Change**
**Endpoint**: `POST /api/auth/password/change/`  
**Authentication**: JWT Required

**Headers**:
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

```json
{
    "old_password": "SecurePass123!",
    "new_password": "NewSecurePass456!",
    "confirm_password": "NewSecurePass456!"
}
```

**Expected Response**:
```json
{
    "message": "Password changed successfully"
}
```

---

## **👤 User Profile Endpoints**

### **5. Get User Profile**
**Endpoint**: `GET /api/profile/`  
**Authentication**: JWT Required

**Headers**:
```
Authorization: Bearer <access_token>
```

**No request body required**

**Expected Response**:
```json
{
    "id": 1,
    "username": "john_doe",
    "email": "john.doe@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+1234567890",
    "date_of_birth": "1990-01-15",
    "customer_id": "CUSTA1B2C3D4E5",
    "kyc_status": "PENDING",
    "risk_profile": "LOW",
    "is_account_verified": false,
    "two_factor_enabled": false,
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
}
```

### **6. Update User Profile**
**Endpoint**: `PUT /api/profile/`  
**Authentication**: JWT Required

**Headers**:
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

```json
{
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+1234567890",
    "address": "456 Updated Street, New York, NY 10002"
}
```

**Expected Response**:
```json
{
    "message": "Profile updated successfully",
    "user": {
        "id": 1,
        "username": "john_doe",
        "email": "john.doe@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "phone_number": "+1234567890",
        "customer_id": "CUSTA1B2C3D4E5",
        "kyc_status": "PENDING",
        "updated_at": "2024-01-15T11:00:00Z"
    }
}
```

---

## **📄 KYC Document Endpoints**

### **7. Upload KYC Document**
**Endpoint**: `POST /api/kyc/upload/`  
**Authentication**: JWT Required

**Headers**:
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Form Data**:
```
document_type: GOVERNMENT_ID
document_number: A1234567
document_file: [FILE] (passport.pdf, driver_license.jpg, etc.)
```

**Available Document Types**:
- `GOVERNMENT_ID`
- `PASSPORT`
- `DRIVER_LICENSE`
- `UTILITY_BILL`
- `BANK_STATEMENT`
- `TAX_DOCUMENT`

**Expected Response**:
```json
{
    "id": 1,
    "document_type": "GOVERNMENT_ID",
    "document_number": "A1234567",
    "file_size": 1024000,
    "upload_date": "2024-01-15T11:30:00Z",
    "verification_status": "PENDING",
    "validation_score": null
}
```

### **8. List KYC Documents**
**Endpoint**: `GET /api/kyc/documents/`  
**Authentication**: JWT Required

**Headers**:
```
Authorization: Bearer <access_token>
```

**Query Parameters** (Optional):
```
?page=1&page_size=10&document_type=GOVERNMENT_ID&status=PENDING
```

**No request body required**

**Expected Response**:
```json
{
    "count": 2,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 1,
            "document_type": "GOVERNMENT_ID",
            "document_number": "A1234567",
            "file_size": 1024000,
            "upload_date": "2024-01-15T11:30:00Z",
            "verification_status": "PENDING",
            "validation_score": 85
        },
        {
            "id": 2,
            "document_type": "PASSPORT",
            "document_number": "P1234567",
            "file_size": 2048000,
            "upload_date": "2024-01-15T12:00:00Z",
            "verification_status": "PENDING",
            "validation_score": 90
        }
    ]
}
```

---

## **👨‍💼 Admin Endpoints**

### **9. List All Users (Admin)**
**Endpoint**: `GET /api/admin/users/`  
**Authentication**: JWT Required (Admin role)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Query Parameters** (Optional):
```
?page=1&page_size=20&kyc_status=PENDING&risk_profile=LOW&search=john
```

**No request body required**

**Expected Response**:
```json
{
    "count": 50,
    "next": "http://localhost:8000/api/admin/users/?page=2",
    "previous": null,
    "results": [
        {
            "id": 1,
            "username": "john_doe",
            "email": "john.doe@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "customer_id": "CUSTA1B2C3D4E5",
            "kyc_status": "PENDING",
            "risk_profile": "LOW",
            "is_account_verified": false,
            "created_at": "2024-01-15T10:30:00Z",
            "last_login": "2024-01-15T11:00:00Z"
        }
    ]
}
```

### **10. List All KYC Documents (Admin)**
**Endpoint**: `GET /api/admin/kyc/documents/`  
**Authentication**: JWT Required (Admin role)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Query Parameters** (Optional):
```
?page=1&page_size=20&verification_status=PENDING&document_type=GOVERNMENT_ID
```

**No request body required**

**Expected Response**:
```json
{
    "count": 25,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 1,
            "user": {
                "id": 1,
                "username": "john_doe",
                "email": "john.doe@example.com",
                "customer_id": "CUSTA1B2C3D4E5"
            },
            "document_type": "GOVERNMENT_ID",
            "document_number": "A1234567",
            "file_size": 1024000,
            "upload_date": "2024-01-15T11:30:00Z",
            "verification_status": "PENDING",
            "validation_score": 85,
            "verified_by": null,
            "verified_at": null
        }
    ]
}
```

### **11. Review KYC Application (Admin)**
**Endpoint**: `POST /api/admin/kyc/review/<user_id>/`  
**Authentication**: JWT Required (Admin role)

**Headers**:
```
Authorization: Bearer <admin_access_token>
Content-Type: application/json
```

**Approve KYC**:
```json
{
    "action": "APPROVE",
    "notes": "All documents verified successfully. Customer meets KYC requirements."
}
```

**Reject KYC**:
```json
{
    "action": "REJECT",
    "notes": "Document quality insufficient. Please resubmit with clearer images.",
    "rejection_reason": "DOCUMENT_QUALITY_POOR"
}
```

**Request Additional Documents**:
```json
{
    "action": "REQUEST_MORE",
    "notes": "Please provide a utility bill as proof of address.",
    "required_documents": ["UTILITY_BILL"]
}
```

**Expected Response (Approve)**:
```json
{
    "message": "KYC application approved successfully",
    "user": {
        "id": 1,
        "username": "john_doe",
        "kyc_status": "APPROVED",
        "is_account_verified": true,
        "kyc_reviewed_by": 2,
        "kyc_reviewed_at": "2024-01-15T14:00:00Z"
    }
}
```

### **12. View Audit Logs (Admin)**
**Endpoint**: `GET /api/admin/audit-logs/`  
**Authentication**: JWT Required (Admin role)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Query Parameters** (Optional):
```
?page=1&page_size=50&action_type=LOGIN&user_id=1&start_date=2024-01-01&end_date=2024-01-31
```

**No request body required**

**Expected Response**:
```json
{
    "count": 100,
    "next": "http://localhost:8000/api/admin/audit-logs/?page=2",
    "previous": null,
    "results": [
        {
            "id": 1,
            "user": {
                "id": 1,
                "username": "john_doe",
                "email": "john.doe@example.com"
            },
            "action_type": "LOGIN",
            "description": "User logged in successfully",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "timestamp": "2024-01-15T11:00:00Z",
            "metadata": {
                "login_method": "password",
                "success": true
            }
        }
    ]
}
```

### **13. View Security Events (Admin)**
**Endpoint**: `GET /api/admin/security-events/`  
**Authentication**: JWT Required (Admin role)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Query Parameters** (Optional):
```
?page=1&page_size=50&severity=HIGH&event_type=FAILED_LOGIN&start_date=2024-01-01
```

**No request body required**

**Expected Response**:
```json
{
    "count": 15,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 1,
            "user": {
                "id": 1,
                "username": "john_doe",
                "email": "john.doe@example.com"
            },
            "event_type": "FAILED_LOGIN",
            "severity": "MEDIUM",
            "description": "Multiple failed login attempts detected",
            "ip_address": "192.168.1.100",
            "timestamp": "2024-01-15T11:05:00Z",
            "metadata": {
                "attempt_count": 3,
                "time_window": "5 minutes"
            }
        }
    ]
}
```

### **14. View Notifications (Admin)**
**Endpoint**: `GET /api/admin/notifications/`  
**Authentication**: JWT Required (Admin role)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**Query Parameters** (Optional):
```
?page=1&page_size=20&notification_type=KYC_REVIEW&is_read=false
```

**No request body required**

**Expected Response**:
```json
{
    "count": 8,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 1,
            "notification_type": "KYC_REVIEW",
            "title": "New KYC Application",
            "message": "john_doe has submitted a new KYC application for review",
            "is_read": false,
            "created_at": "2024-01-15T11:30:00Z",
            "metadata": {
                "user_id": 1,
                "kyc_documents_count": 2
            }
        }
    ]
}
```

### **15. Dashboard Statistics (Admin)**
**Endpoint**: `GET /api/admin/dashboard/stats/`  
**Authentication**: JWT Required (Admin role)

**Headers**:
```
Authorization: Bearer <admin_access_token>
```

**No request body required**

**Expected Response**:
```json
{
    "total_users": 150,
    "pending_kyc": 25,
    "approved_kyc": 120,
    "rejected_kyc": 5,
    "new_registrations_today": 8,
    "kyc_reviews_today": 12,
    "security_events_today": 3,
    "high_risk_users": 2,
    "recent_activity": [
        {
            "type": "NEW_REGISTRATION",
            "user": "jane_smith",
            "timestamp": "2024-01-15T13:45:00Z"
        },
        {
            "type": "KYC_APPROVED",
            "user": "john_doe",
            "timestamp": "2024-01-15T14:00:00Z"
        }
    ]
}
```

---

## **🧪 Testing Workflow**

### **Complete Testing Sequence**

1. **Register User**
   ```bash
   curl -X POST http://localhost:8000/api/auth/register/ \
     -H "Content-Type: application/json" \
     -d '{"username": "test_user", "email": "test@example.com", "password": "TestPass123!", "confirm_password": "TestPass123!", "first_name": "Test", "last_name": "User", "phone_number": "+1234567890", "date_of_birth": "1990-01-01", "ssn": "123-45-6789", "address": "123 Test St"}'
   ```

2. **Login User**
   ```bash
   curl -X POST http://localhost:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"username": "test_user", "password": "TestPass123!"}'
   ```

3. **Get Profile (with token)**
   ```bash
   curl -X GET http://localhost:8000/api/profile/ \
     -H "Authorization: Bearer <access_token>"
   ```

4. **Upload KYC Document**
   ```bash
   curl -X POST http://localhost:8000/api/kyc/upload/ \
     -H "Authorization: Bearer <access_token>" \
     -F "document_type=GOVERNMENT_ID" \
     -F "document_number=A1234567" \
     -F "document_file=@/path/to/document.pdf"
   ```

### **Error Response Examples**

**Validation Error**:
```json
{
    "error": "Validation failed",
    "details": {
        "email": ["This field is required."],
        "password": ["Password must be at least 8 characters long."]
    }
}
```

**Authentication Error**:
```json
{
    "error": "Authentication credentials were not provided."
}
```

**Rate Limit Error**:
```json
{
    "error": "Rate limit exceeded. Try again later.",
    "retry_after": 3600
}
```

**File Upload Error**:
```json
{
    "error": "File too large. Maximum size is 10MB."
}
```

---

## **🔧 Testing Tools**

### **Using Postman**
1. Import the OpenAPI schema from `http://localhost:8000/api/schema/`
2. Set up environment variables for base URL and tokens
3. Use the pre-configured requests

### **Using cURL**
All examples above include cURL commands for command-line testing

### **Using Swagger UI**
1. Go to `http://localhost:8000/api/docs/`
2. Click "Authorize" and enter your JWT token
3. Test endpoints directly in the browser

---

## **📝 Notes**

- **JWT Tokens**: Access tokens expire in 60 minutes, refresh tokens in 7 days
- **Rate Limits**: Respect the rate limits to avoid 429 errors
- **File Uploads**: Maximum file size is 10MB, supported formats: PDF, JPG, PNG, DOC, DOCX
- **Admin Access**: Admin endpoints require users with BANK_ADMIN role
- **Error Handling**: All errors return JSON with appropriate HTTP status codes

**Happy Testing! 🚀**
