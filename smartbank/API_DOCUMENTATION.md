# SmartBank API Documentation

## 📚 **API Documentation Endpoints**

The SmartBank API provides comprehensive interactive documentation through multiple interfaces:

### **🔗 Documentation URLs**

| Endpoint | Description | URL |
|----------|-------------|-----|
| **Swagger UI** | Interactive API documentation with "Try it out" functionality | `http://localhost:8000/api/docs/` |
| **ReDoc** | Clean, responsive API documentation | `http://localhost:8000/api/redoc/` |
| **OpenAPI Schema** | Raw OpenAPI 3.0 schema (JSON) | `http://localhost:8000/api/schema/` |

### **🎯 Key Features**

#### **Swagger UI (`/api/docs/`)**
- **Interactive Testing**: Test API endpoints directly from the browser
- **Authentication**: Built-in JWT token authentication
- **Request/Response Examples**: Pre-filled examples for all endpoints
- **Schema Validation**: Real-time validation of request data
- **Download Schema**: Export OpenAPI schema for external tools

#### **ReDoc (`/api/redoc/`)**
- **Clean Interface**: Professional, readable documentation
- **Search Functionality**: Quick search across all endpoints
- **Mobile Responsive**: Works on all device sizes
- **Print Friendly**: Optimized for printing and PDF generation

### **📋 API Endpoint Categories**

#### **🔐 Authentication**
- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login (JWT tokens)
- `POST /api/auth/token/refresh/` - Refresh JWT token
- `POST /api/auth/password/change/` - Change password

#### **👤 User Profile**
- `GET /api/profile/` - Get user profile
- `PUT /api/profile/` - Update user profile

#### **📄 KYC Documents**
- `POST /api/kyc/upload/` - Upload KYC document
- `GET /api/kyc/documents/` - List user's KYC documents

#### **👨‍💼 Admin Functions**
- `GET /api/admin/users/` - List all users
- `GET /api/admin/kyc/documents/` - List all KYC documents
- `POST /api/admin/kyc/review/<user_id>/` - Review KYC application
- `GET /api/admin/audit-logs/` - View audit logs
- `GET /api/admin/security-events/` - View security events
- `GET /api/admin/notifications/` - View notifications
- `GET /api/admin/dashboard/stats/` - Dashboard statistics

### **🔑 Authentication in Documentation**

#### **JWT Token Authentication**
1. **Login**: Use `/api/auth/login/` to get access and refresh tokens
2. **Authorize**: Click "Authorize" button in Swagger UI
3. **Enter Token**: Paste your access token in format: `Bearer <your_token>`
4. **Test Endpoints**: All protected endpoints will now work

#### **Token Format**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### **📊 API Documentation Features**

#### **Comprehensive Examples**
- **Registration**: Complete user registration example with all fields
- **Login**: Authentication example with credentials
- **KYC Upload**: File upload example with document types
- **Admin Actions**: KYC review and user management examples

#### **Security Information**
- **Rate Limiting**: Documented limits for each endpoint
- **Encryption**: Details about data encryption (SSN, Address, Documents)
- **Audit Logging**: Information about audit trail
- **Error Handling**: Comprehensive error response documentation

#### **Data Models**
- **User Model**: Complete user schema with encrypted fields
- **KYC Document**: Document metadata and file information
- **Audit Log**: Security and action logging schema
- **Security Event**: Security incident tracking schema

### **🚀 Getting Started with API Documentation**

#### **1. Install Dependencies**
```bash
pip install -r requirements.txt
```

#### **2. Run Migrations**
```bash
python manage.py migrate
```

#### **3. Start Development Server**
```bash
python manage.py runserver
```

#### **4. Access Documentation**
- **Swagger UI**: http://localhost:8000/api/docs/
- **ReDoc**: http://localhost:8000/api/redoc/

#### **5. Test API Endpoints**
1. Open Swagger UI
2. Register a new user using `/api/auth/register/`
3. Login using `/api/auth/login/`
4. Copy the access token
5. Click "Authorize" and paste: `Bearer <your_token>`
6. Test protected endpoints

### **📝 API Documentation Best Practices**

#### **For Developers**
- **Always check documentation** before implementing API calls
- **Use examples** provided in Swagger UI
- **Test endpoints** using the interactive interface
- **Handle errors** according to documented response formats

#### **For API Consumers**
- **Start with registration** and login endpoints
- **Store JWT tokens** securely for authenticated requests
- **Follow rate limits** to avoid 429 errors
- **Upload KYC documents** in correct formats (PDF, JPG, PNG)

### **🔧 Customization**

#### **Adding New Endpoints**
1. Add `@extend_schema` decorator to views
2. Include proper tags, summaries, and examples
3. Update this documentation file
4. Test in Swagger UI

#### **Modifying Documentation**
- **Settings**: Update `SPECTACULAR_SETTINGS` in `settings.py`
- **Examples**: Add more examples in view decorators
- **Tags**: Organize endpoints with custom tags
- **Descriptions**: Enhance endpoint descriptions

### **📱 Mobile and External Integration**

#### **OpenAPI Schema Export**
```bash
# Get raw OpenAPI schema
curl http://localhost:8000/api/schema/ > smartbank-api.json

# Use with external tools
# - Postman: Import OpenAPI schema
# - Insomnia: Import OpenAPI schema
# - Code Generation: Generate client SDKs
```

#### **API Client Generation**
```bash
# Generate Python client
openapi-generator generate -i http://localhost:8000/api/schema/ -g python -o smartbank-client

# Generate JavaScript client
openapi-generator generate -i http://localhost:8000/api/schema/ -g javascript -o smartbank-js-client
```

### **🛡️ Security in Documentation**

#### **Sensitive Data Handling**
- **No Real Data**: All examples use fake/test data
- **Token Security**: JWT tokens expire automatically
- **Rate Limiting**: Built-in protection against abuse
- **Input Validation**: All inputs validated and sanitized

#### **Production Considerations**
- **HTTPS Only**: Use HTTPS in production
- **Token Rotation**: Implement token refresh logic
- **Monitoring**: Monitor API usage and errors
- **Backup**: Regular backup of audit logs and user data

---

## **🎉 Ready to Use!**

Your SmartBank API now has comprehensive, interactive documentation that makes it easy for developers to understand and integrate with your banking system. The documentation includes:

✅ **Interactive Testing** - Test endpoints directly in the browser  
✅ **Authentication Examples** - Complete JWT authentication flow  
✅ **File Upload Support** - KYC document upload with examples  
✅ **Admin Functions** - Complete admin panel API documentation  
✅ **Security Features** - Rate limiting, encryption, and audit logging  
✅ **Error Handling** - Comprehensive error response documentation  
✅ **Mobile Ready** - Responsive design for all devices  

**Start exploring**: http://localhost:8000/api/docs/
