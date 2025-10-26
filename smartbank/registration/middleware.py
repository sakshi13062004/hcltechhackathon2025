"""
Middleware for registration app
"""
import logging
from django.conf import settings
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from .utils import RateLimitService, SecurityService, AuditService

logger = logging.getLogger(__name__)


class RateLimitMiddleware(MiddlewareMixin):
    """Rate limiting middleware"""
    
    def process_request(self, request):
        """Process request for rate limiting"""
        try:
            # Get rate limit configuration
            rate_limit_config = self._get_rate_limit_config(request.path)
            
            if not rate_limit_config:
                return None  # No rate limiting for this endpoint
            
            # Get client identifier
            identifier = self._get_client_identifier(request)
            
            # Check rate limit with error handling
            try:
                allowed, message = RateLimitService.check_rate_limit(
                    identifier, request.path, rate_limit_config
                )
            except Exception as e:
                logger.error(f"Rate limit check failed: {e}")
                # If rate limiting fails, allow the request to proceed
                # This prevents Redis issues from blocking legitimate requests
                allowed = True
                message = "Rate limit check failed, allowing request"
            
            if not allowed:
                # Log security event
                AuditService.log_security_event(
                    event_type='RATE_LIMIT_EXCEEDED',
                    description=f"Rate limit exceeded for {request.path}",
                    request=request,
                    severity='MEDIUM',
                    metadata={
                        'endpoint': request.path,
                        'identifier': identifier,
                        'limit': rate_limit_config['requests'],
                        'window': rate_limit_config['window']
                    }
                )
                
                return JsonResponse({
                    'error': True,
                    'message': message,
                    'retry_after': rate_limit_config['window']
                }, status=429)
            
            # Add rate limit headers to response
            request.rate_limit_info = RateLimitService.get_rate_limit_info(
                identifier, request.path, rate_limit_config
            )
            
            return None
            
        except Exception as e:
            logger.error(f"Rate limit middleware error: {e}")
            # Allow request if rate limiting fails
            return None
    
    def process_response(self, request, response):
        """Add rate limit headers to response"""
        if hasattr(request, 'rate_limit_info'):
            rate_info = request.rate_limit_info
            response['X-RateLimit-Limit'] = rate_info['limit']
            response['X-RateLimit-Remaining'] = rate_info['remaining']
            response['X-RateLimit-Reset'] = rate_info['reset_time']
        
        return response
    
    def _get_rate_limit_config(self, path):
        """Get rate limit configuration for endpoint"""
        rate_limit_settings = settings.RATE_LIMIT_SETTINGS
        
        # Map endpoints to rate limit configurations
        endpoint_mapping = {
            '/api/auth/register/': 'REGISTRATION',
            '/api/auth/login/': 'LOGIN',
            '/api/kyc/upload/': 'KYC_UPLOAD',
        }
        
        # Check for exact match first
        if path in endpoint_mapping:
            config_name = endpoint_mapping[path]
            return rate_limit_settings.get(config_name)
        
        # Check for API endpoints (general rate limiting)
        if path.startswith('/api/'):
            return rate_limit_settings.get('API_GENERAL')
        
        return None
    
    def _get_client_identifier(self, request):
        """Get client identifier for rate limiting"""
        # Try to get authenticated user first
        if hasattr(request, 'user') and request.user.is_authenticated:
            return f"user:{request.user.id}"
        
        # Fall back to IP address
        return f"ip:{SecurityService.get_client_ip(request)}"


class SecurityMiddleware(MiddlewareMixin):
    """Security middleware for additional security measures"""
    
    def process_request(self, request):
        """Process request for security checks"""
        try:
            # Log suspicious patterns
            self._check_suspicious_patterns(request)
            
            # Add security headers
            self._add_security_headers(request)
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
        
        return None
    
    def process_response(self, request, response):
        """Add security headers to response"""
        try:
            # Add security headers
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-Frame-Options'] = 'DENY'
            response['X-XSS-Protection'] = '1; mode=block'
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
            # Remove server header
            if 'Server' in response:
                del response['Server']
            
        except Exception as e:
            logger.error(f"Security middleware response error: {e}")
        
        return response
    
    def _check_suspicious_patterns(self, request):
        """Check for suspicious request patterns"""
        user_agent = SecurityService.get_user_agent(request)
        path = request.path
        
        # Check for suspicious user agents
        suspicious_agents = ['bot', 'crawler', 'spider', 'scraper']
        if any(agent in user_agent.lower() for agent in suspicious_agents):
            AuditService.log_security_event(
                event_type='SUSPICIOUS_ACTIVITY',
                description=f"Suspicious user agent detected: {user_agent}",
                request=request,
                severity='LOW',
                metadata={'user_agent': user_agent, 'path': path}
            )
        
        # Check for suspicious paths
        suspicious_paths = ['admin', 'wp-admin', 'phpmyadmin', 'config']
        if any(susp_path in path.lower() for susp_path in suspicious_paths):
            AuditService.log_security_event(
                event_type='SUSPICIOUS_ACTIVITY',
                description=f"Suspicious path access: {path}",
                request=request,
                severity='MEDIUM',
                metadata={'path': path, 'user_agent': user_agent}
            )
    
    def _add_security_headers(self, request):
        """Add security headers to request"""
        # This method can be used to add security-related headers
        # or perform additional security checks
        pass
