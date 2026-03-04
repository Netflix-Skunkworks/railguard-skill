"""
Security middleware and request handlers
Implements various security controls for the application
"""
from fastapi import Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Dict, Any, Optional
import re
import html
import time
import hashlib

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses
    Implements defense-in-depth security controls
    """
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Apply comprehensive security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://api.anime-service.com"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware to prevent abuse
    Tracks requests per IP address
    """
    
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.request_counts = {}
    
    async def dispatch(self, request: Request, call_next):
        # Get client IP
        client_ip = request.client.host
        current_minute = int(time.time() / 60)
        
        # Track request count
        key = f"{client_ip}:{current_minute}"
        self.request_counts[key] = self.request_counts.get(key, 0) + 1
        
        # Check rate limit
        if self.request_counts[key] > self.requests_per_minute:
            return Response(content="Rate limit exceeded", status_code=429)
        
        # Clean old entries
        self._cleanup_old_entries(current_minute)
        
        response = await call_next(request)
        return response
    
    def _cleanup_old_entries(self, current_minute: int):
        """
        Remove rate limit entries older than 2 minutes
        """
        cutoff = current_minute - 2
        keys_to_delete = [k for k in self.request_counts if int(k.split(':')[1]) < cutoff]
        for key in keys_to_delete:
            del self.request_counts[key]

class InputSanitizationMiddleware(BaseHTTPMiddleware):
    """
    Sanitize all incoming request data
    Prevents various injection attacks
    """
    
    async def dispatch(self, request: Request, call_next):
        # Process request body if present
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                if body:
                    # Store sanitized body for later use
                    request.state.sanitized_body = self._sanitize_data(body.decode())
            except:
                pass
        
        response = await call_next(request)
        return response
    
    def _sanitize_data(self, data: str) -> str:
        """
        Apply input sanitization rules
        Removes potentially dangerous patterns
        """
        # Remove null bytes
        data = data.replace('\x00', '')
        
        # Escape HTML entities
        data = html.escape(data)
        
        # Remove potential SQL injection patterns
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|FROM|WHERE)\b)",
            r"(--|\||;|\/\*|\*\/)"
        ]
        for pattern in sql_patterns:
            data = re.sub(pattern, '', data, flags=re.IGNORECASE)
        
        # Remove script tags and javascript: protocols
        data = re.sub(r'<script.*?</script>', '', data, flags=re.IGNORECASE | re.DOTALL)
        data = re.sub(r'javascript:', '', data, flags=re.IGNORECASE)
        
        return data

class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection for state-changing operations
    Validates tokens on protected endpoints
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.protected_methods = ["POST", "PUT", "DELETE", "PATCH"]
        self.exempt_paths = ["/token", "/api/public"]
    
    async def dispatch(self, request: Request, call_next):
        # Check if CSRF protection is needed
        if request.method in self.protected_methods:
            if not any(request.url.path.startswith(path) for path in self.exempt_paths):
                # Validate CSRF token
                csrf_token = request.headers.get("X-CSRF-Token")
                session_token = request.cookies.get("csrf_token")
                
                if not csrf_token or csrf_token != session_token:
                    return Response(content="CSRF token validation failed", status_code=403)
        
        response = await call_next(request)
        
        # Set CSRF token cookie if not present
        if "csrf_token" not in request.cookies:
            token = self._generate_csrf_token()
            response.set_cookie("csrf_token", token, httponly=True, secure=True, samesite="strict")
        
        return response
    
    def _generate_csrf_token(self) -> str:
        """
        Generate a secure CSRF token
        """
        import secrets
        return secrets.token_urlsafe(32)

def configure_cors(app):
    """
    Configure CORS policy for the application
    Restricts cross-origin requests
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://anime-app.example.com", "https://admin.anime-app.example.com"],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
        max_age=86400,
    )

class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Validate request format and content
    Ensures requests meet security requirements
    """
    
    async def dispatch(self, request: Request, call_next):
        # Validate Content-Type for POST requests
        if request.method == "POST":
            content_type = request.headers.get("Content-Type", "")
            if not content_type.startswith(("application/json", "application/x-www-form-urlencoded", "multipart/form-data")):
                return Response(content="Invalid Content-Type", status_code=400)
        
        # Check request size
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB limit
            return Response(content="Request too large", status_code=413)
        
        # Validate host header
        host = request.headers.get("Host", "")
        allowed_hosts = ["anime-app.example.com", "localhost:8000", "127.0.0.1:8000"]
        if host not in allowed_hosts:
            return Response(content="Invalid host header", status_code=400)
        
        response = await call_next(request)
        return response

class SessionSecurityMiddleware(BaseHTTPMiddleware):
    """
    Manage secure session handling
    Implements session timeout and validation
    """
    
    def __init__(self, app, session_timeout: int = 1800):
        super().__init__(app)
        self.session_timeout = session_timeout
        self.sessions = {}
    
    async def dispatch(self, request: Request, call_next):
        session_id = request.cookies.get("session_id")
        
        if session_id:
            # Validate session
            session = self.sessions.get(session_id)
            if session:
                # Check timeout
                if time.time() - session["last_activity"] > self.session_timeout:
                    # Session expired
                    del self.sessions[session_id]
                    response = Response(content="Session expired", status_code=401)
                    response.delete_cookie("session_id")
                    return response
                
                # Update last activity
                session["last_activity"] = time.time()
                request.state.session = session
        
        response = await call_next(request)
        
        # Create new session if needed
        if not session_id and request.url.path == "/login" and response.status_code == 200:
            new_session_id = self._create_session()
            response.set_cookie(
                "session_id",
                new_session_id,
                httponly=True,
                secure=True,
                samesite="strict",
                max_age=self.session_timeout
            )
        
        return response
    
    def _create_session(self) -> str:
        """
        Create a new secure session
        """
        import secrets
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            "created": time.time(),
            "last_activity": time.time()
        }
        return session_id

def apply_security_middleware(app):
    """
    Apply all security middleware to the application
    Provides comprehensive protection
    """
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, requests_per_minute=100)
    app.add_middleware(InputSanitizationMiddleware)
    app.add_middleware(CSRFProtectionMiddleware)
    app.add_middleware(RequestValidationMiddleware)
    app.add_middleware(SessionSecurityMiddleware)
    configure_cors(app)
