"""
Security headers middleware.
Adds security headers to all responses.
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    
    Protects against:
    - XSS attacks (Content-Security-Policy, X-XSS-Protection)
    - Clickjacking (X-Frame-Options)
    - MIME sniffing (X-Content-Type-Options)
    - MITM attacks (Strict-Transport-Security)
    - Information leakage (X-Powered-By removal, Referrer-Policy)
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.settings = get_settings()
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:
        """Process request and add security headers to response."""
        response = await call_next(request)
        
        security = self.settings.security
        
        # Strict Transport Security (HSTS)
        # Forces HTTPS connections
        hsts_value = f"max-age={security.hsts_max_age}"
        if security.hsts_include_subdomains:
            hsts_value += "; includeSubDomains"
        if security.hsts_preload:
            hsts_value += "; preload"
        response.headers["Strict-Transport-Security"] = hsts_value
        
        # Content Security Policy
        # Restricts resources the browser can load
        response.headers["Content-Security-Policy"] = security.content_security_policy
        
        # X-Frame-Options
        # Prevents clickjacking by controlling iframe embedding
        response.headers["X-Frame-Options"] = security.x_frame_options
        
        # X-Content-Type-Options
        # Prevents MIME type sniffing
        response.headers["X-Content-Type-Options"] = security.x_content_type_options
        
        # Referrer Policy
        # Controls referrer information sent with requests
        response.headers["Referrer-Policy"] = security.referrer_policy
        
        # X-XSS-Protection
        # Legacy XSS protection (still useful for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Permissions Policy (formerly Feature-Policy)
        # Restricts browser features
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )
        
        # Cache Control for sensitive endpoints
        # Prevent caching of authenticated responses
        if "/api/" in request.url.path:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        # Remove server identification headers
        if "Server" in response.headers:
            del response.headers["Server"]
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]
        
        # Add Cross-Origin headers
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        
        return response
