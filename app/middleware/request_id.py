"""
Request ID middleware.
Adds unique identifiers to requests for tracing.
"""

import secrets
from contextvars import ContextVar
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.constants import SecurityHeaders

# Context variable for request ID (thread-safe)
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
correlation_id_var: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)


def get_request_id() -> Optional[str]:
    """Get current request ID from context."""
    return request_id_var.get()


def get_correlation_id() -> Optional[str]:
    """Get current correlation ID from context."""
    return correlation_id_var.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add request and correlation IDs.
    
    Features:
    - Generates unique request ID for each request
    - Propagates correlation ID from upstream services
    - Makes IDs available throughout request lifecycle
    - Adds IDs to response headers for client reference
    """
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:
        """Process request with unique identifiers."""
        # Generate or extract request ID
        request_id = request.headers.get(
            SecurityHeaders.X_REQUEST_ID,
            secrets.token_hex(16)
        )
        
        # Extract or generate correlation ID
        # Correlation ID tracks requests across multiple services
        correlation_id = request.headers.get(
            SecurityHeaders.X_CORRELATION_ID,
            secrets.token_hex(16)
        )
        
        # Set context variables
        request_id_token = request_id_var.set(request_id)
        correlation_id_token = correlation_id_var.set(correlation_id)
        
        # Store in request state for easy access
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id
        
        try:
            response = await call_next(request)
            
            # Add IDs to response headers
            response.headers[SecurityHeaders.X_REQUEST_ID] = request_id
            response.headers[SecurityHeaders.X_CORRELATION_ID] = correlation_id
            
            return response
        finally:
            # Reset context variables
            request_id_var.reset(request_id_token)
            correlation_id_var.reset(correlation_id_token)
