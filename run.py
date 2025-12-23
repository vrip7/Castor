#!/usr/bin/env python3
"""
Development server runner.

Usage:
    python run.py
    python run.py --reload
    python run.py --host 0.0.0.0 --port 8000
"""

import argparse
import os
import sys

import uvicorn


def main():
    """Run the development server."""
    parser = argparse.ArgumentParser(description="Run the Castor Auth API server")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to (default: 8000)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of workers (default: 1, ignored with --reload)",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Log level (default: info)",
    )
    
    args = parser.parse_args()
    
    # Set environment variables if not set
    if not os.getenv("DATABASE_URL"):
        print("Warning: DATABASE_URL not set. Using default.", file=sys.stderr)
    
    if not os.getenv("SECRET_KEY"):
        print("Warning: SECRET_KEY not set. Using insecure default for development.", file=sys.stderr)
        os.environ.setdefault("SECRET_KEY", "dev-secret-key-change-in-production")
    
    if not os.getenv("JWT_SECRET_KEY"):
        print("Warning: JWT_SECRET_KEY not set. Using insecure default for development.", file=sys.stderr)
        os.environ.setdefault("JWT_SECRET_KEY", "dev-jwt-secret-change-in-production")
    
    # Run the server
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers if not args.reload else 1,
        log_level=args.log_level,
        access_log=True,
    )


if __name__ == "__main__":
    main()
