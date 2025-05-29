"""
Agentic-IAM: FastAPI Application

Main FastAPI application with comprehensive middleware, routing, and integration
with the Agent Identity Framework.
"""
import asyncio
from contextlib import asynccontextmanager
from typing import Optional
import sys
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Add core modules to path
sys.path.append(str(Path(__file__).parent.parent / "core"))
sys.path.append(str(Path(__file__).parent.parent.parent))

from core.agentic_iam import AgenticIAM
from config.settings import Settings
from utils.logger import setup_logging, get_logger

# Import routers
from api.routers import (
    health, agents, authentication, authorization, 
    sessions, intelligence, audit
)


# Global instances
iam_instance: Optional[AgenticIAM] = None
settings_instance: Optional[Settings] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events"""
    global iam_instance, settings_instance
    
    # Startup
    logger = get_logger("api")
    logger.info("Starting Agentic-IAM API server...")
    
    try:
        # Initialize settings
        settings_instance = Settings()
        
        # Setup logging
        setup_logging(
            log_level=settings_instance.log_level,
            log_file=settings_instance.log_file,
            enable_console=True
        )
        
        # Initialize IAM system
        iam_instance = AgenticIAM(settings_instance)
        await iam_instance.initialize()
        
        logger.info("API server started successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start API server: {str(e)}")
        raise
    finally:
        # Shutdown
        logger.info("Shutting down Agentic-IAM API server...")
        
        if iam_instance:
            await iam_instance.shutdown()
        
        logger.info("API server shutdown complete")


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    
    app = FastAPI(
        title="Agentic-IAM API",
        description="Comprehensive Agent Identity & Access Management Platform",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan
    )
    
    # Add middleware
    setup_middleware(app)
    
    # Add routers
    setup_routers(app)
    
    # Add exception handlers
    setup_exception_handlers(app)
    
    return app


def setup_middleware(app: FastAPI):
    """Configure application middleware"""
    settings = Settings()
    
    # CORS middleware
    if settings.enable_cors:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    # Trusted host middleware
    if settings.is_production:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=[settings.api_host, "localhost", "127.0.0.1"]
        )
    
    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        if settings.require_tls:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response
    
    # Request logging middleware
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        logger = get_logger("api.requests")
        start_time = asyncio.get_event_loop().time()
        
        # Log request
        logger.info(
            f"Request: {request.method} {request.url}",
            extra={
                "method": request.method,
                "url": str(request.url),
                "client_ip": request.client.host,
                "user_agent": request.headers.get("user-agent")
            }
        )
        
        response = await call_next(request)
        
        # Log response
        duration = asyncio.get_event_loop().time() - start_time
        logger.info(
            f"Response: {response.status_code} in {duration:.3f}s",
            extra={
                "status_code": response.status_code,
                "duration": duration
            }
        )
        
        return response


def setup_routers(app: FastAPI):
    """Configure API routers"""
    
    # Health and monitoring
    app.include_router(
        health.router,
        prefix="/health",
        tags=["Health & Monitoring"]
    )
    
    # Core agent management
    app.include_router(
        agents.router,
        prefix="/api/v1/agents",
        tags=["Agent Management"]
    )
    
    # Authentication
    app.include_router(
        authentication.router,
        prefix="/api/v1/auth",
        tags=["Authentication"]
    )
    
    # Authorization
    app.include_router(
        authorization.router,
        prefix="/api/v1/authz",
        tags=["Authorization"]
    )
    
    # Session management
    app.include_router(
        sessions.router,
        prefix="/api/v1/sessions",
        tags=["Session Management"]
    )
    
    # Intelligence & trust scoring
    app.include_router(
        intelligence.router,
        prefix="/api/v1/intelligence",
        tags=["Intelligence & Trust"]
    )
    
    # Audit & compliance
    app.include_router(
        audit.router,
        prefix="/api/v1/audit",
        tags=["Audit & Compliance"]
    )


def setup_exception_handlers(app: FastAPI):
    """Configure exception handlers"""
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        logger = get_logger("api.errors")
        logger.warning(
            f"HTTP Exception: {exc.status_code} - {exc.detail}",
            extra={
                "status_code": exc.status_code,
                "detail": exc.detail,
                "url": str(request.url),
                "method": request.method
            }
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                    "type": "HTTPException"
                },
                "request": {
                    "method": request.method,
                    "url": str(request.url)
                }
            }
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        logger = get_logger("api.errors")
        logger.error(
            f"Unhandled Exception: {str(exc)}",
            extra={
                "exception_type": type(exc).__name__,
                "url": str(request.url),
                "method": request.method
            },
            exc_info=True
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": 500,
                    "message": "Internal server error",
                    "type": "InternalServerError"
                },
                "request": {
                    "method": request.method,
                    "url": str(request.url)
                }
            }
        )


# Dependency injection
async def get_iam() -> AgenticIAM:
    """Get IAM instance dependency"""
    if not iam_instance:
        raise HTTPException(
            status_code=503,
            detail="IAM system not initialized"
        )
    return iam_instance


async def get_settings() -> Settings:
    """Get settings instance dependency"""
    if not settings_instance:
        raise HTTPException(
            status_code=503,
            detail="Settings not initialized"
        )
    return settings_instance


# Create app instance
app = create_app()


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Agentic-IAM API",
        "version": "1.0.0",
        "description": "Comprehensive Agent Identity & Access Management Platform",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health"
    }


# API info endpoint
@app.get("/api/v1")
async def api_info():
    """API version information"""
    return {
        "version": "1.0.0",
        "endpoints": {
            "agents": "/api/v1/agents",
            "authentication": "/api/v1/auth",
            "authorization": "/api/v1/authz",
            "sessions": "/api/v1/sessions",
            "intelligence": "/api/v1/intelligence",
            "audit": "/api/v1/audit"
        },
        "documentation": {
            "openapi": "/openapi.json",
            "swagger": "/docs",
            "redoc": "/redoc"
        }
    }


if __name__ == "__main__":
    # Development server
    settings = Settings()
    
    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.auto_reload,
        log_level=settings.log_level.lower(),
        access_log=True
    )