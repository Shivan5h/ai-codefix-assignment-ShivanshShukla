"""
AI Code Remediation Microservice - FastAPI Application
"""
import sys
from fastapi import FastAPI, HTTPException, status, Request
from pydantic import BaseModel, Field
from typing import Optional
from loguru import logger
import time
from collections import defaultdict
import threading

from app import remediate_code, get_model_service, get_rag_service, config


# Configure logging
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
    level=config.LOG_LEVEL
)


# API Models
class FixRequest(BaseModel):
    """Request model for code remediation"""
    language: str = Field(..., description="Programming language (e.g., 'python', 'javascript')")
    cwe: str = Field(..., description="CWE category (e.g., 'CWE-89')")
    vulnerable_code: str = Field(..., description="The insecure code to fix")
    use_rag: Optional[bool] = Field(default=True, description="Whether to use RAG for context")


class FixResponse(BaseModel):
    """Response model for code remediation"""
    fixed_code: str = Field(..., description="The remediated secure code")
    diff: str = Field(..., description="Unified diff between vulnerable and fixed code")
    explanation: str = Field(..., description="Explanation of the vulnerability and fix")
    model_name: str = Field(..., description="Name of the model used")
    input_tokens: int = Field(..., description="Number of input tokens")
    output_tokens: int = Field(..., description="Number of output tokens")
    total_tokens: int = Field(..., description="Total tokens (input + output)")
    latency_ms: float = Field(..., description="Total latency in milliseconds")


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    model_loaded: bool
    model_name: str
    rag_enabled: bool
    rag_documents: int


# Create FastAPI app
app = FastAPI(
    title="AI Code Remediation Microservice",
    description="Local AI service for automated security vulnerability remediation",
    version="1.0.0"
)

# Simple rate limiting (in-memory)
class RateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed"""
        with self.lock:
            now = time.time()
            # Clean old requests
            self.requests[client_id] = [
                req_time for req_time in self.requests[client_id]
                if now - req_time < self.window_seconds
            ]
            
            if len(self.requests[client_id]) >= self.max_requests:
                return False
            
            self.requests[client_id].append(now)
            return True

rate_limiter = RateLimiter(max_requests=10, window_seconds=60)


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("Starting AI Code Remediation Microservice...")
    
    # Initialize model service (this will load the model)
    try:
        get_model_service()
        logger.info("Model service initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize model service: {e}")
        raise
    
    # Initialize RAG service
    try:
        rag = get_rag_service()
        if rag.enabled:
            logger.info(f"RAG service initialized with {len(rag.documents)} documents")
        else:
            logger.warning("RAG service is disabled")
    except Exception as e:
        logger.warning(f"RAG service initialization failed: {e}")
    
    logger.info("Microservice startup complete")


@app.get("/", response_model=dict)
async def root():
    """Root endpoint"""
    return {
        "service": "AI Code Remediation Microservice",
        "version": "1.0.0",
        "endpoints": ["/local_fix", "/health"]
    }


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint"""
    try:
        model_service = get_model_service()
        rag_service = get_rag_service()
        
        return HealthResponse(
            status="healthy",
            model_loaded=model_service.model is not None,
            model_name=model_service.model_name,
            rag_enabled=rag_service.enabled,
            rag_documents=len(rag_service.documents)
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )


@app.post("/local_fix", response_model=FixResponse)
async def local_fix(request: FixRequest, req: Request):
    """
    Main endpoint for code remediation.
    
    Accepts vulnerable code and returns fixed version with diff and explanation.
    """
    # Rate limiting
    client_ip = req.client.host if req.client else "unknown"
    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later."
        )
    
    logger.info(f"Received fix request for {request.language} code with {request.cwe} from {client_ip}")
    
    try:
        result = remediate_code(
            language=request.language,
            cwe=request.cwe,
            vulnerable_code=request.vulnerable_code,
            use_rag=request.use_rag
        )
        
        logger.info(f"Request completed in {result['latency_ms']:.2f}ms, tokens: {result['total_tokens']}")
        
        return FixResponse(**result)
        
    except ValueError as e:
        # Input validation errors (safe to expose)
        logger.warning(f"Validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        # Unexpected errors (sanitize before exposing)
        logger.error(f"Error processing fix request: {e}", exc_info=True)
        
        # Import sanitization function
        from app import sanitize_error_message
        safe_message = sanitize_error_message(e)
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=safe_message
        )


if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"Starting server on {config.HOST}:{config.PORT}")
    uvicorn.run(
        app,
        host=config.HOST,
        port=config.PORT,
        log_level=config.LOG_LEVEL.lower()
    )
