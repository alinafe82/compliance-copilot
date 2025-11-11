"""Main FastAPI application for Compliance Copilot."""
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from .config import get_settings, setup_logging
from .llm import LLMError, LLMTimeoutError, get_llm
from .safety import SYSTEM_PROMPT, mask_pii, validate_input_safety
from .scoring import get_risk_level, score_risk

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Get settings
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    yield
    logger.info("Shutting down application")


# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-powered PR and ticket risk analysis for compliance and security",
    lifespan=lifespan,
)

# Add CORS middleware
if settings.enable_cors:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# Request/Response Models
class PRPayload(BaseModel):
    """Pull request analysis payload."""
    title: str = Field(..., min_length=1, max_length=500, description="PR title")
    body: str = Field(..., max_length=10000, description="PR description/body")
    diff: str = Field(..., max_length=100000, description="Git diff content")

    @field_validator("title", "body", "diff")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty or whitespace only")
        return v


class TicketPayload(BaseModel):
    """Ticket analysis payload."""
    summary: str = Field(..., min_length=1, max_length=500, description="Ticket summary")
    description: str = Field(..., max_length=10000, description="Ticket description")

    @field_validator("summary", "description")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field cannot be empty or whitespace only")
        return v


class AnalysisResponse(BaseModel):
    """Analysis result response."""
    summary: str = Field(..., description="Risk analysis summary")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Numerical risk score (0-1)")
    risk_level: str = Field(..., description="Categorical risk level")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    environment: str


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: str


# Middleware for request logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests with timing."""
    start_time = time.time()
    request_id = f"{int(time.time() * 1000)}"

    logger.info(f"[{request_id}] {request.method} {request.url.path}")

    try:
        response = await call_next(request)
        process_time = (time.time() - start_time) * 1000
        logger.info(
            f"[{request_id}] Completed in {process_time:.2f}ms - Status: {response.status_code}"
        )
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.2f}"
        return response
    except Exception as e:
        logger.error(f"[{request_id}] Request failed: {str(e)}", exc_info=True)
        raise


# Exception handlers
@app.exception_handler(LLMError)
async def llm_error_handler(request: Request, exc: LLMError):
    """Handle LLM-related errors."""
    logger.error(f"LLM error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"error": "LLM Service Error", "detail": str(exc)},
    )


@app.exception_handler(LLMTimeoutError)
async def llm_timeout_handler(request: Request, exc: LLMTimeoutError):
    """Handle LLM timeout errors."""
    logger.error(f"LLM timeout: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        content={"error": "LLM Request Timeout", "detail": str(exc)},
    )


# API Endpoints
@app.get("/", response_model=dict[str, str])
async def root():
    """Root endpoint with API information."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for container orchestration."""
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        environment=settings.environment,
    )


@app.post("/analyze/pr", response_model=AnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_pr(pr: PRPayload):
    """
    Analyze pull request for security and compliance risks.

    Processes PR title, body, and diff to identify potential risks,
    masks PII, and provides actionable recommendations.
    """
    start_time = time.time()

    # Combine PR fields
    text = f"Title: {pr.title}\n\nBody:\n{pr.body}\n\nDiff:\n{pr.diff}"

    # Validate input safety
    is_valid, error_msg = validate_input_safety(text, settings.max_input_length)
    if not is_valid:
        logger.warning(f"Input validation failed: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Input validation failed: {error_msg}",
        )

    try:
        # Mask PII
        sanitized = mask_pii(text) if settings.mask_pii else text

        # Get LLM instance
        llm = get_llm(
            provider=settings.llm_provider,
            api_key=settings.llm_api_key or None,
            model=settings.llm_model,
        )

        # Generate prompt and get analysis
        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Task: Analyze this pull request for security and compliance risks. "
            f"Provide a concise risk summary and top 3 recommended actions.\n\n"
            f"Input:\n{sanitized}"
        )

        result = llm.complete(
            prompt,
            max_tokens=settings.llm_max_tokens,
            temperature=settings.llm_temperature,
        )

        # Score risk
        risk_score = score_risk(result)
        risk_level = get_risk_level(risk_score)

        processing_time = (time.time() - start_time) * 1000

        logger.info(
            f"PR analysis completed: risk_score={risk_score:.2f}, "
            f"risk_level={risk_level}, time={processing_time:.2f}ms"
        )

        return AnalysisResponse(
            summary=result,
            risk_score=risk_score,
            risk_level=risk_level,
            processing_time_ms=processing_time,
        )

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error(f"Unexpected error in PR analysis: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during analysis",
        ) from e


@app.post("/analyze/ticket", response_model=AnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_ticket(ticket: TicketPayload):
    """
    Analyze ticket/issue for security and compliance risks.

    Processes ticket summary and description to assess severity,
    blast radius, and provide next steps.
    """
    start_time = time.time()

    # Combine ticket fields
    text = f"Summary: {ticket.summary}\n\nDescription:\n{ticket.description}"

    # Validate input safety
    is_valid, error_msg = validate_input_safety(text, settings.max_input_length)
    if not is_valid:
        logger.warning(f"Input validation failed: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Input validation failed: {error_msg}",
        )

    try:
        # Mask PII
        sanitized = mask_pii(text) if settings.mask_pii else text

        # Get LLM instance
        llm = get_llm(
            provider=settings.llm_provider,
            api_key=settings.llm_api_key or None,
            model=settings.llm_model,
        )

        # Generate prompt and get analysis
        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Task: Analyze this ticket/issue for security and compliance implications. "
            f"Provide likely severity, blast radius assessment, and next steps.\n\n"
            f"Input:\n{sanitized}"
        )

        result = llm.complete(
            prompt,
            max_tokens=settings.llm_max_tokens,
            temperature=settings.llm_temperature,
        )

        # Score risk
        risk_score = score_risk(result)
        risk_level = get_risk_level(risk_score)

        processing_time = (time.time() - start_time) * 1000

        logger.info(
            f"Ticket analysis completed: risk_score={risk_score:.2f}, "
            f"risk_level={risk_level}, time={processing_time:.2f}ms"
        )

        return AnalysisResponse(
            summary=result,
            risk_score=risk_score,
            risk_level=risk_level,
            processing_time_ms=processing_time,
        )

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.error(f"Unexpected error in ticket analysis: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during analysis",
        ) from e
