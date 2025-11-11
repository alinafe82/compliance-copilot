"""Tests for FastAPI application."""
import pytest
from fastapi.testclient import TestClient

from src.app import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


class TestRootEndpoints:
    """Tests for root and health endpoints."""

    def test_root_endpoint(self, client):
        """Test root endpoint returns API info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "version" in data
        assert "docs" in data
        assert "health" in data

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "environment" in data

    def test_docs_available(self, client):
        """Test that API docs are available."""
        response = client.get("/docs")
        assert response.status_code == 200


class TestPRAnalysis:
    """Tests for PR analysis endpoint."""

    def test_analyze_pr_success(self, client):
        """Test successful PR analysis."""
        payload = {
            "title": "Add new authentication feature",
            "body": "This PR adds OAuth2 authentication support",
            "diff": "+def authenticate(user):\n+    return True"
        }
        response = client.post("/analyze/pr", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "summary" in data
        assert "risk_score" in data
        assert "risk_level" in data
        assert "processing_time_ms" in data
        assert 0.0 <= data["risk_score"] <= 1.0
        assert data["risk_level"] in ["low", "medium", "high", "critical"]

    def test_analyze_pr_with_secrets(self, client):
        """Test PR analysis detects secrets."""
        payload = {
            "title": "Update config",
            "body": "Added API key configuration",
            "diff": "+API_KEY = 'sk-1234567890abcdef'"
        }
        response = client.post("/analyze/pr", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] >= 0.5

    def test_analyze_pr_empty_title(self, client):
        """Test PR analysis with empty title."""
        payload = {
            "title": "",
            "body": "Some body",
            "diff": "Some diff"
        }
        response = client.post("/analyze/pr", json=payload)
        assert response.status_code == 422  # Validation error

    def test_analyze_pr_empty_body(self, client):
        """Test PR analysis with empty body."""
        payload = {
            "title": "Title",
            "body": "",
            "diff": "Some diff"
        }
        response = client.post("/analyze/pr", json=payload)
        assert response.status_code == 422  # Validation error

    def test_analyze_pr_whitespace_only(self, client):
        """Test PR analysis with whitespace-only fields."""
        payload = {
            "title": "   ",
            "body": "\n\t",
            "diff": "  "
        }
        response = client.post("/analyze/pr", json=payload)
        assert response.status_code == 422  # Validation error

    def test_analyze_pr_too_long_title(self, client):
        """Test PR analysis with title exceeding max length."""
        payload = {
            "title": "x" * 1000,
            "body": "Body",
            "diff": "Diff"
        }
        response = client.post("/analyze/pr", json=payload)
        assert response.status_code == 422  # Validation error

    def test_analyze_pr_with_xss_attempt(self, client):
        """Test PR analysis rejects XSS attempts."""
        payload = {
            "title": "Innocent title",
            "body": "<script>alert('xss')</script>",
            "diff": "Some diff"
        }
        response = client.post("/analyze/pr", json=payload)
        assert response.status_code == 400  # Bad request
        assert "XSS" in response.json()["detail"]


class TestTicketAnalysis:
    """Tests for ticket analysis endpoint."""

    def test_analyze_ticket_success(self, client):
        """Test successful ticket analysis."""
        payload = {
            "summary": "User cannot login",
            "description": "Multiple users reporting login failures after deployment"
        }
        response = client.post("/analyze/ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "summary" in data
        assert "risk_score" in data
        assert "risk_level" in data
        assert "processing_time_ms" in data
        assert 0.0 <= data["risk_score"] <= 1.0
        assert data["risk_level"] in ["low", "medium", "high", "critical"]

    def test_analyze_ticket_with_vulnerability(self, client):
        """Test ticket analysis detects vulnerabilities."""
        payload = {
            "summary": "SQL injection vulnerability found",
            "description": "Critical security vulnerability allows unauthorized database access"
        }
        response = client.post("/analyze/ticket", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] >= 0.5
        assert data["risk_level"] in ["high", "critical"]

    def test_analyze_ticket_empty_summary(self, client):
        """Test ticket analysis with empty summary."""
        payload = {
            "summary": "",
            "description": "Some description"
        }
        response = client.post("/analyze/ticket", json=payload)
        assert response.status_code == 422  # Validation error

    def test_analyze_ticket_missing_fields(self, client):
        """Test ticket analysis with missing fields."""
        payload = {"summary": "Only summary"}
        response = client.post("/analyze/ticket", json=payload)
        assert response.status_code == 422  # Validation error


class TestResponseHeaders:
    """Tests for response headers."""

    def test_request_id_header(self, client):
        """Test that responses include request ID."""
        response = client.get("/health")
        assert "x-request-id" in response.headers

    def test_process_time_header(self, client):
        """Test that responses include processing time."""
        response = client.get("/health")
        assert "x-process-time" in response.headers
        process_time = float(response.headers["x-process-time"])
        assert process_time >= 0.0
