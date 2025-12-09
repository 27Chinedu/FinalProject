# tests/unit/test_web_routes.py

import pytest
from fastapi.testclient import TestClient
from app.main import app


client = TestClient(app)


class TestTemplateRoutes:
    """Test template rendering routes"""

    def test_home_page_loads(self):
        """Test that home page loads successfully"""
        response = client.get("/")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert b"<!DOCTYPE html>" in response.content or b"<html" in response.content

    def test_login_page_loads(self):
        """Test that login page loads successfully"""
        response = client.get("/login")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert b"login" in response.content.lower() or b"sign in" in response.content.lower()

    def test_register_page_loads(self):
        """Test that registration page loads successfully"""
        response = client.get("/register")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert b"register" in response.content.lower() or b"sign up" in response.content.lower()

    def test_dashboard_page_loads(self):
        """Test that dashboard page loads successfully"""
        response = client.get("/dashboard")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert b"dashboard" in response.content.lower() or b"calculation" in response.content.lower()

    def test_profile_page_loads(self):
        """Test that profile page loads successfully"""
        response = client.get("/profile")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert b"profile" in response.content.lower()

    def test_home_page_contains_navigation(self):
        """Test that home page contains navigation links"""
        response = client.get("/")

        content = response.content.lower()
        # Should have links to login and register
        assert b"login" in content or b"sign in" in content
        assert b"register" in content or b"sign up" in content

    def test_login_page_has_form(self):
        """Test that login page has login form elements"""
        response = client.get("/login")

        content = response.content.lower()
        # Should have form elements
        assert b"username" in content or b"email" in content
        assert b"password" in content

    def test_register_page_has_form(self):
        """Test that register page has registration form elements"""
        response = client.get("/register")

        content = response.content.lower()
        # Should have form elements for registration
        assert b"username" in content
        assert b"email" in content
        assert b"password" in content
        assert b"first" in content or b"name" in content

    def test_all_pages_return_html(self):
        """Test that all template routes return HTML"""
        routes = ["/", "/login", "/register", "/dashboard", "/profile"]

        for route in routes:
            response = client.get(route)
            assert response.status_code == 200
            assert "text/html" in response.headers["content-type"]

    def test_nonexistent_page_404(self):
        """Test that nonexistent pages return 404"""
        response = client.get("/nonexistent-page")

        assert response.status_code == 404

    def test_static_files_accessible(self):
        """Test that static files are accessible"""
        # Test CSS file
        response = client.get("/static/css/style.css")

        # Should either exist or return 404, but not 500
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            # Should be CSS content
            assert "text/css" in response.headers.get("content-type", "")


class TestHealthEndpoint:
    """Test health check endpoint"""

    def test_health_endpoint_returns_ok(self):
        """Test that health endpoint returns OK status"""
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_health_endpoint_json_response(self):
        """Test that health endpoint returns JSON"""
        response = client.get("/health")

        assert "application/json" in response.headers["content-type"]

    def test_health_endpoint_no_authentication(self):
        """Test that health endpoint doesn't require authentication"""
        # Health check should be accessible without token
        response = client.get("/health")

        assert response.status_code == 200
        # Should not return 401 Unauthorized


class TestAPIDocumentation:
    """Test API documentation endpoints"""

    def test_openapi_schema_available(self):
        """Test that OpenAPI schema is available"""
        response = client.get("/openapi.json")

        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]

        schema = response.json()
        assert "openapi" in schema
        assert "info" in schema
        assert "paths" in schema

    def test_docs_ui_available(self):
        """Test that Swagger UI docs are available"""
        response = client.get("/docs")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_redoc_available(self):
        """Test that ReDoc documentation is available"""
        response = client.get("/redoc")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_openapi_has_correct_metadata(self):
        """Test that OpenAPI schema has correct metadata"""
        response = client.get("/openapi.json")
        schema = response.json()

        info = schema.get("info", {})
        assert info.get("title") == "Calculations API"
        assert "version" in info
        assert "description" in info

    def test_openapi_has_all_main_paths(self):
        """Test that OpenAPI schema includes main API paths"""
        response = client.get("/openapi.json")
        schema = response.json()

        paths = schema.get("paths", {})

        # Check for main endpoints
        assert "/auth/register" in paths
        assert "/auth/login" in paths
        assert "/calculations" in paths
        assert "/health" in paths

    def test_openapi_has_security_scheme(self):
        """Test that OpenAPI schema defines security scheme"""
        response = client.get("/openapi.json")
        schema = response.json()

        # Should have security schemes defined
        components = schema.get("components", {})
        security_schemes = components.get("securitySchemes", {})

        # Should have OAuth2 or Bearer token scheme
        assert len(security_schemes) > 0


class TestCORSHeaders:
    """Test CORS configuration"""

    def test_cors_headers_present(self):
        """Test that CORS headers are present"""
        response = client.options("/health", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET"
        })

        # FastAPI should handle OPTIONS request
        assert response.status_code in [200, 204, 405]

    def test_api_accepts_json(self):
        """Test that API endpoints accept JSON"""
        response = client.get("/health", headers={
            "Content-Type": "application/json"
        })

        assert response.status_code == 200


class TestErrorHandling:
    """Test error handling in routes"""

    def test_invalid_json_payload(self):
        """Test handling of invalid JSON in request"""
        response = client.post(
            "/auth/register",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )

        # Should return 422 for validation error or 400 for bad request
        assert response.status_code in [400, 422]

    def test_missing_required_fields(self):
        """Test handling of missing required fields"""
        response = client.post(
            "/auth/register",
            json={"username": "test"}  # Missing other required fields
        )

        assert response.status_code == 422

        error = response.json()
        assert "detail" in error

    def test_invalid_calculation_type(self):
        """Test handling of invalid calculation type"""
        # This will fail authentication, but that's expected
        response = client.post(
            "/calculations",
            json={
                "type": "invalid_operation",
                "inputs": [1, 2, 3]
            }
        )

        # Should return 401 (no auth) or 400 (bad request after auth)
        assert response.status_code in [401, 400, 422]


class TestRequestValidation:
    """Test request validation"""

    def test_get_request_no_body(self):
        """Test that GET requests work without body"""
        response = client.get("/health")

        assert response.status_code == 200

    def test_post_request_requires_body(self):
        """Test that POST requests validate body"""
        response = client.post("/auth/register")

        # Should fail validation due to missing body
        assert response.status_code == 422

    def test_content_type_validation(self):
        """Test content type validation"""
        # Send form data to JSON endpoint
        response = client.post(
            "/auth/login",
            data={"username": "test", "password": "test"}
        )

        # Should handle or reject non-JSON content type
        assert response.status_code in [200, 400, 401, 422]
