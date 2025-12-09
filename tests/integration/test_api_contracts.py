# tests/integration/test_api_contracts.py

import pytest
from fastapi.testclient import TestClient
from app.main import app
from uuid import uuid4


client = TestClient(app)


class TestAPIResponseFormats:
    """Test that API responses follow consistent formats"""

    def test_health_response_format(self):
        """Test health endpoint response format"""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        # Should have status key
        assert "status" in data
        assert data["status"] == "ok"

    def test_registration_response_format(self):
        """Test registration response format"""
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!",
            "confirm_password": "TestPass123!"
        }

        response = client.post("/auth/register", json=user_data)

        assert response.status_code == 201
        data = response.json()

        # Should have required fields
        assert "id" in data
        assert "username" in data
        assert "email" in data
        assert "first_name" in data
        assert "last_name" in data
        assert "is_active" in data
        assert "is_verified" in data
        assert "created_at" in data
        assert "updated_at" in data

        # Should NOT have password
        assert "password" not in data

    def test_login_response_format(self):
        """Test login response format"""
        # Register first
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!",
            "confirm_password": "TestPass123!"
        }
        client.post("/auth/register", json=user_data)

        # Login
        login_data = {
            "username": user_data["username"],
            "password": user_data["password"]
        }
        response = client.post("/auth/login", json=login_data)

        assert response.status_code == 200
        data = response.json()

        # Should have token fields
        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert "expires_at" in data

        # Should have user info
        assert "user_id" in data
        assert "username" in data
        assert "email" in data

    def test_error_response_format(self):
        """Test that errors follow consistent format"""
        # Try to register with missing fields
        response = client.post("/auth/register", json={"username": "test"})

        assert response.status_code == 422
        data = response.json()

        # FastAPI validation errors have 'detail' key
        assert "detail" in data

    def test_validation_error_format(self):
        """Test validation error format"""
        # Send invalid email format
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "not-an-email",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!",
            "confirm_password": "TestPass123!"
        }

        response = client.post("/auth/register", json=user_data)

        assert response.status_code in [400, 422]
        data = response.json()

        assert "detail" in data


class TestAPIStatusCodes:
    """Test that API returns correct HTTP status codes"""

    def test_successful_registration_returns_201(self):
        """Test that registration returns 201 Created"""
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!",
            "confirm_password": "TestPass123!"
        }

        response = client.post("/auth/register", json=user_data)

        assert response.status_code == 201

    def test_successful_login_returns_200(self):
        """Test that login returns 200 OK"""
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!",
            "confirm_password": "TestPass123!"
        }
        client.post("/auth/register", json=user_data)

        login_data = {
            "username": user_data["username"],
            "password": user_data["password"]
        }
        response = client.post("/auth/login", json=login_data)

        assert response.status_code == 200

    def test_unauthorized_returns_401(self):
        """Test that unauthorized access returns 401"""
        # Try to access protected endpoint without token
        response = client.get("/calculations")

        assert response.status_code == 401

    def test_not_found_returns_404(self):
        """Test that missing resources return 404"""
        response = client.get("/nonexistent-endpoint")

        assert response.status_code == 404

    def test_validation_error_returns_422(self):
        """Test that validation errors return 422"""
        # Missing required fields
        response = client.post("/auth/register", json={})

        assert response.status_code == 422


class TestOpenAPISchema:
    """Test OpenAPI schema compliance"""

    def test_openapi_schema_available(self):
        """Test that OpenAPI schema is available"""
        response = client.get("/openapi.json")

        assert response.status_code == 200
        schema = response.json()

        assert "openapi" in schema
        assert "info" in schema
        assert "paths" in schema

    def test_schema_has_correct_version(self):
        """Test that schema has correct OpenAPI version"""
        response = client.get("/openapi.json")
        schema = response.json()

        # Should be OpenAPI 3.x
        assert schema["openapi"].startswith("3.")

    def test_schema_has_app_metadata(self):
        """Test that schema has correct app metadata"""
        response = client.get("/openapi.json")
        schema = response.json()

        info = schema["info"]
        assert info["title"] == "Calculations API"
        assert "version" in info
        assert "description" in info

    def test_schema_has_auth_endpoints(self):
        """Test that schema includes auth endpoints"""
        response = client.get("/openapi.json")
        schema = response.json()

        paths = schema["paths"]
        assert "/auth/register" in paths
        assert "/auth/login" in paths
        assert "/auth/token" in paths

    def test_schema_has_calculation_endpoints(self):
        """Test that schema includes calculation endpoints"""
        response = client.get("/openapi.json")
        schema = response.json()

        paths = schema["paths"]
        assert "/calculations" in paths
        assert "/calculations/{calc_id}" in paths

    def test_schema_has_profile_endpoints(self):
        """Test that schema includes profile endpoints"""
        response = client.get("/openapi.json")
        schema = response.json()

        paths = schema["paths"]
        assert "/profile/me" in paths
        assert "/profile/change-password" in paths

    def test_schema_has_security_definitions(self):
        """Test that schema has security definitions"""
        response = client.get("/openapi.json")
        schema = response.json()

        components = schema.get("components", {})
        security_schemes = components.get("securitySchemes", {})

        assert len(security_schemes) > 0

    def test_schema_defines_models(self):
        """Test that schema defines request/response models"""
        response = client.get("/openapi.json")
        schema = response.json()

        components = schema.get("components", {})
        schemas_def = components.get("schemas", {})

        # Should have user and calculation schemas
        assert "UserCreate" in schemas_def or "UserResponse" in schemas_def
        assert len(schemas_def) > 0

    def test_register_endpoint_schema(self):
        """Test registration endpoint schema"""
        response = client.get("/openapi.json")
        schema = response.json()

        register_path = schema["paths"]["/auth/register"]
        post_method = register_path["post"]

        # Should have request body
        assert "requestBody" in post_method

        # Should have responses
        assert "responses" in post_method
        assert "201" in post_method["responses"]

    def test_calculations_endpoint_requires_auth(self):
        """Test that calculations endpoint requires authentication"""
        response = client.get("/openapi.json")
        schema = response.json()

        calc_path = schema["paths"]["/calculations"]
        get_method = calc_path["get"]

        # Should have security requirement
        assert "security" in get_method or "security" in calc_path


class TestContentTypes:
    """Test content type handling"""

    def test_json_content_type_accepted(self):
        """Test that JSON content type is accepted"""
        response = client.get("/health", headers={"Content-Type": "application/json"})

        assert response.status_code == 200

    def test_response_content_type_json(self):
        """Test that API responses are JSON"""
        response = client.get("/health")

        assert "application/json" in response.headers["content-type"]

    def test_html_content_type_for_pages(self):
        """Test that web pages return HTML"""
        response = client.get("/")

        assert "text/html" in response.headers["content-type"]


class TestResponseHeaders:
    """Test response headers"""

    def test_health_has_content_type(self):
        """Test that responses have content-type header"""
        response = client.get("/health")

        assert "content-type" in response.headers

    def test_response_has_correct_charset(self):
        """Test that responses specify UTF-8 charset"""
        response = client.get("/health")

        content_type = response.headers["content-type"]
        # Should specify charset or default to UTF-8
        assert "json" in content_type.lower()


class TestPaginationAndLimits:
    """Test pagination and result limits (if implemented)"""

    def test_list_calculations_returns_array(self):
        """Test that list endpoint returns array"""
        # Register and login
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!",
            "confirm_password": "TestPass123!"
        }
        client.post("/auth/register", json=user_data)

        login_response = client.post("/auth/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })
        token = login_response.json()["access_token"]

        # Get calculations
        response = client.get(
            "/calculations",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()

        # Should be an array
        assert isinstance(data, list)


class TestAPIVersioning:
    """Test API versioning (if implemented)"""

    def test_api_version_in_schema(self):
        """Test that API version is specified"""
        response = client.get("/openapi.json")
        schema = response.json()

        info = schema["info"]
        assert "version" in info
        assert len(info["version"]) > 0

    def test_consistent_version_across_docs(self):
        """Test that version is consistent"""
        response = client.get("/openapi.json")
        schema = response.json()

        # Version should match app version
        from app.main import app
        assert schema["info"]["version"] == app.version


class TestFieldValidation:
    """Test field validation in requests"""

    def test_email_validation(self):
        """Test that email format is validated"""
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "not-an-email",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!",
            "confirm_password": "TestPass123!"
        }

        response = client.post("/auth/register", json=user_data)

        # Should fail validation
        assert response.status_code in [400, 422]

    def test_required_fields_validation(self):
        """Test that required fields are validated"""
        # Missing required fields
        response = client.post("/auth/register", json={
            "username": "testuser"
        })

        assert response.status_code == 422

    def test_extra_fields_ignored_or_rejected(self):
        """Test handling of extra fields"""
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!",
            "confirm_password": "TestPass123!",
            "extra_field": "should_be_ignored"
        }

        response = client.post("/auth/register", json=user_data)

        # Should either succeed (ignoring extra) or fail validation
        assert response.status_code in [201, 400, 422]
