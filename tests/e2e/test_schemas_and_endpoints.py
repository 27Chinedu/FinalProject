"""
Direct tests for schemas and endpoints to achieve proper coverage
Uses FastAPI TestClient to ensure coverage is tracked
"""
import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone
from uuid import uuid4

from app.main import app
from app.schemas.user import UserCreate, UserLogin, PasswordUpdate
from app.schemas.calculation import CalculationBase, CalculationType, CalculationUpdate
from app.schemas.profile import ProfileUpdate, PasswordChange
from app.schemas.token import TokenResponse
from pydantic import ValidationError


client = TestClient(app)


# ==============================================================================
# Schema Validation Tests - Direct Unit Tests
# ==============================================================================

def test_user_create_password_mismatch():
    """Test UserCreate validates password match"""
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(
            first_name="Test",
            last_name="User",
            email="test@test.com",
            username="testuser",
            password="Pass123!",
            confirm_password="Different123!"
        )
    assert "password" in str(exc_info.value).lower()


def test_user_create_no_uppercase():
    """Test password requires uppercase"""
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(
            first_name="Test",
            last_name="User",
            email="test@test.com",
            username="testuser",
            password="pass123!",
            confirm_password="pass123!"
        )
    assert "uppercase" in str(exc_info.value).lower()


def test_user_create_no_lowercase():
    """Test password requires lowercase"""
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(
            first_name="Test",
            last_name="User",
            email="test@test.com",
            username="testuser",
            password="PASS123!",
            confirm_password="PASS123!"
        )
    assert "lowercase" in str(exc_info.value).lower()


def test_user_create_no_digit():
    """Test password requires digit"""
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(
            first_name="Test",
            last_name="User",
            email="test@test.com",
            username="testuser",
            password="Password!",
            confirm_password="Password!"
        )
    assert "digit" in str(exc_info.value).lower()


def test_user_create_no_special():
    """Test password requires special character"""
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(
            first_name="Test",
            last_name="User",
            email="test@test.com",
            username="testuser",
            password="Password123",
            confirm_password="Password123"
        )
    assert "special" in str(exc_info.value).lower()


def test_user_create_too_short():
    """Test password minimum length"""
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(
            first_name="Test",
            last_name="User",
            email="test@test.com",
            username="testuser",
            password="Pass1!",
            confirm_password="Pass1!"
        )
    assert "8" in str(exc_info.value) or "characters" in str(exc_info.value).lower()


def test_calculation_base_validates_type():
    """Test CalculationBase validates type"""
    with pytest.raises(ValidationError):
        CalculationBase(type="invalid", inputs=[1, 2])


def test_calculation_base_validates_inputs_list():
    """Test inputs must be a list"""
    with pytest.raises(ValidationError):
        CalculationBase(type="addition", inputs="not a list")


def test_calculation_base_minimum_inputs():
    """Test minimum 2 inputs required"""
    with pytest.raises(ValidationError):
        CalculationBase(type="addition", inputs=[1])


def test_calculation_base_division_by_zero():
    """Test division by zero prevention"""
    with pytest.raises(ValidationError) as exc_info:
        CalculationBase(type="division", inputs=[10, 0])
    assert "zero" in str(exc_info.value).lower()


def test_calculation_type_case_insensitive():
    """Test case-insensitive type validation"""
    calc = CalculationBase(type="ADDITION", inputs=[1, 2])
    assert calc.type == CalculationType.ADDITION


def test_calculation_update_minimum_inputs():
    """Test CalculationUpdate validates inputs"""
    with pytest.raises(ValidationError):
        CalculationUpdate(inputs=[1])


def test_profile_update_requires_field():
    """Test ProfileUpdate requires at least one field"""
    with pytest.raises(ValidationError) as exc_info:
        ProfileUpdate()
    assert "at least one field" in str(exc_info.value).lower()


def test_profile_update_valid():
    """Test valid ProfileUpdate"""
    profile = ProfileUpdate(username="newuser")
    assert profile.username == "newuser"


def test_password_change_same_password():
    """Test new password must differ from current"""
    with pytest.raises(ValidationError) as exc_info:
        PasswordChange(
            current_password="Pass123!",
            new_password="Pass123!",
            confirm_new_password="Pass123!"
        )
    assert "different" in str(exc_info.value).lower()


def test_password_change_mismatch():
    """Test password confirmation must match"""
    with pytest.raises(ValidationError) as exc_info:
        PasswordChange(
            current_password="OldPass123!",
            new_password="NewPass123!",
            confirm_new_password="Different123!"
        )
    assert "match" in str(exc_info.value).lower()


def test_password_change_weak():
    """Test new password strength validation"""
    with pytest.raises(ValidationError):
        PasswordChange(
            current_password="OldPass123!",
            new_password="weak",
            confirm_new_password="weak"
        )


# ==============================================================================
# Endpoint Tests using TestClient for proper coverage
# ==============================================================================

def test_root_endpoint():
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code == 200


def test_health_endpoint():
    """Test health endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_login_page():
    """Test login page"""
    response = client.get("/login")
    assert response.status_code == 200


def test_register_page():
    """Test register page"""
    response = client.get("/register")
    assert response.status_code == 200


def test_dashboard_page():
    """Test dashboard page"""
    response = client.get("/dashboard")
    assert response.status_code == 200


def test_profile_page_endpoint():
    """Test profile page"""
    response = client.get("/profile")
    assert response.status_code == 200


def register_user(username=None):
    """Helper to register a user"""
    if username is None:
        import time
        username = f"u{int(time.time() * 1000000) % 100000000}"

    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"{username}@test.com",
        "username": username,
        "password": "Pass123!",
        "confirm_password": "Pass123!"
    }
    response = client.post("/auth/register", json=user_data)
    return response, username


def test_register_endpoint():
    """Test user registration"""
    response, _ = register_user()
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert "username" in data


def test_register_duplicate_username():
    """Test duplicate username fails"""
    response1, username = register_user()
    assert response1.status_code == 201

    # Try to register again with same username
    user_data = {
        "first_name": "Test",
        "last_name": "User2",
        "email": f"different@test.com",
        "username": username,
        "password": "Pass123!",
        "confirm_password": "Pass123!"
    }
    response2 = client.post("/auth/register", json=user_data)
    assert response2.status_code == 400


def test_login_endpoint():
    """Test login"""
    response, username = register_user()
    assert response.status_code == 201

    login_data = {
        "username": username,
        "password": "Pass123!"
    }
    login_response = client.post("/auth/login", json=login_data)
    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert "expires_at" in data


def test_login_invalid_credentials():
    """Test login with invalid credentials"""
    login_data = {
        "username": "nonexistent",
        "password": "WrongPass123!"
    }
    response = client.post("/auth/login", json=login_data)
    assert response.status_code == 401


def test_oauth2_token_endpoint():
    """Test OAuth2 token endpoint"""
    response, username = register_user()
    assert response.status_code == 201

    form_data = {
        "username": username,
        "password": "Pass123!"
    }
    token_response = client.post("/auth/token", data=form_data)
    assert token_response.status_code == 200
    data = token_response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def get_auth_headers(username=None):
    """Helper to get auth headers"""
    response, username = register_user(username)
    login_data = {
        "username": username,
        "password": "Pass123!"
    }
    login_response = client.post("/auth/login", json=login_data)
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_create_calculation():
    """Test creating a calculation"""
    headers = get_auth_headers()
    calc_data = {
        "type": "addition",
        "inputs": [1, 2, 3]
    }
    response = client.post("/calculations", json=calc_data, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 6


def test_list_calculations():
    """Test listing calculations"""
    headers = get_auth_headers()

    # Create a calculation
    client.post("/calculations", json={"type": "addition", "inputs": [1, 2]}, headers=headers)

    response = client.get("/calculations", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) >= 1


def test_get_calculation():
    """Test getting a specific calculation"""
    headers = get_auth_headers()

    # Create a calculation
    create_response = client.post("/calculations", json={"type": "addition", "inputs": [1, 2]}, headers=headers)
    calc_id = create_response.json()["id"]

    response = client.get(f"/calculations/{calc_id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == calc_id


def test_get_calculation_invalid_uuid():
    """Test invalid UUID format"""
    headers = get_auth_headers()
    response = client.get("/calculations/invalid-uuid", headers=headers)
    assert response.status_code == 400


def test_get_calculation_not_found():
    """Test non-existent calculation"""
    headers = get_auth_headers()
    fake_uuid = str(uuid4())
    response = client.get(f"/calculations/{fake_uuid}", headers=headers)
    assert response.status_code == 404


def test_update_calculation():
    """Test updating a calculation"""
    headers = get_auth_headers()

    # Create a calculation
    create_response = client.post("/calculations", json={"type": "addition", "inputs": [1, 2]}, headers=headers)
    calc_id = create_response.json()["id"]

    # Update it
    update_data = {"inputs": [5, 10]}
    response = client.put(f"/calculations/{calc_id}", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["result"] == 15


def test_update_calculation_invalid_uuid():
    """Test update with invalid UUID"""
    headers = get_auth_headers()
    response = client.put("/calculations/invalid-uuid", json={"inputs": [1, 2]}, headers=headers)
    assert response.status_code == 400


def test_delete_calculation():
    """Test deleting a calculation"""
    headers = get_auth_headers()

    # Create a calculation
    create_response = client.post("/calculations", json={"type": "addition", "inputs": [1, 2]}, headers=headers)
    calc_id = create_response.json()["id"]

    # Delete it
    response = client.delete(f"/calculations/{calc_id}", headers=headers)
    assert response.status_code == 204


def test_delete_calculation_invalid_uuid():
    """Test delete with invalid UUID"""
    headers = get_auth_headers()
    response = client.delete("/calculations/invalid-uuid", headers=headers)
    assert response.status_code == 400


def test_calculations_require_auth():
    """Test endpoints require authentication"""
    response = client.post("/calculations", json={"type": "addition", "inputs": [1, 2]})
    assert response.status_code == 401

    response = client.get("/calculations")
    assert response.status_code == 401


def test_get_profile():
    """Test getting profile"""
    headers = get_auth_headers()
    response = client.get("/profile/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "username" in data
    assert "calculation_count" in data


def test_update_profile():
    """Test updating profile"""
    headers = get_auth_headers()
    import time
    new_username = f"new{int(time.time() * 1000000) % 100000000}"

    update_data = {
        "username": new_username,
        "first_name": "NewFirst"
    }
    response = client.put("/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == new_username


def test_update_profile_no_fields():
    """Test update with no fields fails"""
    headers = get_auth_headers()
    response = client.put("/profile/me", json={}, headers=headers)
    assert response.status_code == 422


def test_change_password():
    """Test changing password"""
    headers = get_auth_headers()
    password_data = {
        "current_password": "Pass123!",
        "new_password": "NewPass123!",
        "confirm_new_password": "NewPass123!"
    }
    response = client.post("/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 200


def test_change_password_wrong_current():
    """Test wrong current password"""
    headers = get_auth_headers()
    password_data = {
        "current_password": "WrongPass123!",
        "new_password": "NewPass123!",
        "confirm_new_password": "NewPass123!"
    }
    response = client.post("/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 401
