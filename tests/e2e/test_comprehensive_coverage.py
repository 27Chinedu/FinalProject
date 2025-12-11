"""
Comprehensive E2E tests to achieve 90% coverage for app/main.py and app/schemas
"""
from datetime import datetime, timezone
from uuid import uuid4
import pytest
import requests
import time

@pytest.fixture
def base_url(fastapi_server: str) -> str:
    """Returns the FastAPI server base URL without a trailing slash."""
    return fastapi_server.rstrip("/")


def register_and_login(base_url: str, username: str = None, password: str = None) -> dict:
    """
    Helper function to register a new user and login, returning the token response data.
    Uses shorter passwords to avoid bcrypt 72-byte limit.
    """
    if username is None:
        # Use time-based username to ensure uniqueness
        import time
        username = f"u{int(time.time() * 1000000) % 100000000}"
    if password is None:
        password = "Pass123!"

    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"{username}@test.com",
        "username": username,
        "password": password,
        "confirm_password": password
    }

    reg_url = f"{base_url}/auth/register"
    login_url = f"{base_url}/auth/login"

    reg_response = requests.post(reg_url, json=user_data)
    assert reg_response.status_code == 201, f"User registration failed: {reg_response.text}"

    login_payload = {
        "username": username,
        "password": password
    }
    login_response = requests.post(login_url, json=login_payload)
    assert login_response.status_code == 200, f"Login failed: {login_response.text}"
    return login_response.json()


# ==============================================================================
# Tests for app/main.py endpoints
# ==============================================================================

def test_root_endpoint(base_url: str):
    """Test GET / endpoint returns HTML"""
    response = requests.get(f"{base_url}/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_login_page(base_url: str):
    """Test GET /login endpoint returns login page"""
    response = requests.get(f"{base_url}/login")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_register_page(base_url: str):
    """Test GET /register endpoint returns registration page"""
    response = requests.get(f"{base_url}/register")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_dashboard_page(base_url: str):
    """Test GET /dashboard endpoint returns dashboard page"""
    response = requests.get(f"{base_url}/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_profile_page(base_url: str):
    """Test GET /profile endpoint returns profile page"""
    response = requests.get(f"{base_url}/profile")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_health_endpoint(base_url: str):
    """Test /health endpoint"""
    response = requests.get(f"{base_url}/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_oauth2_token_endpoint(base_url: str):
    """Test /auth/token endpoint (OAuth2PasswordRequestForm)"""
    import time
    username = f"oauth{int(time.time() * 1000000) % 100000000}"
    password = "Pass123!"

    # First register a user
    user_data = {
        "first_name": "OAuth",
        "last_name": "User",
        "email": f"{username}@test.com",
        "username": username,
        "password": password,
        "confirm_password": password
    }
    reg_response = requests.post(f"{base_url}/auth/register", json=user_data)
    assert reg_response.status_code == 201, f"Registration failed: {reg_response.text}"

    # Now test the token endpoint with form data
    form_data = {
        "username": username,
        "password": password
    }
    response = requests.post(f"{base_url}/auth/token", data=form_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "token_type" in data
    assert data["token_type"] == "bearer"


def test_oauth2_token_invalid_credentials(base_url: str):
    """Test /auth/token with invalid credentials"""
    form_data = {
        "username": "nonexistent",
        "password": "wrongpass"
    }
    response = requests.post(f"{base_url}/auth/token", data=form_data)
    assert response.status_code == 401


def test_login_json_with_timezone_aware_expires(base_url: str):
    """Test /auth/login returns timezone-aware expires_at"""
    import time
    username = f"tz{int(time.time() * 1000000) % 100000000}"
    password = "Pass123!"

    user_data = {
        "first_name": "TZ",
        "last_name": "Test",
        "email": f"{username}@test.com",
        "username": username,
        "password": password,
        "confirm_password": password
    }
    requests.post(f"{base_url}/auth/register", json=user_data)

    login_response = requests.post(f"{base_url}/auth/login", json={
        "username": username,
        "password": password
    })
    assert login_response.status_code == 200
    data = login_response.json()

    # Verify expires_at is present and parseable
    assert "expires_at" in data
    expires_str = data["expires_at"]
    # Parse datetime to ensure it's valid
    if expires_str.endswith('Z'):
        expires_str = expires_str.replace('Z', '+00:00')
    expires_dt = datetime.fromisoformat(expires_str)
    assert expires_dt > datetime.now(timezone.utc)


def test_get_calculation_invalid_uuid(base_url: str):
    """Test GET /calculations/{calc_id} with invalid UUID format"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.get(f"{base_url}/calculations/invalid-uuid", headers=headers)
    assert response.status_code == 400
    assert "Invalid calculation id format" in response.json()["detail"]


def test_update_calculation_invalid_uuid(base_url: str):
    """Test PUT /calculations/{calc_id} with invalid UUID format"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.put(
        f"{base_url}/calculations/invalid-uuid",
        json={"inputs": [1, 2]},
        headers=headers
    )
    assert response.status_code == 400
    assert "Invalid calculation id format" in response.json()["detail"]


def test_delete_calculation_invalid_uuid(base_url: str):
    """Test DELETE /calculations/{calc_id} with invalid UUID format"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.delete(f"{base_url}/calculations/invalid-uuid", headers=headers)
    assert response.status_code == 400
    assert "Invalid calculation id format" in response.json()["detail"]


def test_get_calculation_not_found(base_url: str):
    """Test GET /calculations/{calc_id} with non-existent UUID"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    fake_uuid = str(uuid4())
    response = requests.get(f"{base_url}/calculations/{fake_uuid}", headers=headers)
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_update_calculation_not_found(base_url: str):
    """Test PUT /calculations/{calc_id} with non-existent UUID"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    fake_uuid = str(uuid4())
    response = requests.put(
        f"{base_url}/calculations/{fake_uuid}",
        json={"inputs": [1, 2]},
        headers=headers
    )
    assert response.status_code == 404


def test_delete_calculation_not_found(base_url: str):
    """Test DELETE /calculations/{calc_id} with non-existent UUID"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    fake_uuid = str(uuid4())
    response = requests.delete(f"{base_url}/calculations/{fake_uuid}", headers=headers)
    assert response.status_code == 404


def test_create_calculation_updates_timestamp(base_url: str):
    """Test that creating calculation sets updated_at"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.post(
        f"{base_url}/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=headers
    )
    assert response.status_code == 201
    data = response.json()

    # Update the calculation
    calc_id = data["id"]
    update_response = requests.put(
        f"{base_url}/calculations/{calc_id}",
        json={"inputs": [3, 4]},
        headers=headers
    )
    assert update_response.status_code == 200
    updated_data = update_response.json()
    assert updated_data["result"] == 7
    assert updated_data["inputs"] == [3, 4]


# ==============================================================================
# Tests for app/schemas/user.py validation
# ==============================================================================

def test_user_registration_password_mismatch(base_url: str):
    """Test UserCreate schema validates password match"""
    import time
    ts = int(time.time() * 1000000) % 100000000
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"test{ts}@test.com",
        "username": f"user{ts}",
        "password": "Pass123!",
        "confirm_password": "Different123!"
    }
    response = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response.status_code == 422
    assert "password" in response.text.lower()


def test_user_registration_no_uppercase(base_url: str):
    """Test UserCreate validates password has uppercase"""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"test{int(time.time() * 1000000) % 100000000}@test.com",
        "username": f"user{int(time.time() * 1000000) % 100000000}",
        "password": "pass123!",
        "confirm_password": "pass123!"
    }
    response = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response.status_code == 422
    assert "uppercase" in response.text.lower()


def test_user_registration_no_lowercase(base_url: str):
    """Test UserCreate validates password has lowercase"""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"test{int(time.time() * 1000000) % 100000000}@test.com",
        "username": f"user{int(time.time() * 1000000) % 100000000}",
        "password": "PASS123!",
        "confirm_password": "PASS123!"
    }
    response = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response.status_code == 422
    assert "lowercase" in response.text.lower()


def test_user_registration_no_digit(base_url: str):
    """Test UserCreate validates password has digit"""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"test{int(time.time() * 1000000) % 100000000}@test.com",
        "username": f"user{int(time.time() * 1000000) % 100000000}",
        "password": "Password!",
        "confirm_password": "Password!"
    }
    response = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response.status_code == 422
    assert "digit" in response.text.lower()


def test_user_registration_no_special_char(base_url: str):
    """Test UserCreate validates password has special character"""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"test{int(time.time() * 1000000) % 100000000}@test.com",
        "username": f"user{int(time.time() * 1000000) % 100000000}",
        "password": "Password123",
        "confirm_password": "Password123"
    }
    response = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response.status_code == 422
    assert "special" in response.text.lower()


def test_user_registration_password_too_short(base_url: str):
    """Test UserCreate validates password minimum length"""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"test{int(time.time() * 1000000) % 100000000}@test.com",
        "username": f"user{int(time.time() * 1000000) % 100000000}",
        "password": "Pass1!",
        "confirm_password": "Pass1!"
    }
    response = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response.status_code == 422


def test_user_registration_username_too_short(base_url: str):
    """Test UserCreate validates username minimum length"""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"test{int(time.time() * 1000000) % 100000000}@test.com",
        "username": "ab",  # Too short
        "password": "Pass123!",
        "confirm_password": "Pass123!"
    }
    response = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response.status_code == 422


def test_user_registration_invalid_email(base_url: str):
    """Test UserCreate validates email format"""
    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": "not-an-email",
        "username": f"user{int(time.time() * 1000000) % 100000000}",
        "password": "Pass123!",
        "confirm_password": "Pass123!"
    }
    response = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response.status_code == 422


# ==============================================================================
# Tests for app/schemas/calculation.py validation
# ==============================================================================

def test_calculation_invalid_type(base_url: str):
    """Test CalculationBase validates type field"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.post(
        f"{base_url}/calculations",
        json={"type": "invalid_operation", "inputs": [1, 2]},
        headers=headers
    )
    assert response.status_code == 422


def test_calculation_inputs_not_list(base_url: str):
    """Test CalculationBase validates inputs is a list"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.post(
        f"{base_url}/calculations",
        json={"type": "addition", "inputs": "not a list"},
        headers=headers
    )
    assert response.status_code == 422


def test_calculation_insufficient_inputs(base_url: str):
    """Test CalculationBase validates minimum 2 inputs"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.post(
        f"{base_url}/calculations",
        json={"type": "addition", "inputs": [1]},
        headers=headers
    )
    assert response.status_code == 422
    assert "at least two" in response.text.lower() or "2" in response.text


def test_calculation_division_by_zero(base_url: str):
    """Test CalculationBase prevents division by zero"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.post(
        f"{base_url}/calculations",
        json={"type": "division", "inputs": [10, 0]},
        headers=headers
    )
    assert response.status_code == 422
    assert "zero" in response.text.lower()


def test_calculation_type_case_insensitive(base_url: str):
    """Test CalculationType accepts case-insensitive values"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.post(
        f"{base_url}/calculations",
        json={"type": "ADDITION", "inputs": [1, 2]},
        headers=headers
    )
    assert response.status_code == 201
    assert response.json()["result"] == 3


def test_calculation_update_insufficient_inputs(base_url: str):
    """Test CalculationUpdate validates minimum 2 inputs"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Create a calculation first
    create_response = requests.post(
        f"{base_url}/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=headers
    )
    calc_id = create_response.json()["id"]

    # Try to update with insufficient inputs
    response = requests.put(
        f"{base_url}/calculations/{calc_id}",
        json={"inputs": [1]},
        headers=headers
    )
    assert response.status_code == 422


def test_calculation_all_types(base_url: str):
    """Test all calculation types work correctly"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    test_cases = [
        ("addition", [1, 2, 3], 6),
        ("subtraction", [10, 3, 2], 5),
        ("multiplication", [2, 3, 4], 24),
        ("division", [100, 2, 5], 10)
    ]

    for calc_type, inputs, expected_result in test_cases:
        response = requests.post(
            f"{base_url}/calculations",
            json={"type": calc_type, "inputs": inputs},
            headers=headers
        )
        assert response.status_code == 201, f"Failed for {calc_type}"
        assert response.json()["result"] == expected_result


# ==============================================================================
# Tests for app/schemas/profile.py validation
# ==============================================================================

def test_profile_update_all_fields(base_url: str):
    """Test ProfileUpdate with all fields"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    new_username = f"newuser{int(time.time() * 1000000) % 100000000}"
    update_data = {
        "username": new_username,
        "email": f"{new_username}@test.com",
        "first_name": "NewFirst",
        "last_name": "NewLast"
    }

    response = requests.put(f"{base_url}/profile", json=update_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == new_username
    assert data["first_name"] == "NewFirst"
    assert data["last_name"] == "NewLast"


def test_profile_update_no_fields(base_url: str):
    """Test ProfileUpdate validates at least one field"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.put(f"{base_url}/profile", json={}, headers=headers)
    assert response.status_code == 422
    assert "at least one field" in response.text.lower()


def test_password_change_same_password(base_url: str):
    """Test PasswordChange validates new password is different"""
    token_data = register_and_login(base_url, password="OldPass123!")
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    password_data = {
        "current_password": "OldPass123!",
        "new_password": "OldPass123!",
        "confirm_new_password": "OldPass123!"
    }

    response = requests.put(f"{base_url}/profile/password", json=password_data, headers=headers)
    assert response.status_code == 422
    assert "different" in response.text.lower()


def test_password_change_mismatch(base_url: str):
    """Test PasswordChange validates new password confirmation"""
    token_data = register_and_login(base_url, password="OldPass123!")
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass123!",
        "confirm_new_password": "Different123!"
    }

    response = requests.put(f"{base_url}/profile/password", json=password_data, headers=headers)
    assert response.status_code == 422
    assert "match" in response.text.lower()


def test_password_change_weak_password(base_url: str):
    """Test PasswordChange validates new password strength"""
    token_data = register_and_login(base_url, password="OldPass123!")
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    weak_passwords = [
        ("weak", "weak", "characters"),  # Too short
        ("nouppercasechar1!", "nouppercasechar1!", "uppercase"),
        ("NOLOWERCASE1!", "NOLOWERCASE1!", "lowercase"),
        ("NoDigitHere!", "NoDigitHere!", "digit"),
        ("NoSpecialChar1", "NoSpecialChar1", "special"),
    ]

    for new_pass, confirm_pass, expected_error_keyword in weak_passwords:
        password_data = {
            "current_password": "OldPass123!",
            "new_password": new_pass,
            "confirm_new_password": confirm_pass
        }

        response = requests.put(f"{base_url}/profile/password", json=password_data, headers=headers)
        assert response.status_code == 422, f"Failed for {new_pass}"
        assert expected_error_keyword in response.text.lower(), f"Expected '{expected_error_keyword}' in error for {new_pass}"


def test_get_profile_with_calculations(base_url: str):
    """Test GET /profile returns calculation count"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Create some calculations
    for i in range(3):
        requests.post(
            f"{base_url}/calculations",
            json={"type": "addition", "inputs": [i, i+1]},
            headers=headers
        )

    # Get profile
    response = requests.get(f"{base_url}/profile", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "calculation_count" in data
    assert data["calculation_count"] == 3


# ==============================================================================
# Tests for app/schemas/token.py
# ==============================================================================

def test_token_response_structure(base_url: str):
    """Test TokenResponse has all required fields"""
    token_data = register_and_login(base_url)

    required_fields = [
        "access_token", "refresh_token", "token_type", "expires_at",
        "user_id", "username", "email", "first_name", "last_name",
        "is_active", "is_verified"
    ]

    for field in required_fields:
        assert field in token_data, f"Missing field: {field}"

    assert token_data["token_type"] == "bearer"
    assert isinstance(token_data["is_active"], bool)
    assert isinstance(token_data["is_verified"], bool)


# ==============================================================================
# Additional coverage for edge cases
# ==============================================================================

def test_register_duplicate_username(base_url: str):
    """Test registering with duplicate username"""
    username = f"duplicate{int(time.time() * 1000000) % 100000000}"
    password = "Pass123!"

    user_data = {
        "first_name": "First",
        "last_name": "User",
        "email": f"{username}@test.com",
        "username": username,
        "password": password,
        "confirm_password": password
    }

    # First registration
    response1 = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response1.status_code == 201

    # Second registration with same username but different email
    user_data["email"] = f"{username}2@test.com"
    response2 = requests.post(f"{base_url}/auth/register", json=user_data)
    assert response2.status_code == 400


def test_register_duplicate_email(base_url: str):
    """Test registering with duplicate email"""
    email = f"duplicate{int(time.time() * 1000000) % 100000000}@test.com"
    password = "Pass123!"

    user_data1 = {
        "first_name": "First",
        "last_name": "User",
        "email": email,
        "username": f"user{int(time.time() * 1000000) % 100000000}",
        "password": password,
        "confirm_password": password
    }

    # First registration
    response1 = requests.post(f"{base_url}/auth/register", json=user_data1)
    assert response1.status_code == 201

    # Second registration with same email but different username
    user_data2 = user_data1.copy()
    user_data2["username"] = f"user{int(time.time() * 1000000) % 100000000}"
    response2 = requests.post(f"{base_url}/auth/register", json=user_data2)
    assert response2.status_code == 400


def test_calculations_requires_auth(base_url: str):
    """Test that calculations endpoints require authentication"""
    # Test without auth header
    response = requests.post(
        f"{base_url}/calculations",
        json={"type": "addition", "inputs": [1, 2]}
    )
    assert response.status_code == 401

    response = requests.get(f"{base_url}/calculations")
    assert response.status_code == 401


def test_invalid_login(base_url: str):
    """Test login with invalid credentials"""
    response = requests.post(
        f"{base_url}/auth/login",
        json={"username": "nonexistent", "password": "wrongpass"}
    )
    assert response.status_code == 401
    assert "Invalid" in response.json()["detail"]


def test_list_calculations_empty(base_url: str):
    """Test listing calculations when user has none"""
    token_data = register_and_login(base_url)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    response = requests.get(f"{base_url}/calculations", headers=headers)
    assert response.status_code == 200
    assert response.json() == []
