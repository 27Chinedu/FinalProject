# tests/e2e/test_auth_comprehensive.py
# Comprehensive authentication and validation tests to improve E2E coverage

from uuid import uuid4
import pytest
import requests


def register_and_login(fastapi_server: str, user_data: dict) -> dict:
    """Helper function to register and login a user"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    login_url = f'{fastapi_server.rstrip("/")}/auth/login'

    reg_response = requests.post(reg_url, json=user_data)
    assert reg_response.status_code == 201

    login_payload = {
        "username": user_data["username"],
        "password": user_data["password"]
    }
    login_response = requests.post(login_url, json=login_payload)
    assert login_response.status_code == 200
    return login_response.json()

# ============================================================================
# Registration Validation Tests - Testing schema validation paths
# ============================================================================

def test_register_password_too_short(fastapi_server: str):
    """Test registration fails with password shorter than 8 characters"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "Short",
        "last_name": "Pass",
        "email": f"short{uuid4()}@example.com",
        "username": f"short_{uuid4()}",
        "password": "Pass1!",  # Only 6 characters
        "confirm_password": "Pass1!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_password_no_uppercase(fastapi_server: str):
    """Test registration fails without uppercase letter in password"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "NoUpper",
        "last_name": "Case",
        "email": f"noupper{uuid4()}@example.com",
        "username": f"noupper_{uuid4()}",
        "password": "password123!",  # No uppercase
        "confirm_password": "password123!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_password_no_lowercase(fastapi_server: str):
    """Test registration fails without lowercase letter in password"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "NoLower",
        "last_name": "Case",
        "email": f"nolower{uuid4()}@example.com",
        "username": f"nolower_{uuid4()}",
        "password": "PASSWORD123!",  # No lowercase
        "confirm_password": "PASSWORD123!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_password_no_digit(fastapi_server: str):
    """Test registration fails without digit in password"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "NoDigit",
        "last_name": "User",
        "email": f"nodigit{uuid4()}@example.com",
        "username": f"nodigit_{uuid4()}",
        "password": "PasswordOnly!",  # No digit
        "confirm_password": "PasswordOnly!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_password_no_special_char(fastapi_server: str):
    """Test registration fails without special character in password"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "NoSpecial",
        "last_name": "Char",
        "email": f"nospecial{uuid4()}@example.com",
        "username": f"nospecial_{uuid4()}",
        "password": "Password123",  # No special character
        "confirm_password": "Password123"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_password_mismatch(fastapi_server: str):
    """Test registration fails when passwords don't match"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "Mismatch",
        "last_name": "Password",
        "email": f"mismatch{uuid4()}@example.com",
        "username": f"mismatch_{uuid4()}",
        "password": "Password123!",
        "confirm_password": "DifferentPass123!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_username_too_short(fastapi_server: str):
    """Test registration fails with username shorter than 3 characters"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "Short",
        "last_name": "Username",
        "email": f"shortuser{uuid4()}@example.com",
        "username": "ab",  # Only 2 characters
        "password": "Password123!",
        "confirm_password": "Password123!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_invalid_email(fastapi_server: str):
    """Test registration fails with invalid email format"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "Invalid",
        "last_name": "Email",
        "email": "not-an-email",
        "username": f"invalidemail_{uuid4()}",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_empty_first_name(fastapi_server: str):
    """Test registration fails with empty first name"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "",
        "last_name": "User",
        "email": f"nofirst{uuid4()}@example.com",
        "username": f"nofirst_{uuid4()}",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_empty_last_name(fastapi_server: str):
    """Test registration fails with empty last name"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "User",
        "last_name": "",
        "email": f"nolast{uuid4()}@example.com",
        "username": f"nolast_{uuid4()}",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

def test_register_missing_fields(fastapi_server: str):
    """Test registration fails with missing required fields"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'

    # Missing password
    user_data = {
        "first_name": "Missing",
        "last_name": "Fields",
        "email": f"missing{uuid4()}@example.com",
        "username": f"missing_{uuid4()}"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 422

# ============================================================================
# Login Validation Tests
# ============================================================================

def test_login_with_email(fastapi_server: str):
    """Test login works with email instead of username"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    login_url = f'{fastapi_server.rstrip("/")}/auth/login'

    unique_email = f"emaillogin{uuid4()}@example.com"
    user_data = {
        "first_name": "Email",
        "last_name": "Login",
        "email": unique_email,
        "username": f"emaillogin_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    # Register
    reg_response = requests.post(reg_url, json=user_data)
    assert reg_response.status_code == 201

    # Login with email
    login_payload = {
        "username": unique_email,  # Using email as username
        "password": user_data["password"]
    }
    login_response = requests.post(login_url, json=login_payload)
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

def test_login_wrong_username(fastapi_server: str):
    """Test login fails with non-existent username"""
    login_url = f'{fastapi_server.rstrip("/")}/auth/login'
    login_payload = {
        "username": f"nonexistent_{uuid4()}",
        "password": "Password123!"
    }

    response = requests.post(login_url, json=login_payload)
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]

def test_login_wrong_password(fastapi_server: str):
    """Test login fails with wrong password"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    login_url = f'{fastapi_server.rstrip("/")}/auth/login'

    user_data = {
        "first_name": "Wrong",
        "last_name": "Pass",
        "email": f"wrongpass{uuid4()}@example.com",
        "username": f"wrongpass_{uuid4()}",
        "password": "CorrectPass123!",
        "confirm_password": "CorrectPass123!"
    }

    # Register
    requests.post(reg_url, json=user_data)

    # Try to login with wrong password
    login_payload = {
        "username": user_data["username"],
        "password": "WrongPass123!"
    }
    response = requests.post(login_url, json=login_payload)
    assert response.status_code == 401

def test_login_username_too_short(fastapi_server: str):
    """Test login validation fails with username too short"""
    login_url = f'{fastapi_server.rstrip("/")}/auth/login'
    login_payload = {
        "username": "ab",  # Too short
        "password": "Password123!"
    }

    response = requests.post(login_url, json=login_payload)
    assert response.status_code == 422

def test_login_password_too_short(fastapi_server: str):
    """Test login validation fails with password too short"""
    login_url = f'{fastapi_server.rstrip("/")}/auth/login'
    login_payload = {
        "username": "validuser",
        "password": "short"  # Too short
    }

    response = requests.post(login_url, json=login_payload)
    assert response.status_code == 422

# ============================================================================
# OAuth2 Form Login Tests
# ============================================================================

def test_oauth2_form_login(fastapi_server: str):
    """Test OAuth2 form-based login endpoint"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    token_url = f'{fastapi_server.rstrip("/")}/auth/token'

    user_data = {
        "first_name": "OAuth",
        "last_name": "User",
        "email": f"oauth{uuid4()}@example.com",
        "username": f"oauth_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    # Register
    requests.post(reg_url, json=user_data)

    # Login via OAuth2 form endpoint
    form_data = {
        "username": user_data["username"],
        "password": user_data["password"]
    }

    response = requests.post(token_url, data=form_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "token_type" in data
    assert data["token_type"] == "bearer"

def test_oauth2_form_login_invalid(fastapi_server: str):
    """Test OAuth2 form login fails with invalid credentials"""
    token_url = f'{fastapi_server.rstrip("/")}/auth/token'

    form_data = {
        "username": "invaliduser",
        "password": "InvalidPass123!"
    }

    response = requests.post(token_url, data=form_data)
    assert response.status_code == 401

# ============================================================================
# Token and Authentication Dependency Tests
# ============================================================================

def test_access_protected_endpoint_without_token(fastapi_server: str):
    """Test accessing protected endpoint without token fails"""
    calc_url = f'{fastapi_server.rstrip("/")}/calculations'

    response = requests.get(calc_url)
    assert response.status_code == 401

def test_access_protected_endpoint_invalid_token(fastapi_server: str):
    """Test accessing protected endpoint with invalid token fails"""
    calc_url = f'{fastapi_server.rstrip("/")}/calculations'
    headers = {"Authorization": "Bearer invalid_token_string"}

    response = requests.get(calc_url, headers=headers)
    assert response.status_code == 401

def test_access_protected_endpoint_malformed_token(fastapi_server: str):
    """Test accessing protected endpoint with malformed token fails"""
    calc_url = f'{fastapi_server.rstrip("/")}/calculations'
    headers = {"Authorization": "InvalidFormat"}

    response = requests.get(calc_url)
    assert response.status_code == 401

def test_token_contains_full_user_payload(fastapi_server: str):
    """Test that login response contains complete user information"""
    user_data = {
        "first_name": "Token",
        "last_name": "Payload",
        "email": f"tokenpayload{uuid4()}@example.com",
        "username": f"tokenpayload_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)

    # Verify all fields are present
    assert "user_id" in token_data
    assert "username" in token_data
    assert "email" in token_data
    assert "first_name" in token_data
    assert "last_name" in token_data
    assert "is_active" in token_data
    assert "is_verified" in token_data
    assert "expires_at" in token_data

    # Verify values match
    assert token_data["username"] == user_data["username"]
    assert token_data["email"] == user_data["email"]
    assert token_data["first_name"] == user_data["first_name"]
    assert token_data["last_name"] == user_data["last_name"]
    assert token_data["is_active"] is True
    assert token_data["is_verified"] is False

# ============================================================================
# User Model Edge Cases
# ============================================================================

def test_duplicate_username_registration(fastapi_server: str):
    """Test that registering with duplicate username fails"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'

    username = f"duplicate_{uuid4()}"
    user_data_1 = {
        "first_name": "First",
        "last_name": "User",
        "email": f"first{uuid4()}@example.com",
        "username": username,
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    # Register first user
    response1 = requests.post(reg_url, json=user_data_1)
    assert response1.status_code == 201

    # Try to register second user with same username
    user_data_2 = {
        "first_name": "Second",
        "last_name": "User",
        "email": f"second{uuid4()}@example.com",
        "username": username,  # Same username
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    response2 = requests.post(reg_url, json=user_data_2)
    assert response2.status_code == 400
    assert "already exists" in response2.json()["detail"].lower()

def test_duplicate_email_registration(fastapi_server: str):
    """Test that registering with duplicate email fails"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'

    email = f"duplicate{uuid4()}@example.com"
    user_data_1 = {
        "first_name": "First",
        "last_name": "User",
        "email": email,
        "username": f"first_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    # Register first user
    response1 = requests.post(reg_url, json=user_data_1)
    assert response1.status_code == 201

    # Try to register second user with same email
    user_data_2 = {
        "first_name": "Second",
        "last_name": "User",
        "email": email,  # Same email
        "username": f"second_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    response2 = requests.post(reg_url, json=user_data_2)
    assert response2.status_code == 400
    assert "already exists" in response2.json()["detail"].lower()

# ============================================================================
# Calculation Authorization Tests
# ============================================================================

def test_user_cannot_access_other_user_calculation(fastapi_server: str):
    """Test that users cannot access calculations belonging to other users"""
    # Create user 1 and their calculation
    user1_data = {
        "first_name": "User",
        "last_name": "One",
        "email": f"user1{uuid4()}@example.com",
        "username": f"user1_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    token1_data = register_and_login(fastapi_server.rstrip("/"), user1_data)
    headers1 = {"Authorization": f"Bearer {token1_data['access_token']}"}

    # Create calculation for user 1
    calc_data = {
        "type": "addition",
        "inputs": [1, 2, 3]
    }
    calc_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers1)
    calc_id = calc_response.json()["id"]

    # Create user 2
    user2_data = {
        "first_name": "User",
        "last_name": "Two",
        "email": f"user2{uuid4()}@example.com",
        "username": f"user2_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    token2_data = register_and_login(fastapi_server.rstrip("/"), user2_data)
    headers2 = {"Authorization": f"Bearer {token2_data['access_token']}"}

    # User 2 tries to access User 1's calculation
    response = requests.get(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', headers=headers2)
    assert response.status_code == 404  # Not found (for security)

def test_user_cannot_update_other_user_calculation(fastapi_server: str):
    """Test that users cannot update calculations belonging to other users"""
    # Create user 1 and their calculation
    user1_data = {
        "first_name": "User",
        "last_name": "One",
        "email": f"user1upd{uuid4()}@example.com",
        "username": f"user1upd_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    token1_data = register_and_login(fastapi_server.rstrip("/"), user1_data)
    headers1 = {"Authorization": f"Bearer {token1_data['access_token']}"}

    # Create calculation for user 1
    calc_data = {
        "type": "addition",
        "inputs": [1, 2, 3]
    }
    calc_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers1)
    calc_id = calc_response.json()["id"]

    # Create user 2
    user2_data = {
        "first_name": "User",
        "last_name": "Two",
        "email": f"user2upd{uuid4()}@example.com",
        "username": f"user2upd_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    token2_data = register_and_login(fastapi_server.rstrip("/"), user2_data)
    headers2 = {"Authorization": f"Bearer {token2_data['access_token']}"}

    # User 2 tries to update User 1's calculation
    update_data = {"inputs": [5, 6, 7]}
    response = requests.put(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', json=update_data, headers=headers2)
    assert response.status_code == 404

def test_user_cannot_delete_other_user_calculation(fastapi_server: str):
    """Test that users cannot delete calculations belonging to other users"""
    # Create user 1 and their calculation
    user1_data = {
        "first_name": "User",
        "last_name": "One",
        "email": f"user1del{uuid4()}@example.com",
        "username": f"user1del_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    token1_data = register_and_login(fastapi_server.rstrip("/"), user1_data)
    headers1 = {"Authorization": f"Bearer {token1_data['access_token']}"}

    # Create calculation for user 1
    calc_data = {
        "type": "addition",
        "inputs": [1, 2, 3]
    }
    calc_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers1)
    calc_id = calc_response.json()["id"]

    # Create user 2
    user2_data = {
        "first_name": "User",
        "last_name": "Two",
        "email": f"user2del{uuid4()}@example.com",
        "username": f"user2del_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    token2_data = register_and_login(fastapi_server.rstrip("/"), user2_data)
    headers2 = {"Authorization": f"Bearer {token2_data['access_token']}"}

    # User 2 tries to delete User 1's calculation
    response = requests.delete(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', headers=headers2)
    assert response.status_code == 404

# ============================================================================
# Web Routes Tests
# ============================================================================

def test_home_page_accessible(fastapi_server: str):
    """Test home page is accessible"""
    response = requests.get(f'{fastapi_server.rstrip("/")}/')
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")

def test_login_page_accessible(fastapi_server: str):
    """Test login page is accessible"""
    response = requests.get(f'{fastapi_server.rstrip("/")}/login')
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")

def test_register_page_accessible(fastapi_server: str):
    """Test register page is accessible"""
    response = requests.get(f'{fastapi_server.rstrip("/")}/register')
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")

def test_dashboard_page_accessible(fastapi_server: str):
    """Test dashboard page is accessible"""
    response = requests.get(f'{fastapi_server.rstrip("/")}/dashboard')
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")

def test_profile_page_accessible(fastapi_server: str):
    """Test profile page is accessible"""
    response = requests.get(f'{fastapi_server.rstrip("/")}/profile')
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")

# ============================================================================
# Calculation Type Validation Tests
# ============================================================================

def test_calculation_invalid_type(fastapi_server: str):
    """Test calculation with invalid type fails"""
    user_data = {
        "first_name": "Invalid",
        "last_name": "Type",
        "email": f"invalidtype{uuid4()}@example.com",
        "username": f"invalidtype_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "invalid_operation",
        "inputs": [1, 2, 3]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code in [400, 422]

def test_calculation_with_string_inputs(fastapi_server: str):
    """Test calculation with non-numeric inputs fails"""
    user_data = {
        "first_name": "String",
        "last_name": "Inputs",
        "email": f"stringinputs{uuid4()}@example.com",
        "username": f"stringinputs_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": ["abc", "def"]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

# ============================================================================
# Last Login Tracking Tests
# ============================================================================

def test_last_login_updated_on_login(fastapi_server: str):
    """Test that last_login is updated when user logs in"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    login_url = f'{fastapi_server.rstrip("/")}/auth/login'
    profile_url = f'{fastapi_server.rstrip("/")}/profile/me'

    user_data = {
        "first_name": "Last",
        "last_name": "Login",
        "email": f"lastlogin{uuid4()}@example.com",
        "username": f"lastlogin_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    # Register
    requests.post(reg_url, json=user_data)

    # First login
    login_payload = {
        "username": user_data["username"],
        "password": user_data["password"]
    }
    response1 = requests.post(login_url, json=login_payload)
    token1 = response1.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    # Get profile to check last_login
    profile1 = requests.get(profile_url, headers=headers1).json()
    last_login1 = profile1.get("last_login")
    assert last_login1 is not None

    # Wait a bit and login again
    import time
    time.sleep(1)

    response2 = requests.post(login_url, json=login_payload)
    token2 = response2.json()["access_token"]
    headers2 = {"Authorization": f"Bearer {token2}"}

    # Get profile again
    profile2 = requests.get(profile_url, headers=headers2).json()
    last_login2 = profile2.get("last_login")
    assert last_login2 is not None

    # Last login should be updated (different from first login)
    assert last_login2 != last_login1

# ============================================================================
# Additional Edge Cases
# ============================================================================

def test_update_calculation_empty_inputs(fastapi_server: str):
    """Test updating calculation with empty inputs fails"""
    user_data = {
        "first_name": "Empty",
        "last_name": "Update",
        "email": f"emptyupdate{uuid4()}@example.com",
        "username": f"emptyupdate_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Create calculation
    calc_data = {
        "type": "addition",
        "inputs": [1, 2, 3]
    }
    calc_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    calc_id = calc_response.json()["id"]

    # Try to update with empty inputs
    update_data = {"inputs": []}
    response = requests.put(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', json=update_data, headers=headers)
    assert response.status_code == 422

def test_registration_response_structure(fastapi_server: str):
    """Test registration response has correct structure"""
    reg_url = f'{fastapi_server.rstrip("/")}/auth/register'
    user_data = {
        "first_name": "Structure",
        "last_name": "Test",
        "email": f"structure{uuid4()}@example.com",
        "username": f"structure_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    response = requests.post(reg_url, json=user_data)
    assert response.status_code == 201

    data = response.json()
    required_fields = ["id", "username", "email", "first_name", "last_name",
                      "is_active", "is_verified", "created_at", "updated_at"]

    for field in required_fields:
        assert field in data, f"Missing field: {field}"

    # Password should NOT be in response
    assert "password" not in data
    assert "hashed_password" not in data

def test_calculation_result_persistence(fastapi_server: str):
    """Test that calculation results are correctly persisted"""
    user_data = {
        "first_name": "Result",
        "last_name": "Persist",
        "email": f"resultpersist{uuid4()}@example.com",
        "username": f"resultpersist_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Create calculation
    calc_data = {
        "type": "multiplication",
        "inputs": [3, 4, 5]
    }
    create_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    calc_id = create_response.json()["id"]
    expected_result = 60  # 3 * 4 * 5

    # Retrieve and verify result
    get_response = requests.get(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', headers=headers)
    assert get_response.json()["result"] == expected_result
