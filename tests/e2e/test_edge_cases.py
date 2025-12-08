# tests/e2e/test_edge_cases.py

from uuid import uuid4
import pytest
import requests

@pytest.fixture
def base_url(fastapi_server: str) -> str:
    """Returns the FastAPI server base URL without a trailing slash"""
    return fastapi_server.rstrip("/")

def register_and_login(base_url: str, user_data: dict) -> dict:
    """Helper function to register and login a user"""
    reg_url = f"{base_url}/auth/register"
    login_url = f"{base_url}/auth/login"
    
    reg_response = requests.post(reg_url, json=user_data)
    assert reg_response.status_code == 201
    
    login_payload = {
        "username": user_data["username"],
        "password": user_data["password"]
    }
    login_response = requests.post(login_url, json=login_payload)
    assert login_response.status_code == 200
    return login_response.json()

def test_register_validation_error(base_url: str):
    """Test registration with validation errors"""
    reg_url = f"{base_url}/auth/register"
    
    # Missing confirm_password
    invalid_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"test{uuid4()}@example.com",
        "username": f"test_{uuid4()}",
        "password": "TestPass123!"
        # Missing confirm_password
    }
    
    response = requests.post(reg_url, json=invalid_data)
    assert response.status_code == 422  # Validation error

def test_calculation_with_empty_inputs(base_url: str):
    """Test calculation with empty inputs array"""
    user_data = {
        "first_name": "Empty",
        "last_name": "Test",
        "email": f"empty{uuid4()}@example.com",
        "username": f"empty_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    
    calc_url = f"{base_url}/calculations"
    payload = {
        "type": "addition",
        "inputs": []
    }
    
    response = requests.post(calc_url, json=payload, headers=headers)
    assert response.status_code == 422

def test_calculation_invalid_type_format(base_url: str):
    """Test calculation with invalid type format"""
    user_data = {
        "first_name": "Invalid",
        "last_name": "Type",
        "email": f"invalid{uuid4()}@example.com",
        "username": f"invalid_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    
    calc_url = f"{base_url}/calculations"
    payload = {
        "type": 123,  # Should be string
        "inputs": [1, 2]
    }
    
    response = requests.post(calc_url, json=payload, headers=headers)
    assert response.status_code == 422

def test_update_calculation_not_found(base_url: str):
    """Test updating non-existent calculation"""
    user_data = {
        "first_name": "Update",
        "last_name": "NotFound",
        "email": f"update{uuid4()}@example.com",
        "username": f"update_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    
    # Try to update non-existent calculation
    fake_id = str(uuid4())
    update_url = f"{base_url}/calculations/{fake_id}"
    payload = {"inputs": [5, 10]}
    
    response = requests.put(update_url, json=payload, headers=headers)
    assert response.status_code == 404

def test_delete_calculation_not_found(base_url: str):
    """Test deleting non-existent calculation"""
    user_data = {
        "first_name": "Delete",
        "last_name": "NotFound",
        "email": f"delete{uuid4()}@example.com",
        "username": f"delete_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    
    # Try to delete non-existent calculation
    fake_id = str(uuid4())
    delete_url = f"{base_url}/calculations/{fake_id}"
    
    response = requests.delete(delete_url, headers=headers)
    assert response.status_code == 404

def test_get_calculation_not_found(base_url: str):
    """Test getting non-existent calculation"""
    user_data = {
        "first_name": "Get",
        "last_name": "NotFound",
        "email": f"get{uuid4()}@example.com",
        "username": f"get_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    
    # Try to get non-existent calculation
    fake_id = str(uuid4())
    get_url = f"{base_url}/calculations/{fake_id}"
    
    response = requests.get(get_url, headers=headers)
    assert response.status_code == 404

def test_calculation_with_invalid_uuid_format(base_url: str):
    """Test accessing calculation with invalid UUID format"""
    user_data = {
        "first_name": "Invalid",
        "last_name": "UUID",
        "email": f"uuid{uuid4()}@example.com",
        "username": f"uuid_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    
    # Try with invalid UUID
    invalid_id = "not-a-valid-uuid"
    get_url = f"{base_url}/calculations/{invalid_id}"
    
    response = requests.get(get_url, headers=headers)
    assert response.status_code == 400
    assert "Invalid calculation id format" in response.json()["detail"]

def test_update_calculation_with_invalid_uuid(base_url: str):
    """Test updating calculation with invalid UUID"""
    user_data = {
        "first_name": "Update",
        "last_name": "Invalid",
        "email": f"updinv{uuid4()}@example.com",
        "username": f"updinv_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    
    invalid_id = "invalid-uuid"
    update_url = f"{base_url}/calculations/{invalid_id}"
    payload = {"inputs": [5, 10]}
    
    response = requests.put(update_url, json=payload, headers=headers)
    assert response.status_code == 400

def test_delete_calculation_with_invalid_uuid(base_url: str):
    """Test deleting calculation with invalid UUID"""
    user_data = {
        "first_name": "Delete",
        "last_name": "Invalid",
        "email": f"delinv{uuid4()}@example.com",
        "username": f"delinv_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    
    invalid_id = "invalid-uuid"
    delete_url = f"{base_url}/calculations/{invalid_id}"
    
    response = requests.delete(delete_url, headers=headers)
    assert response.status_code == 400

def test_list_calculations_empty(base_url: str):
    """Test listing calculations when user has none"""
    user_data = {
        "first_name": "Empty",
        "last_name": "List",
        "email": f"emptylist{uuid4()}@example.com",
        "username": f"emptylist_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    
    list_url = f"{base_url}/calculations"
    response = requests.get(list_url, headers=headers)
    
    assert response.status_code == 200
    assert response.json() == []

def test_web_routes_accessible(base_url: str):
    """Test that web routes are accessible"""
    routes = ["/", "/login", "/register", "/dashboard", "/profile"]
    
    for route in routes:
        response = requests.get(f"{base_url}{route}")
        assert response.status_code == 200

def test_health_endpoint_structure(base_url: str):
    """Test health endpoint returns correct structure"""
    response = requests.get(f"{base_url}/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "ok"

def test_token_response_structure(base_url: str):
    """Test token response has all required fields"""
    user_data = {
        "first_name": "Token",
        "last_name": "Test",
        "email": f"token{uuid4()}@example.com",
        "username": f"token_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    
    required_fields = [
        "access_token", "refresh_token", "token_type", "expires_at",
        "user_id", "username", "email", "first_name", "last_name",
        "is_active", "is_verified"
    ]
    
    for field in required_fields:
        assert field in token_data, f"Missing field: {field}"

def test_oauth2_token_endpoint(base_url: str):
    """Test OAuth2 token endpoint"""
    reg_url = f"{base_url}/auth/register"
    token_url = f"{base_url}/auth/token"
    
    user_data = {
        "first_name": "OAuth",
        "last_name": "Test",
        "email": f"oauth{uuid4()}@example.com",
        "username": f"oauth_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register
    requests.post(reg_url, json=user_data)
    
    # Login via OAuth2 token endpoint
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