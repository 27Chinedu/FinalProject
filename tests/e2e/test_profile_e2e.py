# tests/e2e/test_profile_e2e.py

from datetime import datetime, timezone
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
    assert reg_response.status_code == 201, f"User registration failed: {reg_response.text}"
    
    login_payload = {
        "username": user_data["username"],
        "password": user_data["password"]
    }
    login_response = requests.post(login_url, json=login_payload)
    assert login_response.status_code == 200, f"Login failed: {login_response.text}"
    return login_response.json()

# ============================================================================
# POSITIVE TESTS
# ============================================================================

def test_get_profile_positive(base_url: str):
    """Test getting user profile with valid authentication"""
    user_data = {
        "first_name": "Profile",
        "last_name": "Tester",
        "email": f"profile{uuid4()}@example.com",
        "username": f"profiletest_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Get profile
    response = requests.get(f"{base_url}/profile/me", headers=headers)
    assert response.status_code == 200, f"Get profile failed: {response.text}"
    
    profile = response.json()
    assert profile["username"] == user_data["username"]
    assert profile["email"] == user_data["email"]
    assert profile["first_name"] == user_data["first_name"]
    assert profile["last_name"] == user_data["last_name"]
    assert "calculation_count" in profile
    assert profile["calculation_count"] == 0

def test_update_profile_username_positive(base_url: str):
    """Test updating profile username successfully"""
    user_data = {
        "first_name": "Update",
        "last_name": "User",
        "email": f"update{uuid4()}@example.com",
        "username": f"updatetest_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Update username
    new_username = f"newusername_{uuid4()}"
    update_data = {"username": new_username}
    
    response = requests.put(f"{base_url}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200, f"Update profile failed: {response.text}"
    
    updated_profile = response.json()
    assert updated_profile["username"] == new_username

def test_update_profile_email_positive(base_url: str):
    """Test updating profile email successfully"""
    user_data = {
        "first_name": "Email",
        "last_name": "Update",
        "email": f"oldemail{uuid4()}@example.com",
        "username": f"emailtest_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Update email
    new_email = f"newemail{uuid4()}@example.com"
    update_data = {"email": new_email}
    
    response = requests.put(f"{base_url}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200, f"Update email failed: {response.text}"
    
    updated_profile = response.json()
    assert updated_profile["email"] == new_email

def test_update_profile_multiple_fields_positive(base_url: str):
    """Test updating multiple profile fields at once"""
    user_data = {
        "first_name": "Old",
        "last_name": "Name",
        "email": f"old{uuid4()}@example.com",
        "username": f"olduser_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Update multiple fields
    update_data = {
        "first_name": "New",
        "last_name": "Person",
        "username": f"newuser_{uuid4()}",
        "email": f"new{uuid4()}@example.com"
    }
    
    response = requests.put(f"{base_url}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200, f"Update multiple fields failed: {response.text}"
    
    updated_profile = response.json()
    assert updated_profile["first_name"] == "New"
    assert updated_profile["last_name"] == "Person"
    assert updated_profile["username"] == update_data["username"]
    assert updated_profile["email"] == update_data["email"]

def test_change_password_positive(base_url: str):
    """Test changing password successfully"""
    user_data = {
        "first_name": "Password",
        "last_name": "Changer",
        "email": f"passchange{uuid4()}@example.com",
        "username": f"passtest_{uuid4()}",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Change password
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }
    
    response = requests.post(f"{base_url}/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 200, f"Password change failed: {response.text}"
    
    result = response.json()
    assert "message" in result
    assert "successfully" in result["message"].lower()
    
    # Verify old password no longer works
    old_login = {
        "username": user_data["username"],
        "password": "OldPass123!"
    }
    old_response = requests.post(f"{base_url}/auth/login", json=old_login)
    assert old_response.status_code == 401
    
    # Verify new password works
    new_login = {
        "username": user_data["username"],
        "password": "NewPass456!"
    }
    new_response = requests.post(f"{base_url}/auth/login", json=new_login)
    assert new_response.status_code == 200

def test_profile_with_calculations_positive(base_url: str):
    """Test that profile shows calculation count correctly"""
    user_data = {
        "first_name": "Calc",
        "last_name": "Counter",
        "email": f"calccounter{uuid4()}@example.com",
        "username": f"calctest_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Create some calculations
    for i in range(3):
        calc_data = {
            "type": "addition",
            "inputs": [i, i+1, i+2]
        }
        requests.post(f"{base_url}/calculations", json=calc_data, headers=headers)
    
    # Get profile and check calculation count
    response = requests.get(f"{base_url}/profile/me", headers=headers)
    assert response.status_code == 200
    
    profile = response.json()
    assert profile["calculation_count"] == 3

# ============================================================================
# NEGATIVE TESTS
# ============================================================================

def test_get_profile_no_auth_negative(base_url: str):
    """Test getting profile without authentication fails"""
    response = requests.get(f"{base_url}/profile/me")
    assert response.status_code == 401

def test_get_profile_invalid_token_negative(base_url: str):
    """Test getting profile with invalid token fails"""
    headers = {"Authorization": "Bearer invalid_token_123"}
    response = requests.get(f"{base_url}/profile/me", headers=headers)
    assert response.status_code == 401

def test_update_profile_no_fields_negative(base_url: str):
    """Test updating profile with no fields fails"""
    user_data = {
        "first_name": "No",
        "last_name": "Fields",
        "email": f"nofields{uuid4()}@example.com",
        "username": f"nofields_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Try to update with empty data
    update_data = {}
    response = requests.put(f"{base_url}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 422  # Validation error

def test_update_profile_duplicate_username_negative(base_url: str):
    """Test updating to existing username fails"""
    # Create first user
    user1_data = {
        "first_name": "User",
        "last_name": "One",
        "email": f"user1{uuid4()}@example.com",
        "username": f"user1_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    register_and_login(base_url, user1_data)
    
    # Create second user
    user2_data = {
        "first_name": "User",
        "last_name": "Two",
        "email": f"user2{uuid4()}@example.com",
        "username": f"user2_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    token_data = register_and_login(base_url, user2_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Try to update user2's username to user1's username
    update_data = {"username": user1_data["username"]}
    response = requests.put(f"{base_url}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 400
    assert "already taken" in response.json()["detail"].lower()

def test_update_profile_duplicate_email_negative(base_url: str):
    """Test updating to existing email fails"""
    # Create first user
    user1_data = {
        "first_name": "Email",
        "last_name": "One",
        "email": f"email1{uuid4()}@example.com",
        "username": f"emailuser1_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    register_and_login(base_url, user1_data)
    
    # Create second user
    user2_data = {
        "first_name": "Email",
        "last_name": "Two",
        "email": f"email2{uuid4()}@example.com",
        "username": f"emailuser2_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    token_data = register_and_login(base_url, user2_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Try to update user2's email to user1's email
    update_data = {"email": user1_data["email"]}
    response = requests.put(f"{base_url}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 400
    assert "already in use" in response.json()["detail"].lower()

def test_change_password_wrong_current_negative(base_url: str):
    """Test changing password with wrong current password fails"""
    user_data = {
        "first_name": "Wrong",
        "last_name": "Password",
        "email": f"wrongpass{uuid4()}@example.com",
        "username": f"wrongpass_{uuid4()}",
        "password": "CorrectPass123!",
        "confirm_password": "CorrectPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Try to change with wrong current password
    password_data = {
        "current_password": "WrongPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }
    
    response = requests.post(f"{base_url}/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 401
    assert "incorrect" in response.json()["detail"].lower()

def test_change_password_weak_new_password_negative(base_url: str):
    """Test changing to weak password fails validation"""
    user_data = {
        "first_name": "Weak",
        "last_name": "Pass",
        "email": f"weakpass{uuid4()}@example.com",
        "username": f"weakpass_{uuid4()}",
        "password": "StrongPass123!",
        "confirm_password": "StrongPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Try to change to weak password (no special char)
    password_data = {
        "current_password": "StrongPass123!",
        "new_password": "weakpass123",
        "confirm_new_password": "weakpass123"
    }
    
    response = requests.post(f"{base_url}/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 422  # Validation error

def test_change_password_mismatch_negative(base_url: str):
    """Test changing password with mismatched confirmation fails"""
    user_data = {
        "first_name": "Mismatch",
        "last_name": "Test",
        "email": f"mismatch{uuid4()}@example.com",
        "username": f"mismatch_{uuid4()}",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Try to change with mismatched passwords
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "DifferentPass456!"
    }
    
    response = requests.post(f"{base_url}/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 422  # Validation error

def test_update_profile_invalid_email_format_negative(base_url: str):
    """Test updating with invalid email format fails"""
    user_data = {
        "first_name": "Invalid",
        "last_name": "Email",
        "email": f"validemail{uuid4()}@example.com",
        "username": f"invalidemail_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    token_data = register_and_login(base_url, user_data)
    access_token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Try to update with invalid email
    update_data = {"email": "not-an-email"}
    response = requests.put(f"{base_url}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 422  # Validation error