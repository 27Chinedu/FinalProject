# tests/e2e/test_profile_validation.py
# Comprehensive profile schema and validation tests

from uuid import uuid4
import pytest
import requests


def register_and_login(fastapi_server: str, user_data: dict) -> dict:
    """Helper function to register and login a user"""
    reg_url = f"{fastapi_server.rstrip("/")}/auth/register"
    login_url = f"{fastapi_server.rstrip("/")}/auth/login"

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
# Profile Update Validation Tests
# ============================================================================

def test_update_profile_username_too_short(fastapi_server: str):
    """Test updating profile with username too short fails"""
    user_data = {
        "first_name": "Short",
        "last_name": "Username",
        "email": f"shortusername{uuid4()}@example.com",
        "username": f"shortusername_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to update with too short username
    update_data = {"username": "ab"}  # Only 2 characters

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 422

def test_update_profile_username_too_long(fastapi_server: str):
    """Test updating profile with username too long fails"""
    user_data = {
        "first_name": "Long",
        "last_name": "Username",
        "email": f"longusername{uuid4()}@example.com",
        "username": f"longusername_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to update with too long username (> 50 chars)
    update_data = {"username": "a" * 51}

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 422

def test_update_profile_first_name_empty(fastapi_server: str):
    """Test updating profile with empty first name fails"""
    user_data = {
        "first_name": "Valid",
        "last_name": "Name",
        "email": f"emptyfirst{uuid4()}@example.com",
        "username": f"emptyfirst_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to update with empty first name
    update_data = {"first_name": ""}

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 422

def test_update_profile_last_name_empty(fastapi_server: str):
    """Test updating profile with empty last name fails"""
    user_data = {
        "first_name": "Valid",
        "last_name": "Name",
        "email": f"emptylast{uuid4()}@example.com",
        "username": f"emptylast_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to update with empty last name
    update_data = {"last_name": ""}

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 422

def test_update_profile_first_name_too_long(fastapi_server: str):
    """Test updating profile with first name too long fails"""
    user_data = {
        "first_name": "Valid",
        "last_name": "Name",
        "email": f"longfirst{uuid4()}@example.com",
        "username": f"longfirst_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to update with too long first name (> 50 chars)
    update_data = {"first_name": "A" * 51}

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 422

def test_update_profile_last_name_too_long(fastapi_server: str):
    """Test updating profile with last name too long fails"""
    user_data = {
        "first_name": "Valid",
        "last_name": "Name",
        "email": f"longlast{uuid4()}@example.com",
        "username": f"longlast_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to update with too long last name (> 50 chars)
    update_data = {"last_name": "B" * 51}

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 422

def test_update_profile_only_first_name(fastapi_server: str):
    """Test updating only first name works"""
    user_data = {
        "first_name": "Old",
        "last_name": "Name",
        "email": f"onlyfirst{uuid4()}@example.com",
        "username": f"onlyfirst_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Update only first name
    update_data = {"first_name": "New"}

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200

    updated_profile = response.json()
    assert updated_profile["first_name"] == "New"
    assert updated_profile["last_name"] == user_data["last_name"]

def test_update_profile_only_last_name(fastapi_server: str):
    """Test updating only last name works"""
    user_data = {
        "first_name": "First",
        "last_name": "Old",
        "email": f"onlylast{uuid4()}@example.com",
        "username": f"onlylast_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Update only last name
    update_data = {"last_name": "New"}

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200

    updated_profile = response.json()
    assert updated_profile["first_name"] == user_data["first_name"]
    assert updated_profile["last_name"] == "New"

def test_update_profile_only_email(fastapi_server: str):
    """Test updating only email works"""
    user_data = {
        "first_name": "Email",
        "last_name": "Update",
        "email": f"oldemail{uuid4()}@example.com",
        "username": f"emailupdate_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Update only email
    new_email = f"newemail{uuid4()}@example.com"
    update_data = {"email": new_email}

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200

    updated_profile = response.json()
    assert updated_profile["email"] == new_email

# ============================================================================
# Password Change Validation Tests
# ============================================================================

def test_change_password_new_same_as_current(fastapi_server: str):
    """Test changing password to same as current fails (if validation exists)"""
    user_data = {
        "first_name": "Same",
        "last_name": "Password",
        "email": f"samepass{uuid4()}@example.com",
        "username": f"samepass_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to change to same password
    password_data = {
        "current_password": "TestPass123!",
        "new_password": "TestPass123!",
        "confirm_new_password": "TestPass123!"
    }

    response = requests.post(f"{fastapi_server.rstrip("/")}/profile/change-password", json=password_data, headers=headers)
    # This might be 422 (validation) or could be allowed depending on implementation
    assert response.status_code in [422, 400]

def test_change_password_new_too_short(fastapi_server: str):
    """Test changing password to one that's too short fails"""
    user_data = {
        "first_name": "Short",
        "last_name": "NewPass",
        "email": f"shortnew{uuid4()}@example.com",
        "username": f"shortnew_{uuid4()}",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to change to short password
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "Short1!",  # Too short
        "confirm_new_password": "Short1!"
    }

    response = requests.post(f"{fastapi_server.rstrip("/")}/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 422

def test_change_password_new_no_uppercase(fastapi_server: str):
    """Test changing password to one without uppercase fails"""
    user_data = {
        "first_name": "NoUpper",
        "last_name": "NewPass",
        "email": f"noupperpass{uuid4()}@example.com",
        "username": f"noupperpass_{uuid4()}",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to change to password without uppercase
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "newpass123!",  # No uppercase
        "confirm_new_password": "newpass123!"
    }

    response = requests.post(f"{fastapi_server.rstrip("/")}/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 422

def test_change_password_new_no_lowercase(fastapi_server: str):
    """Test changing password to one without lowercase fails"""
    user_data = {
        "first_name": "NoLower",
        "last_name": "NewPass",
        "email": f"nolowerpass{uuid4()}@example.com",
        "username": f"nolowerpass_{uuid4()}",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to change to password without lowercase
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NEWPASS123!",  # No lowercase
        "confirm_new_password": "NEWPASS123!"
    }

    response = requests.post(f"{fastapi_server.rstrip("/")}/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 422

def test_change_password_new_no_digit(fastapi_server: str):
    """Test changing password to one without digit fails"""
    user_data = {
        "first_name": "NoDigit",
        "last_name": "NewPass",
        "email": f"nodigitpass{uuid4()}@example.com",
        "username": f"nodigitpass_{uuid4()}",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to change to password without digit
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPassword!",  # No digit
        "confirm_new_password": "NewPassword!"
    }

    response = requests.post(f"{fastapi_server.rstrip("/")}/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 422

def test_change_password_new_no_special(fastapi_server: str):
    """Test changing password to one without special character fails"""
    user_data = {
        "first_name": "NoSpecial",
        "last_name": "NewPass",
        "email": f"nospecialpass{uuid4()}@example.com",
        "username": f"nospecialpass_{uuid4()}",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try to change to password without special character
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPassword123",  # No special char
        "confirm_new_password": "NewPassword123"
    }

    response = requests.post(f"{fastapi_server.rstrip("/")}/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 422

def test_change_password_without_auth(fastapi_server: str):
    """Test changing password without authentication fails"""
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }

    response = requests.post(f"{fastapi_server.rstrip("/")}/profile/change-password", json=password_data)
    assert response.status_code == 401

def test_get_profile_without_auth(fastapi_server: str):
    """Test getting profile without authentication fails"""
    response = requests.get(f"{fastapi_server.rstrip("/")}/profile/me")
    assert response.status_code == 401

def test_update_profile_without_auth(fastapi_server: str):
    """Test updating profile without authentication fails"""
    update_data = {"first_name": "New"}

    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data)
    assert response.status_code == 401

# ============================================================================
# Profile Response Structure Tests
# ============================================================================

def test_profile_response_has_calculation_count(fastapi_server: str):
    """Test that profile response includes calculation count"""
    user_data = {
        "first_name": "Calc",
        "last_name": "Count",
        "email": f"calccount{uuid4()}@example.com",
        "username": f"calccount_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Get profile
    response = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers)
    assert response.status_code == 200

    profile = response.json()
    assert "calculation_count" in profile
    assert isinstance(profile["calculation_count"], int)
    assert profile["calculation_count"] == 0

def test_profile_response_structure(fastapi_server: str):
    """Test profile response has all required fields"""
    user_data = {
        "first_name": "Profile",
        "last_name": "Structure",
        "email": f"profilestruct{uuid4()}@example.com",
        "username": f"profilestruct_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Get profile
    response = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers)
    assert response.status_code == 200

    profile = response.json()
    required_fields = ["id", "username", "email", "first_name", "last_name",
                      "is_active", "is_verified", "created_at", "updated_at",
                      "last_login", "calculation_count"]

    for field in required_fields:
        assert field in profile, f"Missing field: {field}"

def test_profile_calculation_count_accuracy(fastapi_server: str):
    """Test that calculation count is accurate"""
    user_data = {
        "first_name": "Count",
        "last_name": "Accuracy",
        "email": f"countaccuracy{uuid4()}@example.com",
        "username": f"countaccuracy_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Initial count should be 0
    profile = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers).json()
    assert profile["calculation_count"] == 0

    # Create 3 calculations
    for i in range(3):
        calc_data = {
            "type": "addition",
            "inputs": [i, i+1]
        }
        requests.post(f"{fastapi_server.rstrip("/")}/calculations", json=calc_data, headers=headers)

    # Check count is now 3
    profile = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers).json()
    assert profile["calculation_count"] == 3

    # Delete one calculation
    calcs = requests.get(f"{fastapi_server.rstrip("/")}/calculations", headers=headers).json()
    if calcs:
        requests.delete(f"{fastapi_server.rstrip("/")}/calculations/{calcs[0]['id']}", headers=headers)

    # Check count is now 2
    profile = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers).json()
    assert profile["calculation_count"] == 2

# ============================================================================
# Edge Cases for Profile Updates
# ============================================================================

def test_update_profile_preserves_other_fields(fastapi_server: str):
    """Test that updating one field doesn't affect other fields"""
    user_data = {
        "first_name": "Preserve",
        "last_name": "Fields",
        "email": f"preserve{uuid4()}@example.com",
        "username": f"preserve_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Get original profile
    original = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers).json()

    # Update only first name
    update_data = {"first_name": "NewFirst"}
    requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)

    # Get updated profile
    updated = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers).json()

    # Check other fields unchanged
    assert updated["first_name"] == "NewFirst"
    assert updated["last_name"] == original["last_name"]
    assert updated["email"] == original["email"]
    assert updated["username"] == original["username"]
    assert updated["is_active"] == original["is_active"]
    assert updated["is_verified"] == original["is_verified"]

def test_update_profile_updates_timestamp(fastapi_server: str):
    """Test that updating profile updates the updated_at timestamp"""
    user_data = {
        "first_name": "Timestamp",
        "last_name": "Update",
        "email": f"timestamp{uuid4()}@example.com",
        "username": f"timestamp_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Get original profile
    original = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers).json()
    original_updated_at = original["updated_at"]

    # Wait a bit
    import time
    time.sleep(1)

    # Update profile
    update_data = {"first_name": "NewName"}
    requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)

    # Get updated profile
    updated = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers).json()
    new_updated_at = updated["updated_at"]

    # Timestamp should be different
    assert new_updated_at != original_updated_at

def test_password_change_updates_timestamp(fastapi_server: str):
    """Test that changing password updates the updated_at timestamp"""
    user_data = {
        "first_name": "PassTime",
        "last_name": "Stamp",
        "email": f"passtime{uuid4()}@example.com",
        "username": f"passtime_{uuid4()}",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Get original timestamp
    original = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=headers).json()
    original_updated_at = original["updated_at"]

    # Wait a bit
    import time
    time.sleep(1)

    # Change password
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }
    requests.post(f"{fastapi_server.rstrip("/")}/profile/change-password", json=password_data, headers=headers)

    # Get new token with new password
    login_payload = {
        "username": user_data["username"],
        "password": "NewPass456!"
    }
    new_token_data = requests.post(f"{fastapi_server.rstrip("/")}/auth/login", json=login_payload).json()
    new_headers = {"Authorization": f"Bearer {new_token_data['access_token']}"}

    # Get updated profile
    updated = requests.get(f"{fastapi_server.rstrip("/")}/profile/me", headers=new_headers).json()
    new_updated_at = updated["updated_at"]

    # Timestamp should be different
    assert new_updated_at != original_updated_at

# ============================================================================
# Additional Validation Tests
# ============================================================================

def test_profile_update_with_null_values(fastapi_server: str):
    """Test that null values in profile update are handled correctly"""
    user_data = {
        "first_name": "Null",
        "last_name": "Values",
        "email": f"nullval{uuid4()}@example.com",
        "username": f"nullval_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try update with null username (should preserve original)
    update_data = {"username": None, "first_name": "NewName"}
    response = requests.put(f"{fastapi_server.rstrip("/")}/profile/me", json=update_data, headers=headers)

    # Should either reject null or preserve original
    if response.status_code == 200:
        profile = response.json()
        # Original username should be preserved
        assert profile["username"] == user_data["username"]
        # But first name should be updated
        assert profile["first_name"] == "NewName"
