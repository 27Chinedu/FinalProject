# tests/unit/test_profile_logic.py

import pytest
from pydantic import ValidationError
from app.schemas.profile import ProfileUpdate, PasswordChange

def test_profile_update_valid():
    """Test ProfileUpdate with valid data"""
    data = {
        "username": "newusername",
        "email": "new@example.com",
        "first_name": "Jane",
        "last_name": "Smith"
    }
    profile_update = ProfileUpdate(**data)
    assert profile_update.username == "newusername"
    assert profile_update.email == "new@example.com"
    assert profile_update.first_name == "Jane"
    assert profile_update.last_name == "Smith"

def test_profile_update_partial():
    """Test ProfileUpdate with partial data"""
    data = {"username": "newusername"}
    profile_update = ProfileUpdate(**data)
    assert profile_update.username == "newusername"
    assert profile_update.email is None
    assert profile_update.first_name is None
    assert profile_update.last_name is None

def test_profile_update_empty():
    """Test ProfileUpdate fails with no data"""
    with pytest.raises(ValidationError):
        ProfileUpdate()

def test_profile_update_short_username():
    """Test ProfileUpdate fails with short username"""
    data = {"username": "ab"}
    with pytest.raises(ValidationError):
        ProfileUpdate(**data)

def test_profile_update_invalid_email():
    """Test ProfileUpdate fails with invalid email"""
    data = {"email": "not-an-email"}
    with pytest.raises(ValidationError):
        ProfileUpdate(**data)

def test_password_change_valid():
    """Test PasswordChange with valid data"""
    data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass123!",
        "confirm_new_password": "NewPass123!"
    }
    password_change = PasswordChange(**data)
    assert password_change.current_password == "OldPass123!"
    assert password_change.new_password == "NewPass123!"

def test_password_change_mismatch():
    """Test PasswordChange fails when passwords don't match"""
    data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass123!",
        "confirm_new_password": "DifferentPass123!"
    }
    with pytest.raises(ValidationError):
        PasswordChange(**data)

def test_password_change_same_password():
    """Test PasswordChange fails when new password same as current"""
    data = {
        "current_password": "SamePass123!",
        "new_password": "SamePass123!",
        "confirm_new_password": "SamePass123!"
    }
    with pytest.raises(ValidationError):
        PasswordChange(**data)

def test_password_change_weak_password():
    """Test PasswordChange fails with weak password"""
    # No uppercase
    data = {
        "current_password": "OldPass123!",
        "new_password": "newpass123!",
        "confirm_new_password": "newpass123!"
    }
    with pytest.raises(ValidationError):
        PasswordChange(**data)

def test_password_change_no_digit():
    """Test PasswordChange fails with no digit"""
    data = {
        "current_password": "OldPass123!",
        "new_password": "NewPassword!",
        "confirm_new_password": "NewPassword!"
    }
    with pytest.raises(ValidationError):
        PasswordChange(**data)

def test_password_change_no_special_char():
    """Test PasswordChange fails with no special character"""
    data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass123",
        "confirm_new_password": "NewPass123"
    }
    with pytest.raises(ValidationError):
        PasswordChange(**data)

def test_password_change_too_short():
    """Test PasswordChange fails with short password"""
    data = {
        "current_password": "OldPass123!",
        "new_password": "New1!",
        "confirm_new_password": "New1!"
    }
    with pytest.raises(ValidationError):
        PasswordChange(**data)