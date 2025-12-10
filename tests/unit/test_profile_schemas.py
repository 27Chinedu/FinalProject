# tests/unit/test_profile_schemas.py
"""
Unit tests for profile schemas to ensure validation coverage.
"""

import pytest
from pydantic import ValidationError
from uuid import uuid4
from datetime import datetime

from app.schemas.profile import (
    ProfileUpdate,
    PasswordChange,
    ProfileResponse,
    PasswordChangeResponse
)


class TestProfileUpdate:
    """Test ProfileUpdate schema"""

    def test_profile_update_username_only(self):
        """Test updating only username"""
        data = {"username": "newusername"}
        update = ProfileUpdate(**data)
        assert update.username == "newusername"
        assert update.email is None
        assert update.first_name is None
        assert update.last_name is None

    def test_profile_update_email_only(self):
        """Test updating only email"""
        data = {"email": "newemail@example.com"}
        update = ProfileUpdate(**data)
        assert update.email == "newemail@example.com"
        assert update.username is None

    def test_profile_update_names_only(self):
        """Test updating only names"""
        data = {
            "first_name": "NewFirst",
            "last_name": "NewLast"
        }
        update = ProfileUpdate(**data)
        assert update.first_name == "NewFirst"
        assert update.last_name == "NewLast"

    def test_profile_update_all_fields(self):
        """Test updating all fields"""
        data = {
            "username": "newuser",
            "email": "new@example.com",
            "first_name": "First",
            "last_name": "Last"
        }
        update = ProfileUpdate(**data)
        assert update.username == "newuser"
        assert update.email == "new@example.com"
        assert update.first_name == "First"
        assert update.last_name == "Last"

    def test_profile_update_no_fields(self):
        """Test that updating with no fields fails validation"""
        data = {}
        with pytest.raises(ValidationError) as exc_info:
            ProfileUpdate(**data)
        assert "At least one field must be provided" in str(exc_info.value)

    def test_profile_update_username_too_short(self):
        """Test username too short fails validation"""
        data = {"username": "ab"}
        with pytest.raises(ValidationError):
            ProfileUpdate(**data)

    def test_profile_update_username_too_long(self):
        """Test username too long fails validation"""
        data = {"username": "a" * 51}
        with pytest.raises(ValidationError):
            ProfileUpdate(**data)

    def test_profile_update_invalid_email(self):
        """Test invalid email fails validation"""
        data = {"email": "not-an-email"}
        with pytest.raises(ValidationError):
            ProfileUpdate(**data)

    def test_profile_update_name_too_long(self):
        """Test name too long fails validation"""
        data = {"first_name": "a" * 51}
        with pytest.raises(ValidationError):
            ProfileUpdate(**data)

    def test_profile_update_empty_name(self):
        """Test empty name fails validation"""
        data = {"first_name": ""}
        with pytest.raises(ValidationError):
            ProfileUpdate(**data)


class TestPasswordChange:
    """Test PasswordChange schema"""

    def test_password_change_valid(self):
        """Test valid password change"""
        data = {
            "current_password": "OldPass123!",
            "new_password": "NewPass123!",
            "confirm_new_password": "NewPass123!"
        }
        change = PasswordChange(**data)
        assert change.current_password == "OldPass123!"
        assert change.new_password == "NewPass123!"

    def test_password_change_mismatch(self):
        """Test mismatched new passwords fail"""
        data = {
            "current_password": "OldPass123!",
            "new_password": "NewPass123!",
            "confirm_new_password": "Different123!"
        }
        with pytest.raises(ValidationError) as exc_info:
            PasswordChange(**data)
        assert "do not match" in str(exc_info.value)

    def test_password_change_same_as_current(self):
        """Test new password same as current fails"""
        data = {
            "current_password": "SamePass123!",
            "new_password": "SamePass123!",
            "confirm_new_password": "SamePass123!"
        }
        with pytest.raises(ValidationError) as exc_info:
            PasswordChange(**data)
        assert "must be different" in str(exc_info.value)

    def test_password_change_too_short(self):
        """Test password too short fails"""
        data = {
            "current_password": "OldPass123!",
            "new_password": "Short1!",
            "confirm_new_password": "Short1!"
        }
        with pytest.raises(ValidationError):
            PasswordChange(**data)

    def test_password_change_no_uppercase(self):
        """Test password without uppercase fails"""
        data = {
            "current_password": "OldPass123!",
            "new_password": "nouppercase123!",
            "confirm_new_password": "nouppercase123!"
        }
        with pytest.raises(ValidationError) as exc_info:
            PasswordChange(**data)
        assert "uppercase" in str(exc_info.value)

    def test_password_change_no_lowercase(self):
        """Test password without lowercase fails"""
        data = {
            "current_password": "OldPass123!",
            "new_password": "NOLOWERCASE123!",
            "confirm_new_password": "NOLOWERCASE123!"
        }
        with pytest.raises(ValidationError) as exc_info:
            PasswordChange(**data)
        assert "lowercase" in str(exc_info.value)

    def test_password_change_no_digit(self):
        """Test password without digit fails"""
        data = {
            "current_password": "OldPass123!",
            "new_password": "NoDigitsHere!",
            "confirm_new_password": "NoDigitsHere!"
        }
        with pytest.raises(ValidationError) as exc_info:
            PasswordChange(**data)
        assert "digit" in str(exc_info.value)

    def test_password_change_no_special_char(self):
        """Test password without special character fails"""
        data = {
            "current_password": "OldPass123!",
            "new_password": "NoSpecialChar123",
            "confirm_new_password": "NoSpecialChar123"
        }
        with pytest.raises(ValidationError) as exc_info:
            PasswordChange(**data)
        assert "special character" in str(exc_info.value)

    def test_password_change_all_special_chars(self):
        """Test password with various special characters"""
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        for char in special_chars:
            data = {
                "current_password": "OldPass123!",
                "new_password": f"ValidPass123{char}",
                "confirm_new_password": f"ValidPass123{char}"
            }
            # Should not raise
            change = PasswordChange(**data)
            assert change.new_password == f"ValidPass123{char}"


class TestProfileResponse:
    """Test ProfileResponse schema"""

    def test_profile_response_valid(self):
        """Test valid profile response"""
        user_id = uuid4()
        data = {
            "id": user_id,
            "username": "testuser",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "is_active": True,
            "is_verified": False,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login": None,
            "calculation_count": 0
        }
        response = ProfileResponse(**data)
        assert response.id == user_id
        assert response.username == "testuser"
        assert response.calculation_count == 0

    def test_profile_response_with_last_login(self):
        """Test profile response with last_login set"""
        user_id = uuid4()
        now = datetime.utcnow()
        data = {
            "id": user_id,
            "username": "testuser",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "is_active": True,
            "is_verified": True,
            "created_at": now,
            "updated_at": now,
            "last_login": now,
            "calculation_count": 42
        }
        response = ProfileResponse(**data)
        assert response.last_login == now
        assert response.calculation_count == 42
        assert response.is_verified is True

    def test_profile_response_default_calculation_count(self):
        """Test calculation_count defaults to 0"""
        user_id = uuid4()
        data = {
            "id": user_id,
            "username": "testuser",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "is_active": True,
            "is_verified": False,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        response = ProfileResponse(**data)
        assert response.calculation_count == 0


class TestPasswordChangeResponse:
    """Test PasswordChangeResponse schema"""

    def test_password_change_response_valid(self):
        """Test valid password change response"""
        now = datetime.utcnow()
        data = {
            "message": "Password successfully updated",
            "updated_at": now
        }
        response = PasswordChangeResponse(**data)
        assert response.message == "Password successfully updated"
        assert response.updated_at == now

    def test_password_change_response_custom_message(self):
        """Test password change response with custom message"""
        now = datetime.utcnow()
        data = {
            "message": "Your password has been changed",
            "updated_at": now
        }
        response = PasswordChangeResponse(**data)
        assert response.message == "Your password has been changed"
