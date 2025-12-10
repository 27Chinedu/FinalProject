# tests/unit/test_schemas.py

import pytest
from pydantic import ValidationError
from uuid import uuid4
from datetime import datetime, timezone
from app.schemas.calculation import (
    CalculationType,
    CalculationBase,
    CalculationCreate,
    CalculationUpdate,
    CalculationResponse
)
from app.schemas.user import (
    UserBase,
    UserCreate,
    UserUpdate,
    PasswordUpdate,
    UserResponse,
    UserLogin
)
from app.schemas.profile import (
    ProfileUpdate,
    PasswordChange,
    ProfileResponse,
    PasswordChangeResponse
)
from app.schemas.token import (
    TokenType,
    Token,
    TokenData,
    TokenResponse
)

def test_calculation_base_valid():
    """Test CalculationBase with valid data"""
    data = {
        "type": "addition",
        "inputs": [1, 2, 3]
    }
    calc = CalculationBase(**data)
    assert calc.type == CalculationType.ADDITION
    assert calc.inputs == [1, 2, 3]

def test_calculation_base_case_insensitive():
    """Test CalculationBase type is case insensitive"""
    data = {
        "type": "ADDITION",
        "inputs": [1, 2]
    }
    calc = CalculationBase(**data)
    assert calc.type == "addition"

def test_calculation_base_invalid_type():
    """Test CalculationBase with invalid type"""
    data = {
        "type": "modulo",
        "inputs": [1, 2]
    }
    with pytest.raises(ValidationError):
        CalculationBase(**data)

def test_calculation_base_not_list():
    """Test CalculationBase with non-list inputs"""
    data = {
        "type": "addition",
        "inputs": "not a list"
    }
    with pytest.raises(ValidationError):
        CalculationBase(**data)

def test_calculation_base_insufficient_inputs():
    """Test CalculationBase with less than 2 inputs"""
    data = {
        "type": "addition",
        "inputs": [1]
    }
    with pytest.raises(ValidationError):
        CalculationBase(**data)

def test_calculation_base_division_by_zero():
    """Test CalculationBase division with zero"""
    data = {
        "type": "division",
        "inputs": [100, 0]
    }
    with pytest.raises(ValidationError):
        CalculationBase(**data)

def test_calculation_create_valid():
    """Test CalculationCreate with valid data"""
    user_id = uuid4()
    data = {
        "type": "multiplication",
        "inputs": [2, 3, 4],
        "user_id": str(user_id)
    }
    calc = CalculationCreate(**data)
    assert calc.user_id == user_id

def test_calculation_update_valid():
    """Test CalculationUpdate with valid inputs"""
    data = {"inputs": [5, 10, 15]}
    update = CalculationUpdate(**data)
    assert update.inputs == [5, 10, 15]

def test_calculation_update_none():
    """Test CalculationUpdate with None inputs"""
    update = CalculationUpdate()
    assert update.inputs is None

def test_calculation_update_insufficient_inputs():
    """Test CalculationUpdate with insufficient inputs"""
    data = {"inputs": [1]}
    with pytest.raises(ValidationError):
        CalculationUpdate(**data)

def test_user_create_valid():
    """Test UserCreate with valid data"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "username": "johndoe",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!"
    }
    user = UserCreate(**data)
    assert user.username == "johndoe"

def test_user_create_password_mismatch():
    """Test UserCreate with mismatched passwords"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "username": "johndoe",
        "password": "SecurePass123!",
        "confirm_password": "DifferentPass123!"
    }
    with pytest.raises(ValidationError):
        UserCreate(**data)

def test_user_create_short_password():
    """Test UserCreate with short password"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "username": "johndoe",
        "password": "short",
        "confirm_password": "short"
    }
    with pytest.raises(ValidationError):
        UserCreate(**data)

def test_user_create_no_uppercase():
    """Test UserCreate with no uppercase letter"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "username": "johndoe",
        "password": "lowercase123!",
        "confirm_password": "lowercase123!"
    }
    with pytest.raises(ValidationError):
        UserCreate(**data)

def test_user_create_no_lowercase():
    """Test UserCreate with no lowercase letter"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "username": "johndoe",
        "password": "UPPERCASE123!",
        "confirm_password": "UPPERCASE123!"
    }
    with pytest.raises(ValidationError):
        UserCreate(**data)

def test_user_create_no_digit():
    """Test UserCreate with no digit"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "username": "johndoe",
        "password": "NoDigits!",
        "confirm_password": "NoDigits!"
    }
    with pytest.raises(ValidationError):
        UserCreate(**data)

def test_user_create_no_special_char():
    """Test UserCreate with no special character"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "username": "johndoe",
        "password": "NoSpecial123",
        "confirm_password": "NoSpecial123"
    }
    with pytest.raises(ValidationError):
        UserCreate(**data)

def test_user_create_short_username():
    """Test UserCreate with short username"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "username": "ab",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!"
    }
    with pytest.raises(ValidationError):
        UserCreate(**data)

def test_user_update_partial():
    """Test UserUpdate with partial data"""
    data = {"first_name": "Jane"}
    update = UserUpdate(**data)
    assert update.first_name == "Jane"
    assert update.last_name is None

def test_password_update_valid():
    """Test PasswordUpdate with valid data"""
    data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass123!",
        "confirm_new_password": "NewPass123!"
    }
    update = PasswordUpdate(**data)
    assert update.new_password == "NewPass123!"

def test_password_update_mismatch():
    """Test PasswordUpdate with mismatched passwords"""
    data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass123!",
        "confirm_new_password": "Different123!"
    }
    with pytest.raises(ValidationError):
        PasswordUpdate(**data)

def test_password_update_same_password():
    """Test PasswordUpdate with same password"""
    data = {
        "current_password": "SamePass123!",
        "new_password": "SamePass123!",
        "confirm_new_password": "SamePass123!"
    }
    with pytest.raises(ValidationError):
        PasswordUpdate(**data)


# Profile Schema Tests


def test_profile_update_single_field():
    """Test ProfileUpdate with single field"""
    update = ProfileUpdate(username="newusername")
    assert update.username == "newusername"
    assert update.email is None


def test_profile_update_all_fields():
    """Test ProfileUpdate with all fields"""
    update = ProfileUpdate(
        username="newusername",
        email="new@example.com",
        first_name="New",
        last_name="Name"
    )
    assert update.username == "newusername"
    assert update.email == "new@example.com"


def test_profile_update_no_fields():
    """Test ProfileUpdate with no fields raises error"""
    with pytest.raises(ValidationError) as exc_info:
        ProfileUpdate()
    assert "at least one field" in str(exc_info.value).lower()


def test_password_change_valid():
    """Test valid PasswordChange"""
    change = PasswordChange(
        current_password="OldPass123!",
        new_password="NewPass456!",
        confirm_new_password="NewPass456!"
    )
    assert change.current_password == "OldPass123!"
    assert change.new_password == "NewPass456!"


def test_password_change_mismatch():
    """Test PasswordChange with mismatched passwords"""
    with pytest.raises(ValidationError) as exc_info:
        PasswordChange(
            current_password="OldPass123!",
            new_password="NewPass456!",
            confirm_new_password="Different789!"
        )
    assert "do not match" in str(exc_info.value).lower()


def test_password_change_same_as_current():
    """Test PasswordChange with new same as current"""
    with pytest.raises(ValidationError) as exc_info:
        PasswordChange(
            current_password="SamePass123!",
            new_password="SamePass123!",
            confirm_new_password="SamePass123!"
        )
    assert "different" in str(exc_info.value).lower()


def test_password_change_weak_password_no_uppercase():
    """Test PasswordChange with weak password"""
    with pytest.raises(ValidationError) as exc_info:
        PasswordChange(
            current_password="OldPass123!",
            new_password="weakpass1!",
            confirm_new_password="weakpass1!"
        )
    assert "uppercase" in str(exc_info.value).lower()


def test_profile_response_creation():
    """Test ProfileResponse creation"""
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    response = ProfileResponse(
        id=user_id,
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        is_active=True,
        is_verified=False,
        created_at=now,
        updated_at=now,
        last_login=now,
        calculation_count=5
    )

    assert response.id == user_id
    assert response.calculation_count == 5


def test_password_change_response():
    """Test PasswordChangeResponse"""
    now = datetime.now(timezone.utc)
    response = PasswordChangeResponse(
        message="Password updated",
        updated_at=now
    )
    assert response.message == "Password updated"


# Token Schema Tests


def test_token_type_enum():
    """Test TokenType enum values"""
    assert TokenType.ACCESS.value == "access"
    assert TokenType.REFRESH.value == "refresh"


def test_token_creation():
    """Test Token schema creation"""
    now = datetime.now(timezone.utc)
    token = Token(
        access_token="test_access",
        refresh_token="test_refresh",
        expires_at=now
    )
    assert token.access_token == "test_access"
    assert token.token_type == "bearer"


def test_token_data_creation():
    """Test TokenData creation"""
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    token_data = TokenData(
        user_id=user_id,
        exp=now,
        jti="unique_jti",
        token_type=TokenType.ACCESS
    )
    assert token_data.user_id == user_id
    assert token_data.jti == "unique_jti"


def test_token_response_creation():
    """Test TokenResponse creation"""
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    response = TokenResponse(
        access_token="test_access",
        refresh_token="test_refresh",
        expires_at=now,
        user_id=user_id,
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        is_active=True,
        is_verified=False
    )
    assert response.user_id == user_id
    assert response.username == "testuser"


# User Response Tests


def test_user_response_creation():
    """Test UserResponse creation"""
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    response = UserResponse(
        id=user_id,
        username="johndoe",
        email="john@example.com",
        first_name="John",
        last_name="Doe",
        is_active=True,
        is_verified=False,
        created_at=now,
        updated_at=now
    )
    assert response.id == user_id
    assert response.is_active is True


def test_user_login_valid():
    """Test valid UserLogin"""
    login = UserLogin(
        username="johndoe",
        password="SecurePass123!"
    )
    assert login.username == "johndoe"


def test_calculation_response_creation():
    """Test CalculationResponse creation"""
    calc_id = uuid4()
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    response = CalculationResponse(
        id=calc_id,
        user_id=user_id,
        type="addition",
        inputs=[10, 5],
        result=15.0,
        created_at=now,
        updated_at=now
    )
    assert response.id == calc_id
    assert response.result == 15.0


# Additional Edge Cases


def test_calculation_float_inputs():
    """Test calculation with float inputs"""
    calc = CalculationBase(
        type="multiplication",
        inputs=[1.5, 2.7, 3.14]
    )
    assert calc.inputs == [1.5, 2.7, 3.14]


def test_calculation_negative_inputs():
    """Test calculation with negative inputs"""
    calc = CalculationBase(
        type="subtraction",
        inputs=[-10, -5, 3]
    )
    assert calc.inputs == [-10, -5, 3]


def test_user_base_creation():
    """Test UserBase creation"""
    user = UserBase(
        first_name="John",
        last_name="Doe",
        email="john@example.com",
        username="johndoe"
    )
    assert user.first_name == "John"


def test_profile_update_email_only():
    """Test ProfileUpdate with just email"""
    update = ProfileUpdate(email="new@example.com")
    assert update.email == "new@example.com"
    assert update.username is None