# tests/unit/test_schemas.py

import pytest
from pydantic import ValidationError
from uuid import uuid4
from app.schemas.calculation import (
    CalculationType,
    CalculationBase,
    CalculationCreate,
    CalculationUpdate
)
from app.schemas.user import UserCreate, UserUpdate, PasswordUpdate

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
    with pytest.raises(ValidationError, match="Type must be one of"):
        CalculationBase(**data)

def test_calculation_base_not_list():
    """Test CalculationBase with non-list inputs"""
    data = {
        "type": "addition",
        "inputs": "not a list"
    }
    with pytest.raises(ValidationError, match="Input should be a valid list"):
        CalculationBase(**data)

def test_calculation_base_insufficient_inputs():
    """Test CalculationBase with less than 2 inputs"""
    data = {
        "type": "addition",
        "inputs": [1]
    }
    with pytest.raises(ValidationError, match="at least two numbers"):
        CalculationBase(**data)

def test_calculation_base_division_by_zero():
    """Test CalculationBase division with zero"""
    data = {
        "type": "division",
        "inputs": [100, 0]
    }
    with pytest.raises(ValidationError, match="Cannot divide by zero"):
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
    with pytest.raises(ValidationError, match="at least two numbers"):
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
    with pytest.raises(ValidationError, match="Passwords do not match"):
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
    with pytest.raises(ValidationError, match="at least 8 characters"):
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
    with pytest.raises(ValidationError, match="uppercase"):
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
    with pytest.raises(ValidationError, match="lowercase"):
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
    with pytest.raises(ValidationError, match="digit"):
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
    with pytest.raises(ValidationError, match="special character"):
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
    with pytest.raises(ValidationError, match="do not match"):
        PasswordUpdate(**data)

def test_password_update_same_password():
    """Test PasswordUpdate with same password"""
    data = {
        "current_password": "SamePass123!",
        "new_password": "SamePass123!",
        "confirm_new_password": "SamePass123!"
    }
    with pytest.raises(ValidationError, match="must be different"):
        PasswordUpdate(**data)