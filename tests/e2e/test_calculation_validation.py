# tests/e2e/test_calculation_validation.py
# Comprehensive calculation schema and validation tests

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
# Calculation Type Validation Tests
# ============================================================================

def test_calculation_type_case_insensitive(fastapi_server: str):
    """Test that calculation type is case-insensitive"""
    user_data = {
        "first_name": "Case",
        "last_name": "Test",
        "email": f"casetest{uuid4()}@example.com",
        "username": f"casetest_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Try uppercase type
    calc_data = {
        "type": "ADDITION",
        "inputs": [1, 2, 3]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    assert response.json()["type"] == "addition"

def test_calculation_type_mixed_case(fastapi_server: str):
    """Test that mixed case calculation type works"""
    user_data = {
        "first_name": "Mixed",
        "last_name": "Case",
        "email": f"mixedcase{uuid4()}@example.com",
        "username": f"mixedcase_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "MuLtIpLiCaTiOn",
        "inputs": [2, 3]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    assert response.json()["type"] == "multiplication"

def test_calculation_invalid_type_string(fastapi_server: str):
    """Test that invalid calculation type string fails"""
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
        "type": "exponentiation",  # Not a valid type
        "inputs": [2, 3]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

def test_calculation_type_integer(fastapi_server: str):
    """Test that integer type fails validation"""
    user_data = {
        "first_name": "Type",
        "last_name": "Integer",
        "email": f"typeint{uuid4()}@example.com",
        "username": f"typeint_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": 123,  # Should be string
        "inputs": [1, 2]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

def test_calculation_missing_type(fastapi_server: str):
    """Test that missing type fails validation"""
    user_data = {
        "first_name": "Missing",
        "last_name": "Type",
        "email": f"missingtype{uuid4()}@example.com",
        "username": f"missingtype_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        # Missing type field
        "inputs": [1, 2, 3]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

# ============================================================================
# Calculation Inputs Validation Tests
# ============================================================================

def test_calculation_inputs_not_list(fastapi_server: str):
    """Test that non-list inputs fails validation"""
    user_data = {
        "first_name": "Not",
        "last_name": "List",
        "email": f"notlist{uuid4()}@example.com",
        "username": f"notlist_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": "1,2,3"  # String instead of list
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

def test_calculation_inputs_single_value(fastapi_server: str):
    """Test that single input value fails validation"""
    user_data = {
        "first_name": "Single",
        "last_name": "Input",
        "email": f"singleinput{uuid4()}@example.com",
        "username": f"singleinput_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": [42]  # Only one input
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

def test_calculation_inputs_empty_list(fastapi_server: str):
    """Test that empty inputs list fails validation"""
    user_data = {
        "first_name": "Empty",
        "last_name": "Inputs",
        "email": f"emptyinputs{uuid4()}@example.com",
        "username": f"emptyinputs_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": []
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

def test_calculation_missing_inputs(fastapi_server: str):
    """Test that missing inputs field fails validation"""
    user_data = {
        "first_name": "Missing",
        "last_name": "Inputs",
        "email": f"missinginputs{uuid4()}@example.com",
        "username": f"missinginputs_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition"
        # Missing inputs field
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

def test_calculation_inputs_with_strings(fastapi_server: str):
    """Test that string values in inputs fail validation"""
    user_data = {
        "first_name": "String",
        "last_name": "Values",
        "email": f"stringvals{uuid4()}@example.com",
        "username": f"stringvals_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": [1, "two", 3]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

def test_calculation_inputs_with_null(fastapi_server: str):
    """Test that null values in inputs fail validation"""
    user_data = {
        "first_name": "Null",
        "last_name": "Values",
        "email": f"nullvals{uuid4()}@example.com",
        "username": f"nullvals_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": [1, None, 3]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

# ============================================================================
# Division by Zero Validation Tests
# ============================================================================

def test_division_by_zero_second_input(fastapi_server: str):
    """Test division by zero in second input fails"""
    user_data = {
        "first_name": "Div",
        "last_name": "Zero",
        "email": f"divzero{uuid4()}@example.com",
        "username": f"divzero_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "division",
        "inputs": [100, 0]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

def test_division_by_zero_third_input(fastapi_server: str):
    """Test division by zero in third input fails"""
    user_data = {
        "first_name": "Div",
        "last_name": "ZeroThird",
        "email": f"divzerothird{uuid4()}@example.com",
        "username": f"divzerothird_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "division",
        "inputs": [100, 5, 0]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 422

def test_division_first_input_zero_allowed(fastapi_server: str):
    """Test that zero as first input in division is allowed"""
    user_data = {
        "first_name": "Div",
        "last_name": "FirstZero",
        "email": f"divfirstzero{uuid4()}@example.com",
        "username": f"divfirstzero_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "division",
        "inputs": [0, 5]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    assert response.json()["result"] == 0

def test_division_negative_zero(fastapi_server: str):
    """Test that -0.0 is treated as zero in division"""
    user_data = {
        "first_name": "Div",
        "last_name": "NegZero",
        "email": f"divnegzero{uuid4()}@example.com",
        "username": f"divnegzero_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "division",
        "inputs": [100, -0.0]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    # Should fail because -0.0 == 0
    assert response.status_code == 422

# ============================================================================
# Calculation Update Validation Tests
# ============================================================================

def test_update_calculation_single_input(fastapi_server: str):
    """Test updating calculation with single input fails"""
    user_data = {
        "first_name": "Update",
        "last_name": "Single",
        "email": f"updatesingle{uuid4()}@example.com",
        "username": f"updatesingle_{uuid4()}",
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
    create_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    calc_id = create_response.json()["id"]

    # Try to update with single input
    update_data = {"inputs": [42]}
    response = requests.put(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', json=update_data, headers=headers)
    assert response.status_code == 422

def test_update_calculation_empty_inputs(fastapi_server: str):
    """Test updating calculation with empty inputs fails"""
    user_data = {
        "first_name": "Update",
        "last_name": "Empty",
        "email": f"updateempty{uuid4()}@example.com",
        "username": f"updateempty_{uuid4()}",
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
    create_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    calc_id = create_response.json()["id"]

    # Try to update with empty inputs
    update_data = {"inputs": []}
    response = requests.put(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', json=update_data, headers=headers)
    assert response.status_code == 422

def test_update_calculation_valid_inputs(fastapi_server: str):
    """Test updating calculation with valid inputs succeeds"""
    user_data = {
        "first_name": "Update",
        "last_name": "Valid",
        "email": f"updatevalid{uuid4()}@example.com",
        "username": f"updatevalid_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Create calculation
    calc_data = {
        "type": "multiplication",
        "inputs": [2, 3]
    }
    create_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    calc_id = create_response.json()["id"]

    # Update with valid inputs
    update_data = {"inputs": [5, 6]}
    response = requests.put(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["result"] == 30

def test_update_calculation_null_inputs(fastapi_server: str):
    """Test updating calculation with null inputs (should preserve original)"""
    user_data = {
        "first_name": "Update",
        "last_name": "Null",
        "email": f"updatenull{uuid4()}@example.com",
        "username": f"updatenull_{uuid4()}",
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
    create_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    calc_id = create_response.json()["id"]
    original_result = create_response.json()["result"]

    # Update with null inputs (should preserve original)
    update_data = {"inputs": None}
    response = requests.put(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', json=update_data, headers=headers)
    assert response.status_code == 200
    # Result should remain unchanged
    assert response.json()["result"] == original_result

# ============================================================================
# Calculation Result Accuracy Tests
# ============================================================================

def test_addition_multiple_inputs(fastapi_server: str):
    """Test addition with multiple inputs calculates correctly"""
    user_data = {
        "first_name": "Add",
        "last_name": "Multi",
        "email": f"addmulti{uuid4()}@example.com",
        "username": f"addmulti_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": [1, 2, 3, 4, 5]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    assert response.json()["result"] == 15

def test_subtraction_multiple_inputs(fastapi_server: str):
    """Test subtraction with multiple inputs calculates correctly"""
    user_data = {
        "first_name": "Sub",
        "last_name": "Multi",
        "email": f"submulti{uuid4()}@example.com",
        "username": f"submulti_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "subtraction",
        "inputs": [100, 10, 5, 2]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    # 100 - 10 - 5 - 2 = 83
    assert response.json()["result"] == 83

def test_multiplication_with_zero(fastapi_server: str):
    """Test multiplication with zero"""
    user_data = {
        "first_name": "Mult",
        "last_name": "Zero",
        "email": f"multzero{uuid4()}@example.com",
        "username": f"multzero_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "multiplication",
        "inputs": [5, 0, 10]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    assert response.json()["result"] == 0

def test_division_with_decimals(fastapi_server: str):
    """Test division with decimal results"""
    user_data = {
        "first_name": "Div",
        "last_name": "Decimal",
        "email": f"divdecimal{uuid4()}@example.com",
        "username": f"divdecimal_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "division",
        "inputs": [10, 3]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    result = response.json()["result"]
    # 10 / 3 = 3.333...
    assert abs(result - 3.333333333) < 0.001

def test_calculation_with_negative_numbers(fastapi_server: str):
    """Test calculations with negative numbers"""
    user_data = {
        "first_name": "Negative",
        "last_name": "Numbers",
        "email": f"negative{uuid4()}@example.com",
        "username": f"negative_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Test addition with negative
    calc_data = {
        "type": "addition",
        "inputs": [-5, 10, -3]
    }
    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    assert response.json()["result"] == 2

def test_calculation_with_large_numbers(fastapi_server: str):
    """Test calculations with large numbers"""
    user_data = {
        "first_name": "Large",
        "last_name": "Numbers",
        "email": f"large{uuid4()}@example.com",
        "username": f"large_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "multiplication",
        "inputs": [1000000, 1000000]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    assert response.json()["result"] == 1000000000000

def test_calculation_with_very_small_decimals(fastapi_server: str):
    """Test calculations with very small decimal numbers"""
    user_data = {
        "first_name": "Small",
        "last_name": "Decimals",
        "email": f"smalldec{uuid4()}@example.com",
        "username": f"smalldec_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": [0.0001, 0.0002]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201
    result = response.json()["result"]
    assert abs(result - 0.0003) < 0.000001

# ============================================================================
# Calculation Response Structure Tests
# ============================================================================

def test_calculation_response_has_all_fields(fastapi_server: str):
    """Test that calculation response has all required fields"""
    user_data = {
        "first_name": "Response",
        "last_name": "Fields",
        "email": f"respfields{uuid4()}@example.com",
        "username": f"respfields_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": [1, 2]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201

    data = response.json()
    required_fields = ["id", "user_id", "type", "inputs", "result",
                      "created_at", "updated_at"]

    for field in required_fields:
        assert field in data, f"Missing field: {field}"

def test_calculation_timestamps(fastapi_server: str):
    """Test that calculation has valid timestamps"""
    user_data = {
        "first_name": "Time",
        "last_name": "Stamps",
        "email": f"timestamps{uuid4()}@example.com",
        "username": f"timestamps_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    calc_data = {
        "type": "addition",
        "inputs": [1, 2]
    }

    response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    assert response.status_code == 201

    data = response.json()
    assert "created_at" in data
    assert "updated_at" in data

    from datetime import datetime
    # Verify timestamps are valid ISO format
    created_at = datetime.fromisoformat(data["created_at"].replace('Z', '+00:00'))
    updated_at = datetime.fromisoformat(data["updated_at"].replace('Z', '+00:00'))

    assert created_at <= updated_at

def test_update_calculation_changes_updated_at(fastapi_server: str):
    """Test that updating calculation changes updated_at timestamp"""
    user_data = {
        "first_name": "Update",
        "last_name": "Timestamp",
        "email": f"updatetime{uuid4()}@example.com",
        "username": f"updatetime_{uuid4()}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }

    token_data = register_and_login(fastapi_server.rstrip("/"), user_data)
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

    # Create calculation
    calc_data = {
        "type": "addition",
        "inputs": [1, 2]
    }
    create_response = requests.post(f'{fastapi_server.rstrip("/")}/calculations', json=calc_data, headers=headers)
    calc_id = create_response.json()["id"]
    original_updated_at = create_response.json()["updated_at"]

    # Wait a bit
    import time
    time.sleep(1)

    # Update calculation
    update_data = {"inputs": [3, 4]}
    update_response = requests.put(f'{fastapi_server.rstrip("/")}/calculations/{calc_id}', json=update_data, headers=headers)
    new_updated_at = update_response.json()["updated_at"]

    # Timestamp should be different
    assert new_updated_at != original_updated_at
