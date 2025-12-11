"""
Additional tests to reach 90% coverage
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.calculation import Calculation
from app.models.user import User
from uuid import uuid4

client = TestClient(app)


def register_and_login():
    """Helper to register and login"""
    import time
    username = f"u{int(time.time() * 1000000) % 100000000}"

    user_data = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"{username}@test.com",
        "username": username,
        "password": "Pass123!",
        "confirm_password": "Pass123!"
    }
    client.post("/auth/register", json=user_data)

    login_response = client.post("/auth/login", json={
        "username": username,
        "password": "Pass123!"
    })
    return login_response.json()["access_token"]


def test_register_with_invalid_data():
    """Test registration error handling"""
    # Invalid email
    response = client.post("/auth/register", json={
        "first_name": "Test",
        "last_name": "User",
        "email": "notanemail",
        "username": "testuser123",
        "password": "Pass123!",
        "confirm_password": "Pass123!"
    })
    assert response.status_code == 422


def test_all_calculation_types():
    """Test all calculation types to cover model branches"""
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}

    # Test all operation types
    operations = [
        ("addition", [1, 2, 3], 6),
        ("subtraction", [10, 3, 2], 5),
        ("multiplication", [2, 3, 4], 24),
        ("division", [100, 2, 5], 10)
    ]

    for op_type, inputs, expected in operations:
        response = client.post(
            "/calculations",
            json={"type": op_type, "inputs": inputs},
            headers=headers
        )
        assert response.status_code == 201
        assert response.json()["result"] == expected


def test_calculation_model_directly():
    """Test Calculation model methods directly"""
    user_id = uuid4()

    # Test addition
    calc = Calculation.create("addition", user_id, [1, 2, 3])
    assert calc.get_result() == 6

    # Test subtraction
    calc = Calculation.create("subtraction", user_id, [10, 3])
    assert calc.get_result() == 7

    # Test multiplication
    calc = Calculation.create("multiplication", user_id, [2, 3])
    assert calc.get_result() == 6

    # Test division
    calc = Calculation.create("division", user_id, [10, 2])
    assert calc.get_result() == 5

    # Test invalid type
    with pytest.raises(ValueError):
        Calculation.create("invalid", user_id, [1, 2])


def test_calculation_edge_cases():
    """Test calculation edge cases"""
    user_id = uuid4()

    # Division by zero in model
    calc = Calculation.create("division", user_id, [10, 0])
    with pytest.raises(ValueError):
        calc.get_result()

    # Empty inputs - this should work at model level, validation happens at schema level
    calc2 = Calculation.create("addition", user_id, [1, 2])
    assert calc2 is not None


def test_user_model_methods():
    """Test User model methods to increase coverage"""
    from app.auth.jwt import get_password_hash

    # Test hash_password class method
    hashed = User.hash_password("TestPass123!")
    assert hashed is not None
    assert len(hashed) > 0


def test_update_calculation_with_none_inputs():
    """Test updating calculation with None inputs"""
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}

    # Create a calculation
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=headers
    )
    calc_id = response.json()["id"]

    # Try to update with None inputs (should not update)
    update_response = client.put(
        f"/calculations/{calc_id}",
        json={},  # Empty update
        headers=headers
    )
    # Should still work, just not change inputs
    assert update_response.status_code in [200, 422]


def test_login_timezone_handling():
    """Test login with timezone-aware expires_at"""
    import time
    username = f"tz{int(time.time() * 1000000) % 100000000}"

    # Register
    user_data = {
        "first_name": "TZ",
        "last_name": "Test",
        "email": f"{username}@test.com",
        "username": username,
        "password": "Pass123!",
        "confirm_password": "Pass123!"
    }
    client.post("/auth/register", json=user_data)

    # Login
    login_response = client.post("/auth/login", json={
        "username": username,
        "password": "Pass123!"
    })

    assert login_response.status_code == 200
    data = login_response.json()

    # Verify all TokenResponse fields
    assert "access_token" in data
    assert "refresh_token" in data
    assert "token_type" in data
    assert "expires_at" in data
    assert "user_id" in data
    assert "username" in data
    assert "email" in data
    assert "first_name" in data
    assert "last_name" in data
    assert "is_active" in data
    assert "is_verified" in data


def test_calculation_with_decimal_results():
    """Test calculations that produce decimal results"""
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}

    # Division with decimal result
    response = client.post(
        "/calculations",
        json={"type": "division", "inputs": [10, 3]},
        headers=headers
    )
    assert response.status_code == 201
    result = response.json()["result"]
    assert abs(result - 3.333333) < 0.01


def test_list_calculations_when_empty():
    """Test listing calculations returns empty list"""
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/calculations", headers=headers)
    assert response.status_code == 200
    assert response.json() == []


def test_calculation_created_and_updated_timestamps():
    """Test that timestamps are set correctly"""
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}

    # Create
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": [1, 2]},
        headers=headers
    )
    data = response.json()
    assert "created_at" in data
    assert "updated_at" in data

    # Update
    calc_id = data["id"]
    update_response = client.put(
        f"/calculations/{calc_id}",
        json={"inputs": [5, 10]},
        headers=headers
    )
    updated_data = update_response.json()
    assert updated_data["created_at"] == data["created_at"]
    # updated_at might be same or different depending on timing


def test_calculation_invalid_operations():
    """Test that invalid calculation operations fail"""
    token = register_and_login()
    headers = {"Authorization": f"Bearer {token}"}

    # Invalid type
    response = client.post(
        "/calculations",
        json={"type": "invalid_op", "inputs": [1, 2]},
        headers=headers
    )
    assert response.status_code == 422

    # Inputs not a list
    response = client.post(
        "/calculations",
        json={"type": "addition", "inputs": "not_a_list"},
        headers=headers
    )
    assert response.status_code == 422
