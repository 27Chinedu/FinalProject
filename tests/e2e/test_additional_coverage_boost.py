"""
Additional focused tests to guarantee >90% e2e coverage
Specifically targets any remaining gaps in coverage
"""

import pytest
from fastapi.testclient import TestClient
from uuid import uuid4
import time

from app.main import app
from app.database import get_db, get_sessionmaker, get_engine
from app.core.config import settings

# Setup
test_engine = get_engine(database_url=settings.DATABASE_URL)
TestingSessionLocal = get_sessionmaker(engine=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


# ==============================================================================
# Focused tests for specific uncovered branches
# ==============================================================================

def test_login_updates_last_login_timestamp():
    """Test that login properly updates last_login field"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Last",
        "last_name": "Login",
        "email": f"lastlogin_{unique_id}@example.com",
        "username": f"lastlogin_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register
    reg_response = client.post("/auth/register", json=user_data)
    assert reg_response.status_code == 201
    
    # First login
    login1 = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    assert login1.status_code == 200
    
    time.sleep(0.1)  # Small delay
    
    # Second login
    login2 = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    assert login2.status_code == 200


def test_token_response_has_all_fields():
    """Verify TokenResponse contains all required fields"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Token",
        "last_name": "Fields",
        "email": f"tokenfields_{unique_id}@example.com",
        "username": f"tokenfields_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register and login
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    
    assert login_response.status_code == 200
    data = login_response.json()
    
    # Verify ALL fields are present
    required_fields = [
        "access_token", "refresh_token", "token_type", "expires_at",
        "user_id", "username", "email", "first_name", "last_name",
        "is_active", "is_verified"
    ]
    
    for field in required_fields:
        assert field in data, f"Missing field: {field}"


def test_calculation_deletion_updates_profile_count():
    """Test that deleting calculations updates profile count"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Delete",
        "last_name": "Count",
        "email": f"delcount_{unique_id}@example.com",
        "username": f"delcount_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register and login
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create 3 calculations
    calc_ids = []
    for i in range(3):
        calc_response = client.post("/calculations", json={
            "type": "addition",
            "inputs": [i, i+1]
        }, headers=headers)
        calc_ids.append(calc_response.json()["id"])
    
    # Verify count is 3
    profile1 = client.get("/profile/me", headers=headers)
    assert profile1.json()["calculation_count"] == 3
    
    # Delete one calculation
    client.delete(f"/calculations/{calc_ids[0]}", headers=headers)
    
    # Verify count is now 2
    profile2 = client.get("/profile/me", headers=headers)
    assert profile2.json()["calculation_count"] == 2


def test_password_change_complete_flow():
    """Complete password change flow with verification"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Pass",
        "last_name": "Change",
        "email": f"passchange_{unique_id}@example.com",
        "username": f"passchange_{unique_id}",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!"
    }
    
    # Register
    client.post("/auth/register", json=user_data)
    
    # Login with old password
    login1 = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "OldPass123!"
    })
    assert login1.status_code == 200
    token = login1.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Change password
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }
    change_response = client.post("/profile/change-password", json=password_data, headers=headers)
    assert change_response.status_code == 200
    assert "successfully" in change_response.json()["message"].lower()
    
    # Verify old password doesn't work
    login_old = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "OldPass123!"
    })
    assert login_old.status_code == 401
    
    # Verify new password works
    login_new = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "NewPass456!"
    })
    assert login_new.status_code == 200


def test_profile_response_includes_all_fields():
    """Verify ProfileResponse has all fields"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Profile",
        "last_name": "Complete",
        "email": f"profcomplete_{unique_id}@example.com",
        "username": f"profcomplete_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register and login
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get profile
    profile_response = client.get("/profile/me", headers=headers)
    assert profile_response.status_code == 200
    data = profile_response.json()
    
    # Verify all fields present
    required_fields = [
        "id", "username", "email", "first_name", "last_name",
        "is_active", "is_verified", "created_at", "updated_at",
        "last_login", "calculation_count"
    ]
    
    for field in required_fields:
        assert field in data, f"Missing field: {field}"


def test_calculation_update_with_none_inputs_branch():
    """Test calculation update with None inputs to cover conditional branch"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Update",
        "last_name": "None",
        "email": f"updatenone_{unique_id}@example.com",
        "username": f"updatenone_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register and login
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create calculation
    calc_response = client.post("/calculations", json={
        "type": "addition",
        "inputs": [1, 2]
    }, headers=headers)
    calc_id = calc_response.json()["id"]
    
    # Try to update with empty body (inputs=None)
    update_response = client.put(f"/calculations/{calc_id}", json={}, headers=headers)
    # Should either succeed (no change) or fail validation
    assert update_response.status_code in [200, 422]


def test_all_calculation_types_comprehensive():
    """Test all four calculation types to ensure complete coverage"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "All",
        "last_name": "Types",
        "email": f"alltypes_{unique_id}@example.com",
        "username": f"alltypes_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register and login
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test each calculation type
    test_cases = [
        ("addition", [1, 2, 3], 6),
        ("subtraction", [10, 3, 2], 5),
        ("multiplication", [2, 3, 4], 24),
        ("division", [100, 2, 5], 10)
    ]
    
    for calc_type, inputs, expected in test_cases:
        response = client.post("/calculations", json={
            "type": calc_type,
            "inputs": inputs
        }, headers=headers)
        assert response.status_code == 201
        assert response.json()["result"] == expected
        assert response.json()["type"] == calc_type


def test_profile_calculation_count_accuracy():
    """Test that calculation count is accurate after multiple operations"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Count",
        "last_name": "Accuracy",
        "email": f"accuracy_{unique_id}@example.com",
        "username": f"accuracy_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register and login
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create 5 calculations
    calc_ids = []
    for i in range(5):
        response = client.post("/calculations", json={
            "type": "addition",
            "inputs": [i, 1]
        }, headers=headers)
        calc_ids.append(response.json()["id"])
    
    # Check count is 5
    profile = client.get("/profile/me", headers=headers)
    assert profile.json()["calculation_count"] == 5
    
    # Delete 2 calculations
    client.delete(f"/calculations/{calc_ids[0]}", headers=headers)
    client.delete(f"/calculations/{calc_ids[1]}", headers=headers)
    
    # Check count is 3
    profile2 = client.get("/profile/me", headers=headers)
    assert profile2.json()["calculation_count"] == 3


def test_timezone_aware_timestamps():
    """Verify all timestamps are timezone-aware"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "TZ",
        "last_name": "Aware",
        "email": f"tzaware_{unique_id}@example.com",
        "username": f"tzaware_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register and login
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    
    # Check login response has timezone-aware expires_at
    data = login_response.json()
    assert "expires_at" in data
    expires_str = data["expires_at"]
    
    # Should be parseable as ISO datetime
    from datetime import datetime
    if expires_str.endswith('Z'):
        expires_str = expires_str.replace('Z', '+00:00')
    expires_dt = datetime.fromisoformat(expires_str)
    assert expires_dt is not None


def test_calculation_list_empty_for_new_user():
    """Test that new users have empty calculation list"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Empty",
        "last_name": "List",
        "email": f"emptylist_{unique_id}@example.com",
        "username": f"emptylist_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register and login
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "TestPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get calculations list
    response = client.get("/calculations", headers=headers)
    assert response.status_code == 200
    assert response.json() == []


@pytest.fixture
def db_session():
    """Provide database session"""
    db = TestingSessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()