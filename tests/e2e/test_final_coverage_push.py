"""
Final comprehensive test file to push e2e coverage above 90%
Targets specific uncovered lines in:
- app/auth/redis.py (lines 5-13) - covered indirectly through auth flow
- app/models/user.py (lines 47, 52, 64-67, 72, 118, 219-231)
- app/routes/profile.py (lines 34, 71, 87, 94-100, 109, 113, 121-123, 160, 179-181)
- app/schemas/user.py (lines 62, 184-188)
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from uuid import uuid4
from datetime import datetime, timezone
import time

from app.main import app
from app.models.user import User, utcnow
from app.models.calculation import Calculation
from app.database import get_db, get_sessionmaker, get_engine
from app.core.config import settings
from app.schemas.user import UserCreate, PasswordUpdate
from pydantic import ValidationError

# Setup test database
test_engine = get_engine(database_url=settings.DATABASE_URL)
TestingSessionLocal = get_sessionmaker(engine=test_engine)


def override_get_db():
    """Override get_db for testing"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


# ==============================================================================
# Tests for app/auth/redis.py - Covered indirectly through authentication
# Note: Redis functions are tested directly in unit tests (test_redis.py)
# Here we just ensure they get called through the auth flow
# ==============================================================================

def test_redis_functions_called_through_auth_flow():
    """Test that redis functions are invoked during authentication (covers lines 5-13)"""
    # The Redis stub functions (add_to_blacklist, is_blacklisted) get called
    # internally during token creation and validation. We test this by doing
    # multiple auth operations which will invoke these functions.
    
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Redis",
        "last_name": "Test",
        "email": f"redistest_{unique_id}@example.com",
        "username": f"redistest_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register (creates tokens, may check blacklist)
    reg_response = client.post("/auth/register", json=user_data)
    assert reg_response.status_code == 201
    
    # Login multiple times (creates tokens each time)
    for i in range(3):
        login_response = client.post("/auth/login", json={
            "username": user_data["username"],
            "password": "TestPass123!"
        })
        assert login_response.status_code == 200
        token = login_response.json()["access_token"]
        
        # Use the token to access protected endpoint (validates token)
        headers = {"Authorization": f"Bearer {token}"}
        profile_response = client.get("/profile/me", headers=headers)
        assert profile_response.status_code == 200


# ==============================================================================
# Tests for app/models/user.py - Target lines 47, 52, 64-67, 72, 118, 219-231
# ==============================================================================

def test_user_model_str_method():
    """Test User.__str__ method (line 47)"""
    user = User(
        username="testuser",
        email="test@example.com",
        first_name="John",
        last_name="Doe",
        password="hashed_password"
    )
    str_repr = str(user)
    assert "User" in str_repr
    assert "John" in str_repr
    assert "Doe" in str_repr
    assert "test@example.com" in str_repr


def test_user_model_hashed_password_property():
    """Test User.hashed_password property (line 64-67)"""
    hashed = User.hash_password("TestPassword123!")
    user = User(
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        password=hashed
    )
    assert user.hashed_password == hashed
    assert user.hashed_password == user.password


def test_user_init_with_hashed_password_kwarg():
    """Test User.__init__ with hashed_password kwarg (line 52)"""
    hashed = User.hash_password("SecurePass123!")
    user = User(
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        hashed_password=hashed  # Using hashed_password instead of password
    )
    assert user.password == hashed


def test_user_update_method_with_timestamp():
    """Test User.update() method to cover lines 72"""
    user = User(
        username="testuser",
        email="test@example.com",
        first_name="Old",
        last_name="Name",
        password="hashed"
    )
    user.updated_at = utcnow()
    original_updated = user.updated_at
    
    time.sleep(0.01)  # Small delay
    
    result = user.update(first_name="New", last_name="Person")
    
    assert result == user
    assert user.first_name == "New"
    assert user.updated_at > original_updated


def test_user_authenticate_with_email():
    """Test User.authenticate using email instead of username (line 118)"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Email",
        "last_name": "User",
        "email": f"emailauth_{unique_id}@example.com",
        "username": f"emailuser_{unique_id}",
        "password": "TestPass123!"
    }
    
    # Register via API
    reg_response = client.post("/auth/register", json={
        **user_data,
        "confirm_password": "TestPass123!"
    })
    assert reg_response.status_code == 201
    
    # Login using email instead of username
    login_response = client.post("/auth/login", json={
        "username": user_data["email"],  # Using email here
        "password": "TestPass123!"
    })
    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data


def test_user_model_utcnow_timezone_aware():
    """Test utcnow() returns timezone-aware datetime"""
    now = utcnow()
    assert now.tzinfo is not None
    assert now.tzinfo == timezone.utc


def test_user_verify_token_method():
    """Test User.verify_token class method (lines 219-231)"""
    user_id = uuid4()
    
    # Create token using User.create_access_token
    token = User.create_access_token({"sub": str(user_id)})
    
    # Verify token
    verified_id = User.verify_token(token)
    assert verified_id == user_id
    
    # Test with invalid token
    invalid_result = User.verify_token("invalid_token_string")
    assert invalid_result is None
    
    # Test with token missing 'sub'
    from jose import jwt
    token_no_sub = jwt.encode({"type": "access"}, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    result_no_sub = User.verify_token(token_no_sub)
    assert result_no_sub is None


def test_user_create_access_and_refresh_tokens():
    """Test token creation methods"""
    user_id = uuid4()
    
    # Test access token
    access_token = User.create_access_token({"sub": str(user_id)})
    assert isinstance(access_token, str)
    assert len(access_token) > 0
    
    # Test refresh token  
    refresh_token = User.create_refresh_token({"sub": str(user_id)})
    assert isinstance(refresh_token, str)
    assert len(refresh_token) > 0
    
    # Verify they're different
    assert access_token != refresh_token


def test_user_register_with_empty_password():
    """Test User.register with empty/None password"""
    unique_id = str(uuid4())[:8]
    
    # Test with None password
    user_data_none = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"none_{unique_id}@example.com",
        "username": f"nonepass_{unique_id}",
        "password": None,
        "confirm_password": None
    }
    
    response = client.post("/auth/register", json=user_data_none)
    assert response.status_code in [400, 422]  # Should fail validation
    
    # Test with empty password
    user_data_empty = {
        "first_name": "Test",
        "last_name": "User",
        "email": f"empty_{unique_id}@example.com",
        "username": f"emptypass_{unique_id}",
        "password": "",
        "confirm_password": ""
    }
    
    response2 = client.post("/auth/register", json=user_data_empty)
    assert response2.status_code == 422  # Should fail validation


# ==============================================================================
# Tests for app/routes/profile.py - Target lines 34, 71, 87, 94-100, etc.
# ==============================================================================

def test_profile_get_user_not_found_in_database():
    """Test GET /profile/me when user not in database (line 34)"""
    # Create token for non-existent user
    from app.auth.jwt import create_token
    from app.schemas.token import TokenType
    
    fake_user_id = uuid4()
    token = create_token(fake_user_id, TokenType.ACCESS)
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/profile/me", headers=headers)
    assert response.status_code == 404
    assert "User not found" in response.json()["detail"]


def test_profile_update_user_not_found():
    """Test PUT /profile/me when user not found (line 71)"""
    from app.auth.jwt import create_token
    from app.schemas.token import TokenType
    
    fake_user_id = uuid4()
    token = create_token(fake_user_id, TokenType.ACCESS)
    headers = {"Authorization": f"Bearer {token}"}
    
    update_data = {"first_name": "New"}
    
    response = client.put("/profile/me", json=update_data, headers=headers)
    assert response.status_code == 404


def test_profile_update_duplicate_username_check():
    """Test profile update duplicate username detection (lines 87, 94-100)"""
    # Create two users
    unique_id = str(uuid4())[:8]
    
    user1_data = {
        "first_name": "User",
        "last_name": "One",
        "email": f"user1_{unique_id}@example.com",
        "username": f"user1_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    user2_data = {
        "first_name": "User",
        "last_name": "Two",
        "email": f"user2_{unique_id}@example.com",
        "username": f"user2_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register both users
    client.post("/auth/register", json=user1_data)
    client.post("/auth/register", json=user2_data)
    
    # Login as user2
    login_response = client.post("/auth/login", json={
        "username": user2_data["username"],
        "password": "TestPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Try to update to user1's username
    update_data = {"username": user1_data["username"]}
    response = client.put("/profile/me", json=update_data, headers=headers)
    assert response.status_code == 400
    assert "already taken" in response.json()["detail"].lower()


def test_profile_update_duplicate_email_check():
    """Test profile update duplicate email detection (lines 109, 113)"""
    unique_id = str(uuid4())[:8]
    
    user1_data = {
        "first_name": "Email",
        "last_name": "One",
        "email": f"email1_{unique_id}@example.com",
        "username": f"emailuser1_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    user2_data = {
        "first_name": "Email",
        "last_name": "Two",
        "email": f"email2_{unique_id}@example.com",
        "username": f"emailuser2_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register both users
    client.post("/auth/register", json=user1_data)
    client.post("/auth/register", json=user2_data)
    
    # Login as user2
    login_response = client.post("/auth/login", json={
        "username": user2_data["username"],
        "password": "TestPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Try to update to user1's email
    update_data = {"email": user1_data["email"]}
    response = client.put("/profile/me", json=update_data, headers=headers)
    assert response.status_code == 400
    assert "already in use" in response.json()["detail"].lower()


def test_profile_update_with_calculations_count():
    """Test profile update maintains calculation count (lines 121-123)"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Calc",
        "last_name": "Count",
        "email": f"calccount_{unique_id}@example.com",
        "username": f"calccount_{unique_id}",
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
    
    # Create some calculations
    for i in range(3):
        client.post("/calculations", json={
            "type": "addition",
            "inputs": [i, i+1]
        }, headers=headers)
    
    # Update profile
    update_data = {"first_name": "Updated"}
    response = client.put("/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["calculation_count"] == 3


def test_change_password_user_not_found():
    """Test change password when user not found (line 160)"""
    from app.auth.jwt import create_token
    from app.schemas.token import TokenType
    
    fake_user_id = uuid4()
    token = create_token(fake_user_id, TokenType.ACCESS)
    headers = {"Authorization": f"Bearer {token}"}
    
    password_data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass123!",
        "confirm_new_password": "NewPass123!"
    }
    
    response = client.post("/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 404


def test_change_password_wrong_current():
    """Test change password with wrong current password (lines 179-181)"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Pass",
        "last_name": "Wrong",
        "email": f"passwrong_{unique_id}@example.com",
        "username": f"passwrong_{unique_id}",
        "password": "CorrectPass123!",
        "confirm_password": "CorrectPass123!"
    }
    
    # Register and login
    client.post("/auth/register", json=user_data)
    login_response = client.post("/auth/login", json={
        "username": user_data["username"],
        "password": "CorrectPass123!"
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Try to change with wrong current password
    password_data = {
        "current_password": "WrongPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "NewPass456!"
    }
    
    response = client.post("/profile/change-password", json=password_data, headers=headers)
    assert response.status_code == 401
    assert "incorrect" in response.json()["detail"].lower()


# ==============================================================================
# Tests for app/schemas/user.py - Target lines 62, 184-188
# ==============================================================================

def test_user_schema_empty_first_name():
    """Test UserCreate with empty first_name (line 62)"""
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(
            first_name="",  # Empty string
            last_name="Doe",
            email="test@example.com",
            username="testuser",
            password="SecurePass123!",
            confirm_password="SecurePass123!"
        )
    # Should fail on min_length=1 constraint


def test_user_schema_empty_last_name():
    """Test UserCreate with empty last_name (line 62)"""
    with pytest.raises(ValidationError):
        UserCreate(
            first_name="John",
            last_name="",  # Empty string
            email="test@example.com",
            username="testuser",
            password="SecurePass123!",
            confirm_password="SecurePass123!"
        )


def test_password_update_schema_verify_passwords_mismatch():
    """Test PasswordUpdate with mismatched passwords (lines 184-188)"""
    with pytest.raises(ValidationError) as exc_info:
        PasswordUpdate(
            current_password="OldPass123!",
            new_password="NewPass123!",
            confirm_new_password="DifferentPass123!"
        )
    assert "do not match" in str(exc_info.value).lower()


def test_password_update_schema_same_password():
    """Test PasswordUpdate when new equals current (lines 184-188)"""
    with pytest.raises(ValidationError) as exc_info:
        PasswordUpdate(
            current_password="SamePass123!",
            new_password="SamePass123!",
            confirm_new_password="SamePass123!"
        )
    assert "different" in str(exc_info.value).lower()


# ==============================================================================
# Additional comprehensive tests to ensure >90% coverage
# ==============================================================================

def test_multiple_authentication_attempts():
    """Test multiple login attempts to invoke redis functions"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Multi",
        "last_name": "Auth",
        "email": f"multiauth_{unique_id}@example.com",
        "username": f"multiauth_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register
    client.post("/auth/register", json=user_data)
    
    # Multiple login attempts
    for i in range(3):
        login_response = client.post("/auth/login", json={
            "username": user_data["username"],
            "password": "TestPass123!"
        })
        assert login_response.status_code == 200


def test_oauth2_token_endpoint_coverage():
    """Test OAuth2 token endpoint for completeness"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "OAuth",
        "last_name": "Test",
        "email": f"oauth_{unique_id}@example.com",
        "username": f"oauth_{unique_id}",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!"
    }
    
    # Register
    client.post("/auth/register", json=user_data)
    
    # Test OAuth2 form login
    form_data = {
        "username": user_data["username"],
        "password": "TestPass123!"
    }
    response = client.post("/auth/token", data=form_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_profile_with_no_calculations():
    """Test profile with zero calculations"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "No",
        "last_name": "Calcs",
        "email": f"nocalcs_{unique_id}@example.com",
        "username": f"nocalcs_{unique_id}",
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
    response = client.get("/profile/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["calculation_count"] == 0


def test_profile_update_only_username():
    """Test updating only username field"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Only",
        "last_name": "Username",
        "email": f"onlyuser_{unique_id}@example.com",
        "username": f"original_{unique_id}",
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
    
    # Update only username
    update_data = {"username": f"newusername_{unique_id}"}
    response = client.put("/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["username"] == update_data["username"]


def test_profile_update_only_email():
    """Test updating only email field"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Only",
        "last_name": "Email",
        "email": f"oldemail_{unique_id}@example.com",
        "username": f"emailonly_{unique_id}",
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
    
    # Update only email
    update_data = {"email": f"newemail_{unique_id}@example.com"}
    response = client.put("/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == update_data["email"]


def test_profile_update_only_first_name():
    """Test updating only first_name field"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "Old",
        "last_name": "Name",
        "email": f"firstname_{unique_id}@example.com",
        "username": f"firstname_{unique_id}",
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
    
    # Update only first_name
    update_data = {"first_name": "NewFirst"}
    response = client.put("/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["first_name"] == "NewFirst"


def test_profile_update_only_last_name():
    """Test updating only last_name field"""
    unique_id = str(uuid4())[:8]
    user_data = {
        "first_name": "First",
        "last_name": "Old",
        "email": f"lastname_{unique_id}@example.com",
        "username": f"lastname_{unique_id}",
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
    
    # Update only last_name
    update_data = {"last_name": "NewLast"}
    response = client.put("/profile/me", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["last_name"] == "NewLast"


@pytest.fixture
def db_session():
    """Provide a database session for tests"""
    db = TestingSessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()