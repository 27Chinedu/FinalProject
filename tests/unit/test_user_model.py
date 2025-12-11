# tests/unit/test_user_model.py

import pytest
from uuid import uuid4
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.models.user import User, utcnow
from datetime import datetime, timezone
import time
from faker import Faker

fake = Faker()

def test_user_init_with_hashed_password():
    """Test User initialization with hashed_password parameter"""
    hashed = User.hash_password("TestPass123!")
    user = User(
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        hashed_password=hashed
    )
    assert user.password == hashed

def test_user_str_representation():
    """Test User string representation"""
    user = User(
        username="testuser",
        email="test@example.com",
        first_name="John",
        last_name="Doe",
        password="hashed"
    )
    str_repr = str(user)
    assert "User" in str_repr
    assert "John" in str_repr
    assert "Doe" in str_repr
    assert "test@example.com" in str_repr

def test_user_update_method():
    """Test User update method"""
    user = User(
        username="testuser",
        email="test@example.com",
        first_name="Old",
        last_name="Name",
        password="hashed"
    )
    # Set initial updated_at
    user.updated_at = utcnow()
    original_updated_at = user.updated_at
    
    # Small delay to ensure timestamp difference
    time.sleep(0.01)
    
    result = user.update(first_name="New", last_name="Person")
    
    assert result == user
    assert user.first_name == "New"
    assert user.last_name == "Person"
    assert user.updated_at > original_updated_at

def test_user_hashed_password_property():
    """Test User hashed_password property"""
    password = "TestPass123!"
    hashed = User.hash_password(password)
    user = User(
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        password=hashed
    )
    assert user.hashed_password == hashed

def test_user_register_short_password(db_session):
    """Test User.register with short password"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "short"
    }
    with pytest.raises(ValueError, match="at least 6 characters"):
        User.register(db_session, user_data)

def test_user_register_no_password(db_session):
    """Test User.register with no password"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": None
    }
    with pytest.raises(ValueError, match="at least 6 characters"):
        User.register(db_session, user_data)

def test_user_register_duplicate_username(db_session):
    """Test User.register with duplicate username"""
    username = fake.unique.user_name()
    user_data = {
        "username": username,
        "email": fake.unique.email(),
        "first_name": "First",
        "last_name": "User",
        "password": "TestPass123!"
    }
    User.register(db_session, user_data)
    db_session.commit()
    
    # Try to register with same username
    user_data2 = {
        "username": username,
        "email": fake.unique.email(),
        "first_name": "Second",
        "last_name": "User",
        "password": "TestPass123!"
    }
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register(db_session, user_data2)

def test_user_register_duplicate_email(db_session):
    """Test User.register with duplicate email"""
    email = fake.unique.email()
    user_data = {
        "username": fake.unique.user_name(),
        "email": email,
        "first_name": "First",
        "last_name": "User",
        "password": "TestPass123!"
    }
    User.register(db_session, user_data)
    db_session.commit()
    
    # Try to register with same email
    user_data2 = {
        "username": fake.unique.user_name(),
        "email": email,
        "first_name": "Second",
        "last_name": "User",
        "password": "TestPass123!"
    }
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register(db_session, user_data2)

def test_user_authenticate_invalid_username(db_session):
    """Test User.authenticate with non-existent username"""
    result = User.authenticate(db_session, "nonexistent", "password")
    assert result is None

def test_user_authenticate_wrong_password(db_session):
    """Test User.authenticate with wrong password"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "CorrectPass123!"
    }
    user = User.register(db_session, user_data)
    db_session.commit()
    
    result = User.authenticate(db_session, user_data["username"], "WrongPass123!")
    assert result is None

def test_user_authenticate_by_email(db_session):
    """Test User.authenticate using email"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "TestPass123!"
    }
    User.register(db_session, user_data)
    db_session.commit()
    
    result = User.authenticate(db_session, user_data["email"], "TestPass123!")
    assert result is not None
    assert "access_token" in result
    assert "refresh_token" in result

def test_user_authenticate_updates_last_login(db_session):
    """Test that authenticate updates last_login"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "TestPass123!"
    }
    user = User.register(db_session, user_data)
    db_session.commit()
    
    original_last_login = user.last_login
    
    result = User.authenticate(db_session, user_data["username"], "TestPass123!")
    db_session.commit()
    db_session.refresh(user)
    
    assert user.last_login is not None
    assert user.last_login != original_last_login

def test_user_verify_token_invalid():
    """Test User.verify_token with invalid token"""
    result = User.verify_token("invalid_token")
    assert result is None

def test_user_verify_token_no_sub():
    """Test User.verify_token with token missing 'sub'"""
    from jose import jwt
    from app.core.config import settings
    
    # Create token without 'sub'
    token = jwt.encode({"type": "access"}, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    result = User.verify_token(token)
    assert result is None

def test_user_verify_token_invalid_sub():
    """Test User.verify_token with invalid UUID in 'sub'"""
    from jose import jwt
    from app.core.config import settings
    
    # Create token with non-UUID 'sub'
    token = jwt.encode({"sub": "not-a-uuid"}, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    result = User.verify_token(token)
    assert result is None

def test_utcnow_helper():
    """Test utcnow helper function"""
    now = utcnow()
    assert isinstance(now, datetime)
    assert now.tzinfo == timezone.utc

def test_user_create_access_token():
    """Test User.create_access_token method"""
    user_id = uuid4()
    token = User.create_access_token({"sub": str(user_id)})

    assert isinstance(token, str)
    assert len(token) > 0

    # Verify token can be decoded
    from jose import jwt
    from app.core.config import settings
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == str(user_id)
    assert payload["type"] == "access"

def test_user_create_refresh_token():
    """Test User.create_refresh_token method"""
    user_id = uuid4()
    token = User.create_refresh_token({"sub": str(user_id)})

    assert isinstance(token, str)
    assert len(token) > 0

    # Verify token can be decoded
    from jose import jwt
    from app.core.config import settings
    payload = jwt.decode(token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == str(user_id)
    assert payload["type"] == "refresh"

def test_user_verify_token_valid():
    """Test User.verify_token with valid token"""
    user_id = uuid4()
    token = User.create_access_token({"sub": str(user_id)})

    result = User.verify_token(token)
    assert result == user_id

def test_user_register_success(db_session):
    """Test successful user registration"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "TestPass123!"
    }
    user = User.register(db_session, user_data)

    assert user.username == user_data["username"]
    assert user.email == user_data["email"]
    assert user.first_name == user_data["first_name"]
    assert user.last_name == user_data["last_name"]
    assert user.is_active is True
    assert user.is_verified is False
    assert user.password != user_data["password"]  # Should be hashed

def test_user_authenticate_success(db_session):
    """Test successful user authentication"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "TestPass123!"
    }
    user = User.register(db_session, user_data)
    db_session.commit()

    result = User.authenticate(db_session, user_data["username"], user_data["password"])

    assert result is not None
    assert "access_token" in result
    assert "refresh_token" in result
    assert "token_type" in result
    assert result["token_type"] == "bearer"
    assert "expires_at" in result
    assert result["user"] == user

def test_user_register_empty_password(db_session):
    """Test User.register with empty password"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": ""
    }
    with pytest.raises(ValueError, match="at least 6 characters"):
        User.register(db_session, user_data)

def test_user_created_at_timestamp(db_session):
    """Test that created_at timestamp is set"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "TestPass123!"
    }
    user = User.register(db_session, user_data)
    db_session.commit()
    db_session.refresh(user)

    assert user.created_at is not None
    assert isinstance(user.created_at, datetime)
    assert user.created_at.tzinfo == timezone.utc

def test_user_updated_at_timestamp(db_session):
    """Test that updated_at timestamp is set"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "TestPass123!"
    }
    user = User.register(db_session, user_data)
    db_session.commit()
    db_session.refresh(user)

    assert user.updated_at is not None
    assert isinstance(user.updated_at, datetime)
    assert user.updated_at.tzinfo == timezone.utc

def test_user_update_multiple_fields(db_session):
    """Test updating multiple fields at once"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Old",
        "last_name": "Name",
        "password": "TestPass123!"
    }
    user = User.register(db_session, user_data)
    db_session.commit()

    user.update(first_name="New", last_name="Person", email="new@example.com")

    assert user.first_name == "New"
    assert user.last_name == "Person"
    assert user.email == "new@example.com"

def test_user_authenticate_inactive_user(db_session):
    """Test authentication still works for inactive users (deactivation check is at route level)"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "TestPass123!"
    }
    user = User.register(db_session, user_data)
    user.is_active = False
    db_session.commit()

    # Authentication at model level doesn't check is_active
    # That's checked at the route/dependency level
    result = User.authenticate(db_session, user_data["username"], user_data["password"])
    assert result is not None

def test_user_verify_password_method(db_session):
    """Test verify_password instance method"""
    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "TestPass123!"
    }
    user = User.register(db_session, user_data)
    db_session.commit()

    assert user.verify_password("TestPass123!")
    assert not user.verify_password("WrongPassword")

def test_user_relationship_with_calculations(db_session):
    """Test user-calculations relationship"""
    from app.models.calculation import Calculation

    user_data = {
        "username": fake.unique.user_name(),
        "email": fake.unique.email(),
        "first_name": "Test",
        "last_name": "User",
        "password": "TestPass123!"
    }
    user = User.register(db_session, user_data)
    db_session.commit()

    # Add calculations
    calc1 = Calculation.create("addition", user.id, [1, 2])
    calc1.result = calc1.get_result()
    calc2 = Calculation.create("subtraction", user.id, [10, 5])
    calc2.result = calc2.get_result()

    db_session.add(calc1)
    db_session.add(calc2)
    db_session.commit()
    db_session.refresh(user)

    assert len(user.calculations) == 2