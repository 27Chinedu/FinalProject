# tests/unit/test_auth_dependencies.py

import pytest
from uuid import uuid4
from datetime import datetime
from fastapi import HTTPException
from app.auth.dependencies import get_current_user, get_current_active_user
from app.schemas.user import UserResponse
from app.models.user import User

def test_get_current_user_with_full_payload():
    """Test get_current_user with full user payload"""
    from jose import jwt
    from app.core.config import settings
    
    user_id = uuid4()
    payload = {
        "id": str(user_id),
        "username": "testuser",
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "is_active": True,
        "is_verified": False,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    user = get_current_user(token)
    
    assert isinstance(user, UserResponse)
    assert user.username == "testuser"

def test_get_current_user_with_minimal_payload():
    """Test get_current_user with minimal payload (only sub)"""
    from jose import jwt
    from app.core.config import settings
    
    user_id = uuid4()
    payload = {"sub": str(user_id)}
    
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    user = get_current_user(token)
    
    assert isinstance(user, UserResponse)
    assert user.id == user_id
    assert user.username == "unknown"

def test_get_current_user_with_uuid_token_data():
    """Test get_current_user when token data is UUID"""
    # This tests the edge case where verify_token returns a UUID directly
    # We need to mock User.verify_token to return a UUID
    from unittest.mock import patch
    from app.models.user import User
    
    user_id = uuid4()
    
    with patch.object(User, 'verify_token', return_value=user_id):
        fake_token = "fake_token"
        user = get_current_user(fake_token)
        
        assert isinstance(user, UserResponse)
        assert user.id == user_id

def test_get_current_user_invalid_token():
    """Test get_current_user with invalid token"""
    with pytest.raises(HTTPException) as exc_info:
        get_current_user("invalid_token")
    
    assert exc_info.value.status_code == 401
    assert "Could not validate credentials" in exc_info.value.detail

def test_get_current_user_no_sub_in_payload():
    """Test get_current_user with payload missing sub"""
    from jose import jwt
    from app.core.config import settings
    
    payload = {"username": "test"}  # Missing 'sub'
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(token)
    
    assert exc_info.value.status_code == 401

def test_get_current_active_user_active():
    """Test get_current_active_user with active user"""
    user = UserResponse(
        id=uuid4(),
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        is_active=True,
        is_verified=False,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    result = get_current_active_user(user)
    assert result == user

def test_get_current_active_user_inactive():
    """Test get_current_active_user with inactive user"""
    user = UserResponse(
        id=uuid4(),
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        is_active=False,
        is_verified=False,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    with pytest.raises(HTTPException) as exc_info:
        get_current_active_user(user)
    
    assert exc_info.value.status_code == 400
    assert "Inactive user" in exc_info.value.detail