# tests/unit/test_jwt.py

import pytest
from datetime import timedelta
from uuid import uuid4
from jose import jwt, JWTError
from app.auth.jwt import (
    verify_password,
    get_password_hash,
    create_token,
    pwd_context
)
from app.schemas.token import TokenType
from app.core.config import settings

def test_password_hashing():
    """Test password hashing"""
    password = "TestPassword123!"
    hashed = get_password_hash(password)
    
    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("WrongPassword", hashed)

def test_password_hash_uniqueness():
    """Test that same password creates different hashes"""
    password = "TestPassword123!"
    hash1 = get_password_hash(password)
    hash2 = get_password_hash(password)
    
    assert hash1 != hash2
    assert verify_password(password, hash1)
    assert verify_password(password, hash2)

def test_create_access_token():
    """Test creating access token"""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    assert isinstance(token, str)
    assert len(token) > 0
    
    # Decode and verify
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == str(user_id)
    assert payload["type"] == TokenType.ACCESS.value

def test_create_refresh_token():
    """Test creating refresh token"""
    user_id = uuid4()
    token = create_token(user_id, TokenType.REFRESH)
    
    assert isinstance(token, str)
    assert len(token) > 0
    
    # Decode and verify
    payload = jwt.decode(token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == str(user_id)
    assert payload["type"] == TokenType.REFRESH.value

def test_create_token_with_custom_expiry():
    """Test creating token with custom expiration"""
    user_id = uuid4()
    custom_delta = timedelta(minutes=5)
    token = create_token(user_id, TokenType.ACCESS, expires_delta=custom_delta)
    
    assert isinstance(token, str)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert "exp" in payload

def test_create_token_with_string_user_id():
    """Test creating token with string user_id"""
    user_id = str(uuid4())
    token = create_token(user_id, TokenType.ACCESS)
    
    assert isinstance(token, str)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == user_id

def test_verify_password_with_wrong_password():
    """Test verify_password returns False for wrong password"""
    password = "CorrectPassword123!"
    hashed = get_password_hash(password)
    
    assert not verify_password("WrongPassword123!", hashed)

def test_token_contains_jti():
    """Test that tokens contain JTI (JWT ID)"""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert "jti" in payload
    assert len(payload["jti"]) > 0

def test_token_contains_iat():
    """Test that tokens contain IAT (issued at)"""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert "iat" in payload