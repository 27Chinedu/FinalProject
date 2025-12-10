# tests/unit/test_auth.py

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4, UUID
from jose import jwt, JWTError
from fastapi import HTTPException

from app.auth.jwt import (
    verify_password,
    get_password_hash,
    create_token,
    pwd_context
)
from app.auth.dependencies import get_current_user, get_current_active_user
from app.auth.redis import add_to_blacklist, is_blacklisted
from app.schemas.token import TokenType
from app.schemas.user import UserResponse
from app.core.config import get_settings

settings = get_settings()


class TestPasswordHashing:
    """Test password hashing and verification"""

    def test_password_hash_generation(self):
        """Test that password hashing generates a hash"""
        password = "TestPass123!"
        hashed = get_password_hash(password)

        assert hashed is not None
        assert hashed != password
        assert len(hashed) > 0
        assert hashed.startswith("$2b$")  # bcrypt prefix

    def test_password_verification_success(self):
        """Test successful password verification"""
        password = "TestPass123!"
        hashed = get_password_hash(password)

        assert verify_password(password, hashed) is True

    def test_password_verification_failure(self):
        """Test failed password verification"""
        password = "TestPass123!"
        wrong_password = "WrongPass456!"
        hashed = get_password_hash(password)

        assert verify_password(wrong_password, hashed) is False

    def test_same_password_different_hashes(self):
        """Test that the same password generates different hashes (due to salt)"""
        password = "TestPass123!"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)

        assert hash1 != hash2
        assert verify_password(password, hash1)
        assert verify_password(password, hash2)

    def test_empty_password_hashing(self):
        """Test hashing an empty password"""
        password = ""
        hashed = get_password_hash(password)

        assert hashed is not None
        assert verify_password(password, hashed)

    def test_long_password_hashing(self):
        """Test hashing a very long password"""
        password = "A" * 1000
        hashed = get_password_hash(password)

        assert hashed is not None
        assert verify_password(password, hashed)

    def test_special_characters_in_password(self):
        """Test password with special characters"""
        password = "P@ssw0rd!#$%^&*()"
        hashed = get_password_hash(password)

        assert verify_password(password, hashed)

    def test_unicode_password(self):
        """Test password with unicode characters"""
        password = "P@ssw0rd_你好_مرحبا"
        hashed = get_password_hash(password)

        assert verify_password(password, hashed)


class TestJWTTokenCreation:
    """Test JWT token creation"""

    def test_create_access_token_with_string_user_id(self):
        """Test creating an access token with string user ID"""
        user_id = str(uuid4())
        token = create_token(user_id, TokenType.ACCESS)

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

        # Decode and verify
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == user_id
        assert payload["type"] == TokenType.ACCESS.value
        assert "exp" in payload
        assert "iat" in payload
        assert "jti" in payload

    def test_create_access_token_with_uuid_user_id(self):
        """Test creating an access token with UUID user ID"""
        user_id = uuid4()
        token = create_token(user_id, TokenType.ACCESS)

        assert token is not None

        # Decode and verify
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == str(user_id)
        assert payload["type"] == TokenType.ACCESS.value

    def test_create_refresh_token(self):
        """Test creating a refresh token"""
        user_id = str(uuid4())
        token = create_token(user_id, TokenType.REFRESH)

        assert token is not None

        # Decode with correct secret for refresh tokens
        payload = jwt.decode(token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == user_id
        assert payload["type"] == TokenType.REFRESH.value

    def test_access_token_expiration(self):
        """Test that access token has correct expiration"""
        user_id = str(uuid4())
        token = create_token(user_id, TokenType.ACCESS)

        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)

        # Check that expiration is approximately ACCESS_TOKEN_EXPIRE_MINUTES in the future
        expected_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        actual_delta = exp - iat

        # Allow 5 second tolerance
        assert abs(actual_delta.total_seconds() - expected_delta.total_seconds()) < 5

    def test_refresh_token_expiration(self):
        """Test that refresh token has correct expiration"""
        user_id = str(uuid4())
        token = create_token(user_id, TokenType.REFRESH)

        payload = jwt.decode(token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])

        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)

        # Check that expiration is approximately REFRESH_TOKEN_EXPIRE_DAYS in the future
        expected_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        actual_delta = exp - iat

        # Allow 5 second tolerance
        assert abs(actual_delta.total_seconds() - expected_delta.total_seconds()) < 5

    def test_custom_expiration_delta(self):
        """Test creating token with custom expiration"""
        user_id = str(uuid4())
        custom_delta = timedelta(hours=2)
        token = create_token(user_id, TokenType.ACCESS, expires_delta=custom_delta)

        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)

        actual_delta = exp - iat

        # Allow 5 second tolerance
        assert abs(actual_delta.total_seconds() - custom_delta.total_seconds()) < 5

    def test_jti_uniqueness(self):
        """Test that each token has a unique JTI"""
        user_id = str(uuid4())
        token1 = create_token(user_id, TokenType.ACCESS)
        token2 = create_token(user_id, TokenType.ACCESS)

        payload1 = jwt.decode(token1, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        payload2 = jwt.decode(token2, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert payload1["jti"] != payload2["jti"]

    def test_token_contains_all_required_claims(self):
        """Test that token contains all required claims"""
        user_id = str(uuid4())
        token = create_token(user_id, TokenType.ACCESS)

        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert "sub" in payload
        assert "type" in payload
        assert "exp" in payload
        assert "iat" in payload
        assert "jti" in payload


class TestJWTDependencies:
    """Test JWT dependency functions"""

    def test_get_current_user_with_minimal_payload(self):
        """Test get_current_user with minimal JWT payload (only sub)"""
        user_id = uuid4()
        token = create_token(user_id, TokenType.ACCESS)

        user = get_current_user(token)

        assert isinstance(user, UserResponse)
        assert user.id == user_id
        # Minimal payload should use default values
        assert user.username == "unknown"
        assert user.email == "unknown@example.com"
        assert user.first_name == "Unknown"
        assert user.last_name == "User"
        assert user.is_active is True
        assert user.is_verified is False

    def test_get_current_user_with_full_payload(self):
        """Test get_current_user with full user data in JWT"""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        # Create token with full payload manually
        full_payload = {
            "id": str(user_id),
            "username": "testuser",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "is_active": True,
            "is_verified": True,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "exp": now + timedelta(minutes=30),
            "iat": now
        }

        token = jwt.encode(full_payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)

        user = get_current_user(token)

        assert isinstance(user, UserResponse)
        assert user.id == user_id
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.first_name == "Test"
        assert user.last_name == "User"
        assert user.is_active is True
        assert user.is_verified is True

    def test_get_current_user_with_invalid_token(self):
        """Test get_current_user with invalid token"""
        with pytest.raises(HTTPException) as exc_info:
            get_current_user("invalid_token")

        assert exc_info.value.status_code == 401
        assert "Could not validate credentials" in exc_info.value.detail

    def test_get_current_user_with_expired_token(self):
        """Test get_current_user with expired token"""
        user_id = uuid4()
        # Create token that expired 1 hour ago
        expired_delta = timedelta(hours=-1)

        payload = {
            "sub": str(user_id),
            "exp": datetime.now(timezone.utc) + expired_delta,
            "iat": datetime.now(timezone.utc) + timedelta(hours=-2)
        }

        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(token)

        assert exc_info.value.status_code == 401

    def test_get_current_user_with_missing_sub(self):
        """Test get_current_user with token missing sub claim"""
        payload = {
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            "iat": datetime.now(timezone.utc)
        }

        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(token)

        assert exc_info.value.status_code == 401

    def test_get_current_user_with_invalid_uuid(self):
        """Test get_current_user with invalid UUID in sub"""
        payload = {
            "sub": "not-a-valid-uuid",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            "iat": datetime.now(timezone.utc)
        }

        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(token)

        assert exc_info.value.status_code == 401

    def test_get_current_active_user_with_active_user(self):
        """Test get_current_active_user with active user"""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        payload = {
            "sub": str(user_id),
            "is_active": True,
            "exp": now + timedelta(minutes=30),
            "iat": now
        }

        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
        current_user = get_current_user(token)

        # This should work fine
        active_user = get_current_active_user(current_user)
        assert active_user.id == user_id
        assert active_user.is_active is True

    def test_get_current_active_user_with_inactive_user(self):
        """Test get_current_active_user with inactive user"""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        payload = {
            "id": str(user_id),
            "username": "testuser",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "is_active": False,  # Inactive user
            "is_verified": True,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "exp": now + timedelta(minutes=30),
            "iat": now
        }

        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
        current_user = get_current_user(token)

        with pytest.raises(HTTPException) as exc_info:
            get_current_active_user(current_user)

        assert exc_info.value.status_code == 400
        assert "Inactive user" in exc_info.value.detail


class TestRedisStubs:
    """Test Redis stub implementations"""

    @pytest.mark.asyncio
    async def test_add_to_blacklist(self):
        """Test adding token to blacklist (stub)"""
        jti = "test_jti_123"
        exp = int(datetime.now(timezone.utc).timestamp()) + 3600

        # Should not raise any errors
        result = await add_to_blacklist(jti, exp)
        assert result is None

    @pytest.mark.asyncio
    async def test_is_blacklisted(self):
        """Test checking if token is blacklisted (stub)"""
        jti = "test_jti_123"

        # Stub always returns False
        result = await is_blacklisted(jti)
        assert result is False

    @pytest.mark.asyncio
    async def test_blacklist_multiple_tokens(self):
        """Test blacklisting multiple tokens"""
        jtis = [f"jti_{i}" for i in range(10)]
        exp = int(datetime.now(timezone.utc).timestamp()) + 3600

        for jti in jtis:
            await add_to_blacklist(jti, exp)
            result = await is_blacklisted(jti)
            # Stub implementation always returns False
            assert result is False
