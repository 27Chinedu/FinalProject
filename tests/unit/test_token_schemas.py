# tests/unit/test_token_schemas.py
"""
Unit tests for token schemas.
"""

import pytest
from pydantic import ValidationError
from uuid import uuid4
from datetime import datetime

from app.schemas.token import (
    TokenType,
    Token,
    TokenData,
    TokenResponse
)


class TestTokenType:
    """Test TokenType enum"""

    def test_token_type_access(self):
        """Test ACCESS token type"""
        assert TokenType.ACCESS == "access"
        assert TokenType.ACCESS.value == "access"

    def test_token_type_refresh(self):
        """Test REFRESH token type"""
        assert TokenType.REFRESH == "refresh"
        assert TokenType.REFRESH.value == "refresh"

    def test_token_type_values(self):
        """Test all token type values"""
        assert set(t.value for t in TokenType) == {"access", "refresh"}


class TestToken:
    """Test Token schema"""

    def test_token_valid(self):
        """Test valid token"""
        data = {
            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
            "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
            "token_type": "bearer",
            "expires_at": datetime.utcnow()
        }
        token = Token(**data)
        assert token.access_token == data["access_token"]
        assert token.refresh_token == data["refresh_token"]
        assert token.token_type == "bearer"

    def test_token_default_type(self):
        """Test token_type defaults to bearer"""
        data = {
            "access_token": "access_token_value",
            "refresh_token": "refresh_token_value",
            "expires_at": datetime.utcnow()
        }
        token = Token(**data)
        assert token.token_type == "bearer"

    def test_token_missing_access_token(self):
        """Test missing access_token fails"""
        data = {
            "refresh_token": "refresh_token_value",
            "expires_at": datetime.utcnow()
        }
        with pytest.raises(ValidationError):
            Token(**data)

    def test_token_missing_refresh_token(self):
        """Test missing refresh_token fails"""
        data = {
            "access_token": "access_token_value",
            "expires_at": datetime.utcnow()
        }
        with pytest.raises(ValidationError):
            Token(**data)

    def test_token_missing_expires_at(self):
        """Test missing expires_at fails"""
        data = {
            "access_token": "access_token_value",
            "refresh_token": "refresh_token_value"
        }
        with pytest.raises(ValidationError):
            Token(**data)


class TestTokenData:
    """Test TokenData schema"""

    def test_token_data_valid(self):
        """Test valid token data"""
        user_id = uuid4()
        exp = datetime.utcnow()
        data = {
            "user_id": user_id,
            "exp": exp,
            "jti": "unique_token_id",
            "token_type": TokenType.ACCESS
        }
        token_data = TokenData(**data)
        assert token_data.user_id == user_id
        assert token_data.exp == exp
        assert token_data.jti == "unique_token_id"
        assert token_data.token_type == TokenType.ACCESS

    def test_token_data_refresh_type(self):
        """Test token data with refresh type"""
        user_id = uuid4()
        data = {
            "user_id": user_id,
            "exp": datetime.utcnow(),
            "jti": "refresh_token_id",
            "token_type": TokenType.REFRESH
        }
        token_data = TokenData(**data)
        assert token_data.token_type == TokenType.REFRESH

    def test_token_data_missing_user_id(self):
        """Test missing user_id fails"""
        data = {
            "exp": datetime.utcnow(),
            "jti": "token_id",
            "token_type": TokenType.ACCESS
        }
        with pytest.raises(ValidationError):
            TokenData(**data)

    def test_token_data_missing_jti(self):
        """Test missing jti fails"""
        data = {
            "user_id": uuid4(),
            "exp": datetime.utcnow(),
            "token_type": TokenType.ACCESS
        }
        with pytest.raises(ValidationError):
            TokenData(**data)


class TestTokenResponse:
    """Test TokenResponse schema"""

    def test_token_response_valid(self):
        """Test valid token response"""
        user_id = uuid4()
        data = {
            "access_token": "access_token_value",
            "refresh_token": "refresh_token_value",
            "token_type": "bearer",
            "expires_at": datetime.utcnow(),
            "user_id": user_id,
            "username": "testuser",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "is_active": True,
            "is_verified": False
        }
        response = TokenResponse(**data)
        assert response.access_token == "access_token_value"
        assert response.refresh_token == "refresh_token_value"
        assert response.user_id == user_id
        assert response.username == "testuser"
        assert response.email == "test@example.com"
        assert response.is_active is True
        assert response.is_verified is False

    def test_token_response_verified_user(self):
        """Test token response with verified user"""
        user_id = uuid4()
        data = {
            "access_token": "access_token",
            "refresh_token": "refresh_token",
            "token_type": "bearer",
            "expires_at": datetime.utcnow(),
            "user_id": user_id,
            "username": "verified",
            "email": "verified@example.com",
            "first_name": "Verified",
            "last_name": "User",
            "is_active": True,
            "is_verified": True
        }
        response = TokenResponse(**data)
        assert response.is_verified is True

    def test_token_response_inactive_user(self):
        """Test token response with inactive user"""
        user_id = uuid4()
        data = {
            "access_token": "access_token",
            "refresh_token": "refresh_token",
            "token_type": "bearer",
            "expires_at": datetime.utcnow(),
            "user_id": user_id,
            "username": "inactive",
            "email": "inactive@example.com",
            "first_name": "Inactive",
            "last_name": "User",
            "is_active": False,
            "is_verified": False
        }
        response = TokenResponse(**data)
        assert response.is_active is False

    def test_token_response_default_token_type(self):
        """Test token_type defaults to bearer"""
        user_id = uuid4()
        data = {
            "access_token": "access_token",
            "refresh_token": "refresh_token",
            "expires_at": datetime.utcnow(),
            "user_id": user_id,
            "username": "user",
            "email": "user@example.com",
            "first_name": "First",
            "last_name": "Last",
            "is_active": True,
            "is_verified": False
        }
        response = TokenResponse(**data)
        assert response.token_type == "bearer"

    def test_token_response_missing_user_id(self):
        """Test missing user_id fails"""
        data = {
            "access_token": "access_token",
            "refresh_token": "refresh_token",
            "expires_at": datetime.utcnow(),
            "username": "user",
            "email": "user@example.com",
            "first_name": "First",
            "last_name": "Last",
            "is_active": True,
            "is_verified": False
        }
        with pytest.raises(ValidationError):
            TokenResponse(**data)

    def test_token_response_missing_username(self):
        """Test missing username fails"""
        data = {
            "access_token": "access_token",
            "refresh_token": "refresh_token",
            "expires_at": datetime.utcnow(),
            "user_id": uuid4(),
            "email": "user@example.com",
            "first_name": "First",
            "last_name": "Last",
            "is_active": True,
            "is_verified": False
        }
        with pytest.raises(ValidationError):
            TokenResponse(**data)
