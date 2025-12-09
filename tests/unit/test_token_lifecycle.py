# tests/unit/test_token_lifecycle.py

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from jose import jwt, JWTError
from app.auth.jwt import create_token, verify_password, get_password_hash
from app.core.config import settings
from app.schemas.token import TokenType
from app.auth.redis import add_to_blacklist, is_blacklisted


class TestTokenCreation:
    """Test JWT token creation"""

    def test_create_access_token_default_expiry(self):
        """Test creating access token with default expiry"""
        user_id = uuid4()

        token = create_token(user_id, TokenType.ACCESS)

        assert token is not None
        assert isinstance(token, str)

        # Decode and verify
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        assert payload["sub"] == str(user_id)
        assert payload["type"] == TokenType.ACCESS.value
        assert "exp" in payload
        assert "jti" in payload

    def test_create_access_token_custom_expiry(self):
        """Test creating access token with custom expiry"""
        user_id = uuid4()
        expires = timedelta(minutes=60)

        token = create_token(user_id, TokenType.ACCESS, expires_delta=expires)

        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        # Check expiry is roughly 60 minutes from now
        exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        time_diff = (exp_time - now).total_seconds()

        assert 3500 < time_diff < 3700  # ~60 minutes (with some tolerance)

    def test_create_refresh_token(self):
        """Test creating refresh token"""
        user_id = uuid4()

        token = create_token(user_id, TokenType.REFRESH)

        assert token is not None
        assert isinstance(token, str)

        # Decode with refresh secret
        payload = jwt.decode(
            token,
            settings.JWT_REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        assert payload["sub"] == str(user_id)
        assert payload["type"] == TokenType.REFRESH.value

    def test_access_and_refresh_tokens_different(self):
        """Test that access and refresh tokens are different"""
        user_id = uuid4()

        access_token = create_token(user_id, TokenType.ACCESS)
        refresh_token = create_token(user_id, TokenType.REFRESH)

        assert access_token != refresh_token

    def test_token_includes_jti(self):
        """Test that tokens include JTI (JWT ID) for tracking"""
        user_id = uuid4()

        token = create_token(user_id, TokenType.ACCESS)

        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        # JTI should be present for blacklisting support
        assert "jti" in payload
        assert isinstance(payload["jti"], str)
        assert len(payload["jti"]) == 32  # 16 bytes hex = 32 chars

    def test_multiple_tokens_unique_jti(self):
        """Test that each token has unique JTI"""
        user_id = uuid4()

        token1 = create_token(user_id, TokenType.ACCESS)
        token2 = create_token(user_id, TokenType.ACCESS)

        payload1 = jwt.decode(token1, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        payload2 = jwt.decode(token2, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert payload1["jti"] != payload2["jti"]

    def test_token_with_uuid_user_id(self):
        """Test token creation with UUID user_id"""
        user_id = uuid4()

        token = create_token(user_id, TokenType.ACCESS)
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        # Should convert UUID to string
        assert payload["sub"] == str(user_id)

    def test_token_with_string_user_id(self):
        """Test token creation with string user_id"""
        user_id = str(uuid4())

        token = create_token(user_id, TokenType.ACCESS)
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert payload["sub"] == user_id


class TestTokenVerification:
    """Test token verification"""

    def test_verify_valid_token(self):
        """Test verifying a valid token"""
        user_id = uuid4()
        token = create_token(user_id, TokenType.ACCESS)

        # Decode manually to verify
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert payload is not None
        assert payload["sub"] == str(user_id)

    def test_verify_expired_token(self):
        """Test verifying an expired token"""
        user_id = uuid4()
        expires = timedelta(seconds=-10)  # Already expired

        token = create_token(user_id, TokenType.ACCESS, expires_delta=expires)

        # Should raise JWTError when decoding
        with pytest.raises(JWTError):
            jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

    def test_verify_invalid_signature(self):
        """Test verifying token with invalid signature"""
        # Create token with wrong key
        user_id = uuid4()
        token = jwt.encode({"sub": str(user_id)}, "wrong-key", algorithm=settings.ALGORITHM)

        # Should raise JWTError
        with pytest.raises(JWTError):
            jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

    def test_verify_malformed_token(self):
        """Test verifying malformed token"""
        malformed_token = "not.a.valid.jwt.token"

        with pytest.raises(JWTError):
            jwt.decode(malformed_token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])


class TestPasswordHashing:
    """Test password hashing functionality"""

    def test_hash_password(self):
        """Test password hashing"""
        password = "TestPassword123!"

        hashed = get_password_hash(password)

        assert hashed != password
        assert hashed.startswith("$2b$")  # bcrypt format
        assert len(hashed) == 60  # bcrypt hash length

    def test_verify_correct_password(self):
        """Test verifying correct password"""
        password = "TestPassword123!"
        hashed = get_password_hash(password)

        assert verify_password(password, hashed) is True

    def test_verify_wrong_password(self):
        """Test verifying wrong password"""
        password = "TestPassword123!"
        hashed = get_password_hash(password)

        assert verify_password("WrongPassword!", hashed) is False

    def test_same_password_different_hashes(self):
        """Test that same password produces different hashes (salt)"""
        password = "TestPassword123!"

        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)

        # Hashes should be different due to random salt
        assert hash1 != hash2

        # But both should verify correctly
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True


class TestTokenBlacklisting:
    """Test token blacklisting functionality"""

    @pytest.mark.asyncio
    async def test_add_token_to_blacklist(self):
        """Test adding token to blacklist"""
        jti = str(uuid4())
        exp = 3600

        # Should not raise error
        await add_to_blacklist(jti, exp)

    @pytest.mark.asyncio
    async def test_check_non_blacklisted_token(self):
        """Test checking non-blacklisted token"""
        jti = str(uuid4())

        is_blocked = await is_blacklisted(jti)

        # Stub implementation always returns False
        assert is_blocked is False

    @pytest.mark.asyncio
    async def test_blacklist_stub_behavior(self):
        """Test that blacklist stub doesn't actually block"""
        jti = str(uuid4())

        # Add to blacklist
        await add_to_blacklist(jti, 3600)

        # Check if blacklisted (stub returns False)
        is_blocked = await is_blacklisted(jti)

        assert is_blocked is False

    @pytest.mark.asyncio
    async def test_blacklist_different_tokens(self):
        """Test blacklisting multiple different tokens"""
        jtis = [str(uuid4()) for _ in range(5)]

        for jti in jtis:
            await add_to_blacklist(jti, 3600)

        for jti in jtis:
            is_blocked = await is_blacklisted(jti)
            assert is_blocked is False


class TestTokenExpiry:
    """Test token expiry handling"""

    def test_token_expires_after_set_time(self):
        """Test that token expires after configured time"""
        import time

        user_id = uuid4()
        expires = timedelta(seconds=2)  # Expire in 2 seconds

        token = create_token(user_id, TokenType.ACCESS, expires_delta=expires)

        # Should be valid immediately
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload is not None

        # Wait for expiry
        time.sleep(3)

        # Should be expired now
        with pytest.raises(JWTError):
            jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

    def test_token_exp_claim_format(self):
        """Test that exp claim is in correct format"""
        user_id = uuid4()
        token = create_token(user_id, TokenType.ACCESS)

        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        # exp should be a timestamp
        assert isinstance(payload["exp"], int)
        assert payload["exp"] > 0

    def test_refresh_token_longer_expiry(self):
        """Test that refresh tokens have longer expiry than access tokens"""
        user_id = uuid4()

        access_token = create_token(user_id, TokenType.ACCESS)
        refresh_token = create_token(user_id, TokenType.REFRESH)

        access_payload = jwt.decode(
            access_token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        refresh_payload = jwt.decode(
            refresh_token,
            settings.JWT_REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        # Refresh token should expire later
        assert refresh_payload["exp"] > access_payload["exp"]

    def test_token_iat_claim(self):
        """Test that iat (issued at) claim is set"""
        user_id = uuid4()
        token = create_token(user_id, TokenType.ACCESS)

        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert "iat" in payload
        assert isinstance(payload["iat"], int)


class TestTokenPayload:
    """Test token payload structure"""

    def test_token_contains_required_claims(self):
        """Test that token contains all required claims"""
        user_id = uuid4()

        token = create_token(user_id, TokenType.ACCESS)
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        # Required claims
        assert "sub" in payload
        assert "exp" in payload
        assert "jti" in payload
        assert "type" in payload
        assert "iat" in payload

    def test_token_sub_claim_format(self):
        """Test that sub claim is properly formatted"""
        user_id = uuid4()

        token = create_token(user_id, TokenType.ACCESS)
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        # Should be a string representation of UUID
        assert isinstance(payload["sub"], str)
        # Should be valid UUID format
        parsed_uuid = UUID(payload["sub"])
        assert parsed_uuid == user_id

    def test_token_type_claim(self):
        """Test that type claim is correct"""
        user_id = uuid4()

        access_token = create_token(user_id, TokenType.ACCESS)
        access_payload = jwt.decode(access_token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert access_payload["type"] == TokenType.ACCESS.value

        refresh_token = create_token(user_id, TokenType.REFRESH)
        refresh_payload = jwt.decode(refresh_token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert refresh_payload["type"] == TokenType.REFRESH.value


class TestTokenRefresh:
    """Test token refresh functionality"""

    def test_refresh_token_can_be_verified(self):
        """Test that refresh tokens can be verified"""
        user_id = uuid4()
        refresh_token = create_token(user_id, TokenType.REFRESH)

        # Should be verifiable with refresh secret
        payload = jwt.decode(
            refresh_token,
            settings.JWT_REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        assert payload["sub"] == str(user_id)

    def test_access_token_cannot_use_refresh_secret(self):
        """Test that access tokens fail with wrong secret"""
        user_id = uuid4()
        access_token = create_token(user_id, TokenType.ACCESS)

        # Should fail with refresh secret
        with pytest.raises(JWTError):
            jwt.decode(
                access_token,
                settings.JWT_REFRESH_SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )

    def test_refresh_token_cannot_use_access_secret(self):
        """Test that refresh tokens fail with wrong secret"""
        user_id = uuid4()
        refresh_token = create_token(user_id, TokenType.REFRESH)

        # Should fail with access secret
        with pytest.raises(JWTError):
            jwt.decode(
                refresh_token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
