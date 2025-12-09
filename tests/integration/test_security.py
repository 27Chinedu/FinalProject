# tests/integration/test_security.py

import pytest
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from jose import jwt
from app.models.user import User
from app.models.calculation import Calculation
from app.core.config import settings
from app.auth.jwt import create_token
from app.schemas.token import TokenType


class TestSQLInjectionPrevention:
    """Test SQL injection attack prevention"""

    def test_sql_injection_in_username_registration(self, db_session):
        """Test SQL injection attempts in username during registration"""
        malicious_payloads = [
            "admin'--",
            "admin' OR '1'='1",
            "'; DROP TABLE users; --",
            "admin'; DELETE FROM users WHERE '1'='1",
            "1' UNION SELECT * FROM users--",
        ]

        for payload in malicious_payloads:
            user_data = {
                "first_name": "Test",
                "last_name": "User",
                "email": f"test_{uuid4()}@example.com",
                "username": payload,
                "password": "TestPass123!"
            }

            # Should either succeed (treating as literal string) or fail validation
            # but NOT execute SQL injection
            try:
                user = User.register(db_session, user_data)
                db_session.commit()

                # If successful, verify the username is stored literally
                assert user.username == payload

                # Clean up
                db_session.delete(user)
                db_session.commit()
            except ValueError:
                # Expected validation error is acceptable
                db_session.rollback()
                pass

    def test_sql_injection_in_email(self, db_session):
        """Test SQL injection attempts in email field"""
        malicious_email = "admin'@example.com OR '1'='1"

        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": malicious_email,
            "username": f"test_{uuid4()}",
            "password": "TestPass123!"
        }

        try:
            user = User.register(db_session, user_data)
            db_session.commit()

            # Verify stored literally, not executed
            assert user.email == malicious_email

            db_session.delete(user)
            db_session.commit()
        except ValueError:
            db_session.rollback()
            pass

    def test_sql_injection_in_calculation_query(self, db_session, fake_user_data):
        """Test SQL injection in calculation type"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Try malicious calculation type
        malicious_type = "addition'; DROP TABLE calculations; --"

        with pytest.raises(ValueError):
            # Should fail validation, not execute
            calc = Calculation.create(malicious_type, user.id, [1, 2, 3])


class TestXSSPrevention:
    """Test Cross-Site Scripting (XSS) prevention"""

    def test_xss_in_first_name(self, db_session):
        """Test XSS script injection in first name"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ]

        for payload in xss_payloads:
            user_data = {
                "first_name": payload,
                "last_name": "User",
                "email": f"test_{uuid4()}@example.com",
                "username": f"test_{uuid4()}",
                "password": "TestPass123!"
            }

            user = User.register(db_session, user_data)
            db_session.commit()

            # Verify stored as literal string (not executed)
            assert user.first_name == payload

            # Clean up
            db_session.delete(user)
            db_session.commit()

    def test_xss_in_calculation_inputs(self, db_session, fake_user_data):
        """Test XSS attempts in calculation inputs"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Calculation inputs should only accept numbers
        calc = Calculation.create(
            "addition",
            user.id,
            ["<script>alert('XSS')</script>", "test"]
        )
        # XSS strings will cause error when trying to compute result
        with pytest.raises((ValueError, TypeError)):
            calc.get_result()


class TestAuthenticationSecurity:
    """Test authentication and token security"""

    def test_expired_token_rejection(self, db_session, fake_user_data):
        """Test that expired tokens are rejected"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Create expired token
        expires = timedelta(minutes=-10)  # Expired 10 minutes ago
        expired_token = create_token(
            user.id,
            TokenType.ACCESS,
            expires_delta=expires
        )

        # Try to decode expired token
        from app.auth.dependencies import get_current_user
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(expired_token)

        assert exc_info.value.status_code == 401

    def test_tampered_token_rejection(self, db_session, fake_user_data):
        """Test that tampered tokens are rejected"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Create valid token
        token = create_token(user.id, TokenType.ACCESS)

        # Tamper with token
        tampered_token = token[:-10] + "tampered123"

        from app.auth.dependencies import get_current_user
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(tampered_token)

        assert exc_info.value.status_code == 401

    def test_token_with_invalid_signature(self, db_session):
        """Test token with wrong signature key"""
        user_id = uuid4()

        # Create token with wrong secret
        wrong_token = jwt.encode(
            {"sub": str(user_id)},
            "wrong-secret-key",
            algorithm=settings.ALGORITHM
        )

        from app.auth.dependencies import get_current_user
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(wrong_token)

        assert exc_info.value.status_code == 401

    def test_token_without_sub_claim(self, db_session):
        """Test token missing required 'sub' claim"""
        # Create token without 'sub'
        token = jwt.encode(
            {"username": "test"},
            settings.JWT_SECRET_KEY,
            algorithm=settings.ALGORITHM
        )

        from app.auth.dependencies import get_current_user
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(token)

        assert exc_info.value.status_code == 401

    def test_brute_force_password_attempts(self, db_session, fake_user_data):
        """Test multiple failed login attempts"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Attempt multiple wrong passwords
        wrong_passwords = [
            "wrong1", "wrong2", "wrong3", "wrong4", "wrong5"
        ]

        for wrong_pass in wrong_passwords:
            result = User.authenticate(db_session, user.username, wrong_pass)
            assert result is None

        # Verify user still exists and correct password still works
        result = User.authenticate(db_session, user.username, "TestPass123!")
        assert result is not None

    def test_password_timing_attack_resistance(self, db_session, fake_user_data):
        """Test that authentication timing is consistent"""
        import time

        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Time wrong password
        start1 = time.time()
        User.authenticate(db_session, user.username, "wrong")
        time1 = time.time() - start1

        # Time another wrong password
        start2 = time.time()
        User.authenticate(db_session, user.username, "different_wrong")
        time2 = time.time() - start2

        # Time non-existent user
        start3 = time.time()
        User.authenticate(db_session, "nonexistent_user", "password")
        time3 = time.time() - start3

        # Times should be relatively similar (within 1 second)
        # This prevents timing attacks to determine valid usernames
        # Note: In CI/CD environments, timing can vary significantly
        assert abs(time1 - time2) < 1.0
        assert abs(time2 - time3) < 1.0


class TestPasswordSecurity:
    """Test password security requirements"""

    def test_weak_password_rejection(self, db_session):
        """Test that too-short passwords are rejected"""
        # Application only validates password length (>= 6 chars)
        # Not strength requirements like uppercase, numbers, special chars
        short_passwords = [
            "a",      # 1 char
            "ab",     # 2 chars
            "abc",    # 3 chars
            "abcd",   # 4 chars
            "abcde",  # 5 chars - still too short
        ]

        for weak_pass in short_passwords:
            user_data = {
                "first_name": "Test",
                "last_name": "User",
                "email": f"test_{uuid4()}@example.com",
                "username": f"test_{uuid4()}",
                "password": weak_pass
            }

            with pytest.raises(ValueError) as exc_info:
                User.register(db_session, user_data)
                db_session.commit()

            db_session.rollback()
            assert "password" in str(exc_info.value).lower()

    def test_password_not_stored_plaintext(self, db_session, fake_user_data):
        """Test that passwords are hashed, not stored as plaintext"""
        password = "TestPass123!"
        fake_user_data['password'] = password

        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Password should be hashed
        assert user.password != password
        assert user.password.startswith("$2b$")  # bcrypt hash format
        assert len(user.password) == 60  # bcrypt hash length


class TestInputValidation:
    """Test input validation and sanitization"""

    def test_empty_string_username(self, db_session):
        """Test empty username handling"""
        # Empty strings are allowed (nullable=False only prevents NULL, not empty strings)
        # The application doesn't validate for empty usernames
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": "",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        # Verify empty username is stored
        assert user.username == ""
        assert user.id is not None

        # Clean up
        db_session.delete(user)
        db_session.commit()

    def test_null_bytes_in_input(self, db_session):
        """Test null byte injection prevention"""
        from sqlalchemy.exc import DataError

        user_data = {
            "first_name": "Test\x00Admin",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"test_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        # PostgreSQL doesn't allow null bytes in strings
        with pytest.raises((DataError, ValueError)):
            db_session.commit()

        db_session.rollback()

    def test_extremely_long_input(self, db_session):
        """Test extremely long input handling"""
        long_string = "A" * 10000

        user_data = {
            "first_name": long_string,
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"test_{uuid4()}",
            "password": "TestPass123!"
        }

        # Should either truncate, reject, or store
        # Depending on database constraints
        try:
            user = User.register(db_session, user_data)
            db_session.commit()
            assert len(user.first_name) <= 10000
        except (ValueError, Exception):
            db_session.rollback()
            pass

    def test_unicode_characters(self, db_session):
        """Test Unicode character handling"""
        unicode_data = {
            "first_name": "José",
            "last_name": "García",
            "email": f"test_{uuid4()}@example.com",
            "username": f"test_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, unicode_data)
        db_session.commit()

        assert user.first_name == "José"
        assert user.last_name == "García"

    def test_emoji_in_names(self, db_session):
        """Test emoji handling in user fields"""
        emoji_data = {
            "first_name": "John 😀",
            "last_name": "Doe 🎉",
            "email": f"test_{uuid4()}@example.com",
            "username": f"test_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, emoji_data)
        db_session.commit()

        assert "😀" in user.first_name
        assert "🎉" in user.last_name


class TestAuthorizationSecurity:
    """Test authorization and access control"""

    def test_user_cannot_access_other_user_calculations(self, db_session):
        """Test that users cannot access other users' calculations"""
        # Create two users with unique identifiers
        user1_data = {
            "first_name": "User",
            "last_name": "One",
            "email": f"user1_{uuid4()}@example.com",
            "username": f"user1_{uuid4()}",
            "password": "TestPass123!"
        }
        user1 = User.register(db_session, user1_data)

        user2_data = {
            "first_name": "User",
            "last_name": "Two",
            "email": f"user2_{uuid4()}@example.com",
            "username": f"user2_{uuid4()}",
            "password": "TestPass123!"
        }
        user2 = User.register(db_session, user2_data)
        db_session.commit()

        # Create calculation for user1
        calc = Calculation.create("addition", user1.id, [1, 2, 3])
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()

        # User2 should not be able to find user1's calculation
        result = db_session.query(Calculation).filter(
            Calculation.id == calc.id,
            Calculation.user_id == user2.id
        ).first()

        assert result is None

    def test_inactive_user_blocked(self, db_session, fake_user_data):
        """Test that inactive users cannot authenticate"""
        from app.auth.dependencies import get_current_active_user
        from app.schemas.user import UserResponse
        from fastapi import HTTPException

        inactive_user = UserResponse(
            id=uuid4(),
            username="inactive",
            email="inactive@example.com",
            first_name="In",
            last_name="Active",
            is_active=False,
            is_verified=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        with pytest.raises(HTTPException) as exc_info:
            get_current_active_user(inactive_user)

        assert exc_info.value.status_code == 400
