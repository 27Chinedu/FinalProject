# tests/unit/test_boundary_conditions.py

import pytest
from uuid import uuid4
from datetime import datetime, timezone
from app.models.user import User
from app.models.calculation import Calculation


class TestNumericBoundaries:
    """Test numeric boundary conditions"""

    def test_zero_in_addition(self, db_session, fake_user_data):
        """Test addition with zeros"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("addition", user.id, [0, 0])
        calc.result = calc.get_result()

        assert calc.result == 0

    def test_zero_in_multiplication(self, db_session, fake_user_data):
        """Test multiplication with zero"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("multiplication", user.id, [100, 0, 50])
        calc.result = calc.get_result()

        assert calc.result == 0

    def test_negative_numbers_addition(self, db_session, fake_user_data):
        """Test addition with negative numbers"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("addition", user.id, [-5, -10, 3])
        calc.result = calc.get_result()

        assert calc.result == -12

    def test_negative_numbers_multiplication(self, db_session, fake_user_data):
        """Test multiplication with negative numbers"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("multiplication", user.id, [-2, -3])
        calc.result = calc.get_result()

        assert calc.result == 6

    def test_very_small_decimal(self, db_session, fake_user_data):
        """Test calculations with very small decimals"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("addition", user.id, [0.0001, 0.0002, 0.0003])
        calc.result = calc.get_result()

        assert abs(calc.result - 0.0006) < 0.000001

    def test_large_number_addition(self, db_session, fake_user_data):
        """Test addition with very large numbers"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        large_nums = [1000000, 2000000, 3000000]
        calc = Calculation.create("addition", user.id, large_nums)
        calc.result = calc.get_result()

        assert calc.result == 6000000

    def test_mixed_positive_negative(self, db_session, fake_user_data):
        """Test operations with mixed positive and negative"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("addition", user.id, [100, -50, 25, -75])
        calc.result = calc.get_result()

        assert calc.result == 0

    def test_division_resulting_in_fraction(self, db_session, fake_user_data):
        """Test division resulting in fraction"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("division", user.id, [7, 2])
        calc.result = calc.get_result()

        assert calc.result == 3.5

    def test_subtraction_to_zero(self, db_session, fake_user_data):
        """Test subtraction resulting in zero"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("subtraction", user.id, [100, 50, 50])
        calc.result = calc.get_result()

        assert calc.result == 0

    def test_many_decimal_places(self, db_session, fake_user_data):
        """Test numbers with many decimal places"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("addition", user.id, [1.123456789, 2.987654321])
        calc.result = calc.get_result()

        expected = 1.123456789 + 2.987654321
        assert abs(calc.result - expected) < 0.000000001


class TestStringBoundaries:
    """Test string boundary conditions"""

    def test_minimum_length_name(self, db_session):
        """Test single character names"""
        user_data = {
            "first_name": "A",
            "last_name": "B",
            "email": f"test_{uuid4()}@example.com",
            "username": f"u_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.first_name == "A"
        assert user.last_name == "B"

    def test_long_names(self, db_session):
        """Test very long names - should fail with database constraint"""
        from sqlalchemy.exc import DataError

        long_name = "A" * 100

        user_data = {
            "first_name": long_name,
            "last_name": long_name,
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)

        # Should fail due to VARCHAR(50) constraint
        with pytest.raises(DataError):
            db_session.commit()

        db_session.rollback()

    def test_maximum_length_names(self, db_session):
        """Test names at maximum allowed length (50 chars)"""
        max_length_name = "A" * 50

        user_data = {
            "first_name": max_length_name,
            "last_name": max_length_name,
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert len(user.first_name) == 50
        assert len(user.last_name) == 50

    def test_special_characters_in_name(self, db_session):
        """Test special characters in names"""
        user_data = {
            "first_name": "O'Brien",
            "last_name": "Smith-Jones",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.first_name == "O'Brien"
        assert user.last_name == "Smith-Jones"

    def test_unicode_names(self, db_session):
        """Test Unicode characters in names"""
        user_data = {
            "first_name": "François",
            "last_name": "Müller",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.first_name == "François"
        assert user.last_name == "Müller"

    def test_cyrillic_characters(self, db_session):
        """Test Cyrillic characters"""
        user_data = {
            "first_name": "Иван",
            "last_name": "Петров",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.first_name == "Иван"

    def test_chinese_characters(self, db_session):
        """Test Chinese characters"""
        user_data = {
            "first_name": "李",
            "last_name": "明",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.first_name == "李"

    def test_arabic_characters(self, db_session):
        """Test Arabic characters"""
        user_data = {
            "first_name": "محمد",
            "last_name": "علي",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.first_name == "محمد"

    def test_spaces_in_names(self, db_session):
        """Test handling of spaces in names"""
        user_data = {
            "first_name": "Mary Jane",
            "last_name": "Van Der Berg",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.first_name == "Mary Jane"
        assert user.last_name == "Van Der Berg"

    def test_numbers_in_names(self, db_session):
        """Test numbers in names"""
        user_data = {
            "first_name": "User123",
            "last_name": "Test456",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.first_name == "User123"


class TestEmailBoundaries:
    """Test email boundary conditions"""

    def test_short_email(self, db_session):
        """Test shortest valid email"""
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "a@b.c",
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.email == "a@b.c"

    def test_long_email(self, db_session):
        """Test very long email"""
        long_local = "a" * 50
        long_domain = "b" * 50
        email = f"{long_local}@{long_domain}.com"

        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": email,
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.email == email

    def test_email_with_plus(self, db_session):
        """Test email with plus sign"""
        email = f"user+tag_{uuid4()}@example.com"

        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": email,
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.email == email

    def test_email_with_dots(self, db_session):
        """Test email with dots in local part"""
        email = f"first.last.name_{uuid4()}@example.com"

        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": email,
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.email == email

    def test_email_with_subdomain(self, db_session):
        """Test email with subdomain"""
        email = f"user_{uuid4()}@mail.example.com"

        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": email,
            "username": f"user_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.email == email


class TestPasswordBoundaries:
    """Test password boundary conditions"""

    def test_minimum_valid_password(self, db_session):
        """Test minimum length valid password"""
        # Exactly 8 characters with all requirements
        password = "Test123!"

        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": password
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.verify_password(password)

    def test_very_long_password(self, db_session):
        """Test very long password"""
        # 100 character password
        password = "A1b!" * 25  # 100 chars

        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": password
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.verify_password(password)

    def test_password_with_all_special_chars(self, db_session):
        """Test password with many special characters"""
        password = "Test123!@#$%^&*()"

        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": password
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.verify_password(password)

    def test_password_with_spaces(self, db_session):
        """Test password with spaces"""
        password = "Test 123 Pass!"

        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"user_{uuid4()}",
            "password": password
        }

        user = User.register(db_session, user_data)
        db_session.commit()

        assert user.verify_password(password)


class TestCalculationInputBoundaries:
    """Test calculation input boundary conditions"""

    def test_minimum_inputs(self, db_session, fake_user_data):
        """Test calculation with exactly 2 inputs (minimum)"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("addition", user.id, [1, 2])
        calc.result = calc.get_result()

        assert calc.result == 3

    def test_many_inputs(self, db_session, fake_user_data):
        """Test calculation with many inputs"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        inputs = list(range(1, 101))  # 100 inputs
        calc = Calculation.create("addition", user.id, inputs)
        calc.result = calc.get_result()

        assert calc.result == sum(inputs)

    def test_all_same_inputs(self, db_session, fake_user_data):
        """Test calculation with all identical inputs"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("multiplication", user.id, [5, 5, 5])
        calc.result = calc.get_result()

        assert calc.result == 125

    def test_alternating_large_small(self, db_session, fake_user_data):
        """Test calculation with alternating large and small numbers"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        calc = Calculation.create("addition", user.id, [1000000, 1, 1000000, 1])
        calc.result = calc.get_result()

        assert calc.result == 2000002


class TestTimestampBoundaries:
    """Test timestamp handling"""

    def test_created_at_set_on_creation(self, db_session, fake_user_data):
        """Test that created_at is set on user creation"""
        fake_user_data['password'] = "TestPass123!"

        before = datetime.now(timezone.utc)
        user = User.register(db_session, fake_user_data)
        db_session.commit()
        after = datetime.now(timezone.utc)

        assert before <= user.created_at <= after

    def test_updated_at_changes_on_update(self, db_session, fake_user_data):
        """Test that updated_at changes on update"""
        import time

        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        original_updated = user.updated_at

        time.sleep(0.1)

        # Update user
        user.first_name = "Updated"
        user.updated_at = datetime.now(timezone.utc)
        db_session.commit()

        assert user.updated_at > original_updated

    def test_last_login_null_initially(self, db_session, fake_user_data):
        """Test that last_login is null for new users"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        assert user.last_login is None

    def test_last_login_set_on_authentication(self, db_session, fake_user_data):
        """Test that last_login is set on authentication"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Authenticate
        result = User.authenticate(db_session, user.username, "TestPass123!")
        db_session.commit()

        db_session.refresh(user)
        assert user.last_login is not None
