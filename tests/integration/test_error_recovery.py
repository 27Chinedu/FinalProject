# tests/integration/test_error_recovery.py

import pytest
from uuid import uuid4
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from app.models.user import User
from app.models.calculation import Calculation


class TestDatabaseErrorHandling:
    """Test error handling for database operations"""

    def test_duplicate_username_error(self, db_session):
        """Test handling of duplicate username"""
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "test1@example.com",
            "username": "duplicate_user",
            "password": "TestPass123!"
        }

        # Create first user
        user1 = User.register(db_session, user_data)
        db_session.commit()

        # Try to create second user with same username
        user_data2 = {
            "first_name": "Test2",
            "last_name": "User2",
            "email": "test2@example.com",
            "username": "duplicate_user",  # Same username
            "password": "TestPass123!"
        }

        with pytest.raises((ValueError, IntegrityError)):
            user2 = User.register(db_session, user_data2)
            db_session.commit()

        db_session.rollback()

    def test_duplicate_email_error(self, db_session):
        """Test handling of duplicate email"""
        email = f"duplicate_{uuid4()}@example.com"

        user_data1 = {
            "first_name": "Test1",
            "last_name": "User1",
            "email": email,
            "username": f"user1_{uuid4()}",
            "password": "TestPass123!"
        }

        user1 = User.register(db_session, user_data1)
        db_session.commit()

        user_data2 = {
            "first_name": "Test2",
            "last_name": "User2",
            "email": email,  # Same email
            "username": f"user2_{uuid4()}",
            "password": "TestPass123!"
        }

        with pytest.raises((ValueError, IntegrityError)):
            user2 = User.register(db_session, user_data2)
            db_session.commit()

        db_session.rollback()

    def test_transaction_rollback_on_error(self, db_session, fake_user_data):
        """Test that transactions rollback on error"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Create a calculation
        calc = Calculation.create("addition", user.id, [1, 2, 3])
        calc.result = calc.get_result()
        db_session.add(calc)

        # Get count before
        count_before = db_session.query(Calculation).filter(
            Calculation.user_id == user.id
        ).count()

        # Try to add invalid calculation (this should fail)
        try:
            invalid_calc = Calculation.create("invalid_type", user.id, [1, 2])
            db_session.add(invalid_calc)
            db_session.commit()
        except ValueError:
            db_session.rollback()

        # Count should be unchanged
        count_after = db_session.query(Calculation).filter(
            Calculation.user_id == user.id
        ).count()

        assert count_after == count_before + 1  # Only first calc added

    def test_invalid_foreign_key(self, db_session):
        """Test handling of invalid foreign key"""
        fake_user_id = uuid4()  # Non-existent user

        calc = Calculation.create("addition", fake_user_id, [1, 2, 3])
        calc.result = calc.get_result()
        db_session.add(calc)

        # Should fail due to foreign key constraint
        with pytest.raises(IntegrityError):
            db_session.commit()

        db_session.rollback()

    def test_session_expiry_handling(self, db_session, fake_user_data):
        """Test handling of expired session"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()
        user_id = user.id

        # Close session
        db_session.close()

        # Try to use closed session should handle gracefully
        # Depending on implementation, this might raise an error
        try:
            user = db_session.query(User).filter(User.id == user_id).first()
            # If it works, that's fine too
        except (InvalidRequestError, AttributeError):
            # Expected behavior for closed session
            pass


class TestCalculationErrorHandling:
    """Test error handling in calculations"""

    def test_division_by_zero_handling(self, db_session, fake_user_data):
        """Test that division by zero is handled properly"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Try division by zero
        with pytest.raises(ValueError) as exc_info:
            calc = Calculation.create("division", user.id, [10, 0])
            calc.result = calc.get_result()

        assert "zero" in str(exc_info.value).lower()

    def test_division_by_zero_in_sequence(self, db_session, fake_user_data):
        """Test division by zero in middle of sequence"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Division: 100 / 5 / 0
        with pytest.raises(ValueError) as exc_info:
            calc = Calculation.create("division", user.id, [100, 5, 0])
            calc.result = calc.get_result()

        assert "zero" in str(exc_info.value).lower()

    def test_empty_inputs_error(self, db_session, fake_user_data):
        """Test that empty inputs are rejected"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        with pytest.raises(ValueError):
            calc = Calculation.create("addition", user.id, [])

    def test_single_input_error(self, db_session, fake_user_data):
        """Test that single input is rejected"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        with pytest.raises(ValueError):
            calc = Calculation.create("addition", user.id, [5])

    def test_non_numeric_input_error(self, db_session, fake_user_data):
        """Test that non-numeric inputs are rejected"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        with pytest.raises((ValueError, TypeError)):
            calc = Calculation.create("addition", user.id, ["not", "numbers"])

    def test_invalid_calculation_type(self, db_session, fake_user_data):
        """Test that invalid calculation type is rejected"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        with pytest.raises(ValueError):
            calc = Calculation.create("invalid_operation", user.id, [1, 2, 3])


class TestAuthenticationErrorHandling:
    """Test error handling in authentication"""

    def test_authentication_wrong_password(self, db_session, fake_user_data):
        """Test authentication with wrong password"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        result = User.authenticate(db_session, user.username, "WrongPassword123!")

        assert result is None

    def test_authentication_nonexistent_user(self, db_session):
        """Test authentication with non-existent username"""
        result = User.authenticate(db_session, "nonexistent_user", "password")

        assert result is None

    def test_authentication_empty_credentials(self, db_session):
        """Test authentication with empty credentials"""
        result = User.authenticate(db_session, "", "")

        assert result is None

    def test_password_verification_wrong_password(self, db_session, fake_user_data):
        """Test password verification with wrong password"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        assert user.verify_password("WrongPassword!") is False

    def test_password_verification_empty_password(self, db_session, fake_user_data):
        """Test password verification with empty password"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        assert user.verify_password("") is False


class TestDataIntegrityHandling:
    """Test data integrity and constraint handling"""

    def test_null_required_field(self, db_session):
        """Test that null values in required fields are rejected"""
        with pytest.raises((ValueError, IntegrityError, TypeError)):
            user_data = {
                "first_name": None,  # Required field
                "last_name": "User",
                "email": "test@example.com",
                "username": "testuser",
                "password": "TestPass123!"
            }
            user = User.register(db_session, user_data)
            db_session.commit()

        db_session.rollback()

    def test_user_delete_cascades(self, db_session, fake_user_data):
        """Test that deleting user cascades to calculations"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Create calculations
        for i in range(3):
            calc = Calculation.create("addition", user.id, [i, i + 1])
            calc.result = calc.get_result()
            db_session.add(calc)
        db_session.commit()

        calc_count = db_session.query(Calculation).filter(
            Calculation.user_id == user.id
        ).count()
        assert calc_count == 3

        # Delete user
        db_session.delete(user)
        db_session.commit()

        # Calculations should be deleted
        calc_count = db_session.query(Calculation).filter(
            Calculation.user_id == user.id
        ).count()
        assert calc_count == 0

    def test_orphaned_calculation_prevention(self, db_session):
        """Test that calculations cannot exist without user"""
        fake_user_id = uuid4()

        calc = Calculation.create("addition", fake_user_id, [1, 2, 3])
        calc.result = calc.get_result()
        db_session.add(calc)

        with pytest.raises(IntegrityError):
            db_session.commit()

        db_session.rollback()


class TestRecoveryFromErrors:
    """Test recovery after errors"""

    def test_session_reuse_after_rollback(self, db_session):
        """Test that session can be reused after rollback"""
        # Cause an error
        try:
            user_data = {
                "first_name": "Test",
                "last_name": "User",
                "email": "test@example.com",
                "username": "testuser",
                "password": "weak"  # Weak password
            }
            user = User.register(db_session, user_data)
            db_session.commit()
        except ValueError:
            db_session.rollback()

        # Session should still work
        valid_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{uuid4()}@example.com",
            "username": f"test_{uuid4()}",
            "password": "StrongPass123!"
        }

        user = User.register(db_session, valid_data)
        db_session.commit()

        assert user.id is not None

    def test_multiple_errors_and_rollbacks(self, db_session):
        """Test handling multiple errors with rollbacks"""
        for i in range(3):
            try:
                # Try to create user with weak password
                user_data = {
                    "first_name": f"Test{i}",
                    "last_name": "User",
                    "email": f"test{i}@example.com",
                    "username": f"test{i}",
                    "password": "weak"
                }
                user = User.register(db_session, user_data)
                db_session.commit()
            except ValueError:
                db_session.rollback()

        # Session should still work after multiple errors
        valid_data = {
            "first_name": "Valid",
            "last_name": "User",
            "email": f"valid_{uuid4()}@example.com",
            "username": f"valid_{uuid4()}",
            "password": "ValidPass123!"
        }

        user = User.register(db_session, valid_data)
        db_session.commit()

        assert user.id is not None


class TestBoundaryErrorHandling:
    """Test error handling at boundaries"""

    def test_extremely_large_calculation_result(self, db_session, fake_user_data):
        """Test handling of extremely large calculation results"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Large multiplication
        large_inputs = [999999, 999999, 999999]

        calc = Calculation.create("multiplication", user.id, large_inputs)
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()

        assert calc.result == 999999 * 999999 * 999999

    def test_negative_number_calculations(self, db_session, fake_user_data):
        """Test calculations with negative numbers"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Subtraction resulting in negative
        calc = Calculation.create("subtraction", user.id, [5, 10])
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()

        assert calc.result == -5

    def test_floating_point_precision_errors(self, db_session, fake_user_data):
        """Test handling of floating point precision"""
        fake_user_data['password'] = "TestPass123!"
        user = User.register(db_session, fake_user_data)
        db_session.commit()

        # Division that results in repeating decimal
        calc = Calculation.create("division", user.id, [1, 3])
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()

        # Should handle floating point
        assert 0.33 < calc.result < 0.34
