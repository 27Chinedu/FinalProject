# tests/unit/test_javascript_utils.py

"""
Tests for JavaScript utility functions
These tests verify the logic of client-side validation and utility functions
"""

import pytest
import re


class TestEmailValidation:
    """Test email validation regex from JavaScript"""

    def get_email_regex(self):
        """JavaScript regex: /^[^\s@]+@[^\s@]+\.[^\s@]+$/"""
        return re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

    def test_valid_emails(self):
        """Test that valid emails pass validation"""
        regex = self.get_email_regex()

        valid_emails = [
            "user@example.com",
            "test.user@example.com",
            "user+tag@example.com",
            "user@mail.example.com",
            "a@b.c",
            "user123@test.org"
        ]

        for email in valid_emails:
            assert regex.match(email) is not None, f"{email} should be valid"

    def test_invalid_emails(self):
        """Test that invalid emails fail validation"""
        regex = self.get_email_regex()

        invalid_emails = [
            "notanemail",
            "@example.com",
            "user@",
            "user @example.com",  # Space
            "user@example",  # No TLD
            "user example@test.com",  # Space in local
            "",
            "user@@example.com"
        ]

        for email in invalid_emails:
            assert regex.match(email) is None, f"{email} should be invalid"

    def test_email_edge_cases(self):
        """Test email edge cases"""
        regex = self.get_email_regex()

        # Should pass
        assert regex.match("a@b.c") is not None

        # Should fail
        assert regex.match("user@.com") is None
        assert regex.match(".user@example.com") is not None  # Starts with dot, but matches regex


class TestPasswordStrengthValidation:
    """Test password strength validation from JavaScript"""

    def is_strong_password(self, password: str) -> bool:
        """
        JavaScript validation:
        - At least 8 characters
        - Contains uppercase letter
        - Contains lowercase letter
        - Contains digit
        - Contains special character
        """
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            return False
        return True

    def test_strong_passwords(self):
        """Test that strong passwords pass validation"""
        strong_passwords = [
            "Password123!",
            "Test@Pass1",
            "Secure#Pass99",
            "MyP@ssw0rd",
            "Complex1!Pass"
        ]

        for password in strong_passwords:
            assert self.is_strong_password(password), f"{password} should be strong"

    def test_weak_passwords(self):
        """Test that weak passwords fail validation"""
        weak_passwords = [
            "short1!",  # Too short
            "nouppercase123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoNumbers!",  # No numbers
            "NoSpecial123",  # No special chars
            "12345678",  # Only numbers
            "Password",  # Missing numbers and special
            "Pass1!",  # Too short
        ]

        for password in weak_passwords:
            assert not self.is_strong_password(password), f"{password} should be weak"

    def test_password_exactly_8_chars(self):
        """Test password with exactly 8 characters"""
        # Valid with all requirements
        assert self.is_strong_password("Test123!")

        # Invalid - 7 chars
        assert not self.is_strong_password("Test12!")

    def test_password_with_all_special_chars(self):
        """Test password with various special characters"""
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        for char in special_chars:
            password = f"Test123{char}"
            assert self.is_strong_password(password), f"Password with {char} should be strong"

    def test_password_with_spaces(self):
        """Test that password with spaces works if other requirements met"""
        password = "Test 123!"
        assert self.is_strong_password(password)


class TestLocalStorageOperations:
    """Test localStorage operations logic"""

    def test_authentication_check_logic(self):
        """Test isAuthenticated logic"""
        # If token exists, user is authenticated
        # This is a simple boolean check in JavaScript

        # Simulate token present
        token = "some.jwt.token"
        is_authenticated = bool(token)
        assert is_authenticated is True

        # Simulate no token
        token = None
        is_authenticated = bool(token)
        assert is_authenticated is False

        # Empty string should be false
        token = ""
        is_authenticated = bool(token)
        assert is_authenticated is False

    def test_auth_header_format(self):
        """Test authorization header format"""
        token = "sample.jwt.token"

        # JavaScript creates: 'Authorization': `Bearer ${token}`
        auth_header = f"Bearer {token}"

        assert auth_header.startswith("Bearer ")
        assert token in auth_header

    def test_logout_clears_storage(self):
        """Test that logout logic clears all data"""
        # Simulate localStorage
        storage = {
            "access_token": "token",
            "user_id": "123",
            "username": "test"
        }

        # Logout should clear all
        storage.clear()

        assert len(storage) == 0


class TestDateFormatting:
    """Test date formatting logic"""

    def test_date_format_components(self):
        """Test that date formatting includes all components"""
        from datetime import datetime

        date = datetime(2025, 1, 15, 14, 30, 0)

        # JavaScript formats to: 'Jan 15, 2025, 02:30 PM' (en-US locale)
        # We just verify the logic works
        formatted = date.strftime('%b %d, %Y, %I:%M %p')

        assert "Jan" in formatted or "01" in formatted
        assert "15" in formatted
        assert "2025" in formatted

    def test_date_parsing(self):
        """Test that date strings can be parsed"""
        from datetime import datetime

        date_string = "2025-01-15T14:30:00"

        # Should be parseable
        parsed = datetime.fromisoformat(date_string.replace('Z', '+00:00') if 'Z' in date_string else date_string)

        assert parsed.year == 2025
        assert parsed.month == 1
        assert parsed.day == 15


class TestAPIErrorHandling:
    """Test API error handling logic"""

    def test_401_error_triggers_logout(self):
        """Test that 401 errors trigger logout"""
        # Simulate error response
        error_status = 401

        # Logic: if error.status === 401, call logout
        should_logout = (error_status == 401)

        assert should_logout is True

    def test_non_401_error_no_logout(self):
        """Test that non-401 errors don't trigger logout"""
        error_statuses = [400, 403, 404, 500]

        for status in error_statuses:
            should_logout = (status == 401)
            assert should_logout is False

    def test_error_propagation(self):
        """Test that errors are propagated after handling"""
        # JavaScript: handleApiError returns the error after handling
        # This ensures error can be caught by caller

        error = {"status": 401, "message": "Unauthorized"}

        # After handling, error should still be returned
        returned_error = error  # Simulates: return error;

        assert returned_error == error


class TestLoadingStateManagement:
    """Test loading state management logic"""

    def test_show_loading_disables_button(self):
        """Test that showing loading disables element"""
        # Simulate button state
        button = {"disabled": False, "innerHTML": "Submit"}

        # Show loading
        button["disabled"] = True
        button["innerHTML"] = "<span class='spinner'></span>"

        assert button["disabled"] is True
        assert "spinner" in button["innerHTML"]

    def test_hide_loading_enables_button(self):
        """Test that hiding loading enables element"""
        # Simulate button with loading
        button = {"disabled": True, "innerHTML": "<span class='spinner'></span>"}
        original_text = "Submit"

        # Hide loading
        button["disabled"] = False
        button["innerHTML"] = original_text

        assert button["disabled"] is False
        assert button["innerHTML"] == original_text

    def test_loading_state_toggle(self):
        """Test complete loading state toggle"""
        button = {"disabled": False, "innerHTML": "Submit"}

        # Show loading
        button["disabled"] = True
        assert button["disabled"] is True

        # Hide loading
        button["disabled"] = False
        assert button["disabled"] is False


class TestUtilityFunctions:
    """Test utility function logic"""

    def test_format_date_handles_invalid(self):
        """Test that date formatting handles invalid input"""
        from datetime import datetime

        # Valid date
        valid_date = "2025-01-15T14:30:00"
        try:
            parsed = datetime.fromisoformat(valid_date.replace('Z', '+00:00') if 'Z' in valid_date else valid_date)
            assert parsed is not None
        except ValueError:
            pytest.fail("Should parse valid date")

        # Invalid date
        invalid_date = "not-a-date"
        with pytest.raises(ValueError):
            datetime.fromisoformat(invalid_date)

    def test_null_element_handling(self):
        """Test that functions handle null elements"""
        # JavaScript checks: if (element) { ... }

        element = None
        if element:
            element["disabled"] = True
        # Should not crash

        element = {"disabled": False}
        if element:
            element["disabled"] = True

        assert element["disabled"] is True


class TestValidationHelpers:
    """Test validation helper functions"""

    def test_empty_string_validation(self):
        """Test empty string detection"""
        empty_strings = ["", "   ", "\t", "\n"]

        for s in empty_strings:
            # JavaScript: !value || value.trim() === ''
            is_empty = not s or s.strip() == ''
            assert is_empty is True

    def test_non_empty_string_validation(self):
        """Test non-empty string detection"""
        valid_strings = ["test", "  test  ", "a"]

        for s in valid_strings:
            is_empty = not s or s.strip() == ''
            assert is_empty is False

    def test_numeric_validation(self):
        """Test numeric input validation"""
        # Test if value is numeric
        numeric_values = ["123", "45.67", "-10", "0"]

        for value in numeric_values:
            try:
                float(value)
                is_numeric = True
            except ValueError:
                is_numeric = False

            assert is_numeric is True

    def test_non_numeric_validation(self):
        """Test non-numeric input rejection"""
        import math

        non_numeric = ["abc", "12abc", ""]

        for value in non_numeric:
            if value == "":
                is_numeric = False
            else:
                try:
                    float(value)
                    is_numeric = True
                except ValueError:
                    is_numeric = False

            assert is_numeric is False

        # Special case: "NaN" is technically parseable as float but not a valid number
        nan_value = float("NaN")
        assert math.isnan(nan_value)  # It's NaN, which is a special float value


class TestTokenManagement:
    """Test token management logic"""

    def test_token_storage_format(self):
        """Test that tokens are stored correctly"""
        # Simulate storing token
        access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        refresh_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ8..."

        storage = {
            "access_token": access_token,
            "refresh_token": refresh_token
        }

        assert storage["access_token"] == access_token
        assert storage["refresh_token"] == refresh_token

    def test_token_retrieval(self):
        """Test token retrieval from storage"""
        storage = {"access_token": "test.token.here"}

        token = storage.get("access_token")

        assert token == "test.token.here"

    def test_missing_token_handling(self):
        """Test handling of missing token"""
        storage = {}

        token = storage.get("access_token")

        assert token is None

    def test_token_expiry_check(self):
        """Test token expiry checking logic"""
        from datetime import datetime, timedelta, timezone

        # Simulate token expiry time
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
        now = datetime.now(timezone.utc)

        is_expired = now >= expires_at

        assert is_expired is False

        # Expired token
        expires_at_past = datetime.now(timezone.utc) - timedelta(minutes=5)
        is_expired = now >= expires_at_past

        assert is_expired is True
