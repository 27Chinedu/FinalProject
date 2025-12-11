# tests/integration/test_profile_api.py
"""
Comprehensive integration tests for profile API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from uuid import uuid4

from app.main import app
from app.models.user import User
from app.models.calculation import Calculation
from app.database import get_db, get_sessionmaker, get_engine
from app.core.config import settings

# Setup test database
test_engine = get_engine(database_url=settings.DATABASE_URL)
TestingSessionLocal = get_sessionmaker(engine=test_engine)

# Override the get_db dependency
def override_get_db():
    """Override get_db for testing"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

# Create test client
client = TestClient(app)


class TestProfileEndpoints:
    """Test profile API endpoints"""

    @pytest.fixture
    def authenticated_user(self, db_session):
        """Create and authenticate a user, return user and auth headers"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Profile",
            "last_name": "User",
            "email": f"profile_{unique_id}@example.com",
            "username": f"profileuser_{unique_id}",
            "password": "SecurePass123!"
        }
        user = User.register(db_session, user_data)
        db_session.commit()

        # Login to get token
        login_response = client.post("/auth/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })
        token = login_response.json()["access_token"]

        return user, {"Authorization": f"Bearer {token}"}

    def test_get_profile(self, authenticated_user, db_session):
        """Test getting current user's profile"""
        user, headers = authenticated_user

        response = client.get("/profile/me", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(user.id)
        assert data["username"] == user.username
        assert data["email"] == user.email
        assert "calculation_count" in data
        assert data["calculation_count"] == 0

    def test_get_profile_with_calculations(self, authenticated_user, db_session):
        """Test profile includes calculation count"""
        user, headers = authenticated_user

        # Add some calculations
        for i in range(5):
            calc = Calculation.create("addition", user.id, [i, i+1])
            calc.result = calc.get_result()
            db_session.add(calc)
        db_session.commit()

        response = client.get("/profile/me", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["calculation_count"] == 5

    def test_get_profile_unauthorized(self):
        """Test getting profile without authentication fails"""
        response = client.get("/profile/me")
        assert response.status_code == 401

    def test_update_profile_username(self, authenticated_user, db_session):
        """Test updating profile username"""
        user, headers = authenticated_user

        unique_id = str(uuid4())[:8]
        update_data = {
            "username": f"newusername_{unique_id}"
        }

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == update_data["username"]

    def test_update_profile_email(self, authenticated_user, db_session):
        """Test updating profile email"""
        user, headers = authenticated_user

        unique_id = str(uuid4())[:8]
        update_data = {
            "email": f"newemail_{unique_id}@example.com"
        }

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == update_data["email"]

    def test_update_profile_names(self, authenticated_user, db_session):
        """Test updating profile first and last name"""
        user, headers = authenticated_user

        update_data = {
            "first_name": "NewFirst",
            "last_name": "NewLast"
        }

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "NewFirst"
        assert data["last_name"] == "NewLast"

    def test_update_profile_all_fields(self, authenticated_user, db_session):
        """Test updating all profile fields at once"""
        user, headers = authenticated_user

        unique_id = str(uuid4())[:8]
        update_data = {
            "username": f"allfielduser_{unique_id}",
            "email": f"allfields_{unique_id}@example.com",
            "first_name": "AllFirst",
            "last_name": "AllLast"
        }

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == update_data["username"]
        assert data["email"] == update_data["email"]
        assert data["first_name"] == update_data["first_name"]
        assert data["last_name"] == update_data["last_name"]

    def test_update_profile_duplicate_username(self, authenticated_user, db_session):
        """Test updating to existing username fails"""
        user, headers = authenticated_user

        # Create another user
        unique_id = str(uuid4())[:8]
        other_user_data = {
            "first_name": "Other",
            "last_name": "User",
            "email": f"other_{unique_id}@example.com",
            "username": f"otheruser_{unique_id}",
            "password": "SecurePass123!"
        }
        other_user = User.register(db_session, other_user_data)
        db_session.commit()

        # Try to update to other user's username
        update_data = {
            "username": other_user.username
        }

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 400
        assert "already taken" in response.json()["detail"].lower()

    def test_update_profile_duplicate_email(self, authenticated_user, db_session):
        """Test updating to existing email fails"""
        user, headers = authenticated_user

        # Create another user
        unique_id = str(uuid4())[:8]
        other_user_data = {
            "first_name": "Other",
            "last_name": "User",
            "email": f"otheremail_{unique_id}@example.com",
            "username": f"otheremailuser_{unique_id}",
            "password": "SecurePass123!"
        }
        other_user = User.register(db_session, other_user_data)
        db_session.commit()

        # Try to update to other user's email
        update_data = {
            "email": other_user.email
        }

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 400
        assert "already in use" in response.json()["detail"].lower()

    def test_update_profile_no_fields(self, authenticated_user):
        """Test updating profile with no fields fails validation"""
        user, headers = authenticated_user

        update_data = {}

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 422  # Validation error

    def test_update_profile_unauthorized(self):
        """Test updating profile without auth fails"""
        update_data = {
            "first_name": "New"
        }

        response = client.put("/profile/me", json=update_data)
        assert response.status_code == 401

    def test_change_password_success(self, authenticated_user, db_session):
        """Test successfully changing password"""
        user, headers = authenticated_user

        password_data = {
            "current_password": "SecurePass123!",
            "new_password": "NewSecurePass123!",
            "confirm_new_password": "NewSecurePass123!"
        }

        response = client.post("/profile/change-password", json=password_data, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert "Password successfully updated" in data["message"]
        assert "updated_at" in data

        # Verify new password works
        db_session.refresh(user)
        assert user.verify_password("NewSecurePass123!")
        assert not user.verify_password("SecurePass123!")

    def test_change_password_wrong_current(self, authenticated_user):
        """Test changing password with wrong current password fails"""
        user, headers = authenticated_user

        password_data = {
            "current_password": "WrongPassword123!",
            "new_password": "NewSecurePass123!",
            "confirm_new_password": "NewSecurePass123!"
        }

        response = client.post("/profile/change-password", json=password_data, headers=headers)
        assert response.status_code == 401
        assert "Current password is incorrect" in response.json()["detail"]

    def test_change_password_mismatch(self, authenticated_user):
        """Test changing password with mismatched new passwords fails"""
        user, headers = authenticated_user

        password_data = {
            "current_password": "SecurePass123!",
            "new_password": "NewSecurePass123!",
            "confirm_new_password": "DifferentPass123!"
        }

        response = client.post("/profile/change-password", json=password_data, headers=headers)
        assert response.status_code == 422  # Validation error

    def test_change_password_same_as_current(self, authenticated_user):
        """Test changing to same password fails validation"""
        user, headers = authenticated_user

        password_data = {
            "current_password": "SecurePass123!",
            "new_password": "SecurePass123!",
            "confirm_new_password": "SecurePass123!"
        }

        response = client.post("/profile/change-password", json=password_data, headers=headers)
        assert response.status_code == 422  # Validation error

    def test_change_password_weak_password(self, authenticated_user):
        """Test changing to weak password fails validation"""
        user, headers = authenticated_user

        password_data = {
            "current_password": "SecurePass123!",
            "new_password": "weak",
            "confirm_new_password": "weak"
        }

        response = client.post("/profile/change-password", json=password_data, headers=headers)
        assert response.status_code == 422  # Validation error

    def test_change_password_no_uppercase(self, authenticated_user):
        """Test password without uppercase fails"""
        user, headers = authenticated_user

        password_data = {
            "current_password": "SecurePass123!",
            "new_password": "nouppercase123!",
            "confirm_new_password": "nouppercase123!"
        }

        response = client.post("/profile/change-password", json=password_data, headers=headers)
        assert response.status_code == 422

    def test_change_password_no_lowercase(self, authenticated_user):
        """Test password without lowercase fails"""
        user, headers = authenticated_user

        password_data = {
            "current_password": "SecurePass123!",
            "new_password": "NOLOWERCASE123!",
            "confirm_new_password": "NOLOWERCASE123!"
        }

        response = client.post("/profile/change-password", json=password_data, headers=headers)
        assert response.status_code == 422

    def test_change_password_no_digit(self, authenticated_user):
        """Test password without digit fails"""
        user, headers = authenticated_user

        password_data = {
            "current_password": "SecurePass123!",
            "new_password": "NoDigitsHere!",
            "confirm_new_password": "NoDigitsHere!"
        }

        response = client.post("/profile/change-password", json=password_data, headers=headers)
        assert response.status_code == 422

    def test_change_password_no_special_char(self, authenticated_user):
        """Test password without special character fails"""
        user, headers = authenticated_user

        password_data = {
            "current_password": "SecurePass123!",
            "new_password": "NoSpecialChar123",
            "confirm_new_password": "NoSpecialChar123"
        }

        response = client.post("/profile/change-password", json=password_data, headers=headers)
        assert response.status_code == 422

    def test_change_password_unauthorized(self):
        """Test changing password without auth fails"""
        password_data = {
            "current_password": "OldPass123!",
            "new_password": "NewPass123!",
            "confirm_new_password": "NewPass123!"
        }

        response = client.post("/profile/change-password", json=password_data)
        assert response.status_code == 401


class TestProfileEdgeCases:
    """Test edge cases for profile endpoints"""

    @pytest.fixture
    def authenticated_user(self, db_session):
        """Create and authenticate a user"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Edge",
            "last_name": "Case",
            "email": f"profileedge_{unique_id}@example.com",
            "username": f"profileedgeuser_{unique_id}",
            "password": "SecurePass123!"
        }
        user = User.register(db_session, user_data)
        db_session.commit()

        login_response = client.post("/auth/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })
        token = login_response.json()["access_token"]

        return user, {"Authorization": f"Bearer {token}"}

    def test_profile_short_username(self, authenticated_user):
        """Test updating to username that's too short fails"""
        user, headers = authenticated_user

        update_data = {
            "username": "ab"  # Less than 3 characters
        }

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 422

    def test_profile_invalid_email(self, authenticated_user):
        """Test updating to invalid email fails"""
        user, headers = authenticated_user

        update_data = {
            "email": "not-an-email"
        }

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 422

    def test_profile_empty_name(self, authenticated_user):
        """Test updating to empty name fails"""
        user, headers = authenticated_user

        update_data = {
            "first_name": ""
        }

        response = client.put("/profile/me", json=update_data, headers=headers)
        assert response.status_code == 422

    def test_profile_with_large_calculation_count(self, authenticated_user, db_session):
        """Test profile correctly counts many calculations"""
        user, headers = authenticated_user

        # Create many calculations
        for i in range(50):
            calc = Calculation.create("addition", user.id, [i, 1])
            calc.result = calc.get_result()
            db_session.add(calc)
        db_session.commit()

        response = client.get("/profile/me", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["calculation_count"] == 50
