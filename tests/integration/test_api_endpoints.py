# tests/integration/test_api_endpoints.py
"""
Comprehensive integration tests for all API endpoints to increase coverage.
Tests actual HTTP requests to the FastAPI application.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from uuid import uuid4
from datetime import datetime

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


class TestHealthEndpoint:
    """Test health check endpoint"""

    def test_health_check(self):
        """Test /health endpoint returns ok status"""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestWebPageRoutes:
    """Test web page HTML routes"""

    def test_index_page(self):
        """Test / (index) returns HTML"""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_login_page(self):
        """Test /login returns HTML"""
        response = client.get("/login")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_register_page(self):
        """Test /register returns HTML"""
        response = client.get("/register")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_dashboard_page(self):
        """Test /dashboard returns HTML"""
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_profile_page(self):
        """Test /profile returns HTML"""
        response = client.get("/profile")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]


class TestAuthEndpoints:
    """Test authentication endpoints"""

    def test_register_success(self, db_session):
        """Test successful user registration"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{unique_id}@example.com",
            "username": f"testuser_{unique_id}",
            "password": "SecurePass123!",
            "confirm_password": "SecurePass123!"
        }

        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == user_data["username"]
        assert data["email"] == user_data["email"]
        assert "id" in data

    def test_register_password_mismatch(self):
        """Test registration fails with mismatched passwords"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"test_{unique_id}@example.com",
            "username": f"testuser_{unique_id}",
            "password": "SecurePass123!",
            "confirm_password": "DifferentPass123!"
        }

        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422  # Validation error

    def test_register_duplicate_username(self, db_session):
        """Test registration fails with duplicate username"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "First",
            "last_name": "User",
            "email": f"first_{unique_id}@example.com",
            "username": f"duplicate_{unique_id}",
            "password": "SecurePass123!"
        }
        user = User.register(db_session, user_data)
        db_session.commit()

        # Try to register again with same username
        duplicate_data = {
            "first_name": "Second",
            "last_name": "User",
            "email": f"second_{unique_id}@example.com",
            "username": user_data["username"],
            "password": "SecurePass123!",
            "confirm_password": "SecurePass123!"
        }

        response = client.post("/auth/register", json=duplicate_data)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"].lower()

    def test_login_json_success(self, db_session):
        """Test successful login with JSON payload"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"login_{unique_id}@example.com",
            "username": f"loginuser_{unique_id}",
            "password": "SecurePass123!"
        }
        user = User.register(db_session, user_data)
        db_session.commit()

        login_data = {
            "username": user_data["username"],
            "password": user_data["password"]
        }

        response = client.post("/auth/login", json=login_data)
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["username"] == user_data["username"]

    def test_login_json_invalid_credentials(self):
        """Test login fails with invalid credentials"""
        login_data = {
            "username": "nonexistent_user",
            "password": "WrongPass123!"
        }

        response = client.post("/auth/login", json=login_data)
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["detail"]

    def test_login_form_success(self, db_session):
        """Test successful login with form data (OAuth2 flow)"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": f"formlogin_{unique_id}@example.com",
            "username": f"formuser_{unique_id}",
            "password": "SecurePass123!"
        }
        user = User.register(db_session, user_data)
        db_session.commit()

        form_data = {
            "username": user_data["username"],
            "password": user_data["password"]
        }

        response = client.post("/auth/token", data=form_data)
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_form_invalid_credentials(self):
        """Test form login fails with invalid credentials"""
        form_data = {
            "username": "nonexistent",
            "password": "wrong"
        }

        response = client.post("/auth/token", data=form_data)
        assert response.status_code == 401


class TestCalculationEndpoints:
    """Test calculation BREAD endpoints"""

    @pytest.fixture
    def authenticated_user(self, db_session):
        """Create and authenticate a user, return user and auth headers"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Calc",
            "last_name": "User",
            "email": f"calc_{unique_id}@example.com",
            "username": f"calcuser_{unique_id}",
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

    def test_create_calculation_addition(self, authenticated_user):
        """Test creating an addition calculation"""
        user, headers = authenticated_user

        calc_data = {
            "type": "addition",
            "inputs": [10, 20, 30]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 201
        data = response.json()
        assert data["type"] == "addition"
        assert data["inputs"] == [10, 20, 30]
        assert data["result"] == 60
        assert "id" in data
        assert data["user_id"] == str(user.id)

    def test_create_calculation_subtraction(self, authenticated_user):
        """Test creating a subtraction calculation"""
        user, headers = authenticated_user

        calc_data = {
            "type": "subtraction",
            "inputs": [100, 25, 10]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 201
        data = response.json()
        assert data["type"] == "subtraction"
        assert data["result"] == 65

    def test_create_calculation_multiplication(self, authenticated_user):
        """Test creating a multiplication calculation"""
        user, headers = authenticated_user

        calc_data = {
            "type": "multiplication",
            "inputs": [5, 4, 2]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 201
        data = response.json()
        assert data["type"] == "multiplication"
        assert data["result"] == 40

    def test_create_calculation_division(self, authenticated_user):
        """Test creating a division calculation"""
        user, headers = authenticated_user

        calc_data = {
            "type": "division",
            "inputs": [100, 2, 5]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 201
        data = response.json()
        assert data["type"] == "division"
        assert data["result"] == 10

    def test_create_calculation_division_by_zero(self, authenticated_user):
        """Test division by zero returns error"""
        user, headers = authenticated_user

        calc_data = {
            "type": "division",
            "inputs": [100, 0]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 422  # Validation error

    def test_create_calculation_unauthorized(self):
        """Test creating calculation without auth fails"""
        calc_data = {
            "type": "addition",
            "inputs": [1, 2]
        }

        response = client.post("/calculations", json=calc_data)
        assert response.status_code == 401

    def test_list_calculations(self, authenticated_user, db_session):
        """Test listing user's calculations"""
        user, headers = authenticated_user

        # Create some calculations
        for i in range(3):
            calc = Calculation.create("addition", user.id, [i, i+1])
            calc.result = calc.get_result()
            db_session.add(calc)
        db_session.commit()

        response = client.get("/calculations", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 3
        assert all(c["user_id"] == str(user.id) for c in data)

    def test_list_calculations_unauthorized(self):
        """Test listing calculations without auth fails"""
        response = client.get("/calculations")
        assert response.status_code == 401

    def test_get_calculation_by_id(self, authenticated_user, db_session):
        """Test retrieving a specific calculation"""
        user, headers = authenticated_user

        calc = Calculation.create("addition", user.id, [5, 10])
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()
        db_session.refresh(calc)

        response = client.get(f"/calculations/{calc.id}", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(calc.id)
        assert data["result"] == 15

    def test_get_calculation_invalid_id_format(self, authenticated_user):
        """Test getting calculation with invalid UUID format"""
        user, headers = authenticated_user

        response = client.get("/calculations/invalid-uuid", headers=headers)
        assert response.status_code == 400
        assert "Invalid calculation id format" in response.json()["detail"]

    def test_get_calculation_not_found(self, authenticated_user):
        """Test getting non-existent calculation"""
        user, headers = authenticated_user

        fake_id = uuid4()
        response = client.get(f"/calculations/{fake_id}", headers=headers)
        assert response.status_code == 404
        assert "Calculation not found" in response.json()["detail"]

    def test_update_calculation(self, authenticated_user, db_session):
        """Test updating a calculation's inputs"""
        user, headers = authenticated_user

        calc = Calculation.create("addition", user.id, [1, 2])
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()
        db_session.refresh(calc)

        update_data = {"inputs": [10, 20, 30]}
        response = client.put(f"/calculations/{calc.id}", json=update_data, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["inputs"] == [10, 20, 30]
        assert data["result"] == 60

    def test_update_calculation_invalid_id(self, authenticated_user):
        """Test updating calculation with invalid UUID"""
        user, headers = authenticated_user

        update_data = {"inputs": [5, 10]}
        response = client.put("/calculations/invalid-uuid", json=update_data, headers=headers)
        assert response.status_code == 400

    def test_update_calculation_not_found(self, authenticated_user):
        """Test updating non-existent calculation"""
        user, headers = authenticated_user

        fake_id = uuid4()
        update_data = {"inputs": [5, 10]}
        response = client.put(f"/calculations/{fake_id}", json=update_data, headers=headers)
        assert response.status_code == 404

    def test_delete_calculation(self, authenticated_user, db_session):
        """Test deleting a calculation"""
        user, headers = authenticated_user

        calc = Calculation.create("addition", user.id, [1, 2])
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()
        calc_id = calc.id

        response = client.delete(f"/calculations/{calc_id}", headers=headers)
        assert response.status_code == 204

        # Verify deletion
        deleted = db_session.query(Calculation).filter(Calculation.id == calc_id).first()
        assert deleted is None

    def test_delete_calculation_invalid_id(self, authenticated_user):
        """Test deleting calculation with invalid UUID"""
        user, headers = authenticated_user

        response = client.delete("/calculations/invalid-uuid", headers=headers)
        assert response.status_code == 400

    def test_delete_calculation_not_found(self, authenticated_user):
        """Test deleting non-existent calculation"""
        user, headers = authenticated_user

        fake_id = uuid4()
        response = client.delete(f"/calculations/{fake_id}", headers=headers)
        assert response.status_code == 404


class TestCalculationEdgeCases:
    """Test edge cases for calculations"""

    @pytest.fixture
    def authenticated_user(self, db_session):
        """Create and authenticate a user"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Edge",
            "last_name": "Case",
            "email": f"edge_{unique_id}@example.com",
            "username": f"edgeuser_{unique_id}",
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

    def test_calculation_with_negative_numbers(self, authenticated_user):
        """Test calculations with negative numbers"""
        user, headers = authenticated_user

        calc_data = {
            "type": "addition",
            "inputs": [-10, 5, -3]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 201
        assert response.json()["result"] == -8

    def test_calculation_with_decimals(self, authenticated_user):
        """Test calculations with decimal numbers"""
        user, headers = authenticated_user

        calc_data = {
            "type": "multiplication",
            "inputs": [2.5, 4.2]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 201
        assert abs(response.json()["result"] - 10.5) < 0.01

    def test_calculation_insufficient_inputs(self, authenticated_user):
        """Test calculation with only one input fails"""
        user, headers = authenticated_user

        calc_data = {
            "type": "addition",
            "inputs": [5]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 422

    def test_calculation_invalid_type(self, authenticated_user):
        """Test calculation with invalid type"""
        user, headers = authenticated_user

        calc_data = {
            "type": "modulo",
            "inputs": [10, 3]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 422
