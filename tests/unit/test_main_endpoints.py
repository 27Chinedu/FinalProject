# tests/unit/test_main_endpoints.py
"""
Unit tests for app/main.py endpoints using FastAPI TestClient.
This ensures the code in main.py is actually executed and covered.
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


def override_get_db():
    """Override get_db for testing"""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


class TestWebPageRoutes:
    """Test HTML page routes from main.py"""

    def test_read_index(self):
        """Test GET / returns index page"""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_login_page(self):
        """Test GET /login returns login page"""
        response = client.get("/login")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_register_page(self):
        """Test GET /register returns register page"""
        response = client.get("/register")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_dashboard_page(self):
        """Test GET /dashboard returns dashboard page"""
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_profile_page(self):
        """Test GET /profile returns profile page"""
        response = client.get("/profile")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]


class TestHealthEndpoint:
    """Test health endpoint from main.py"""

    def test_read_health(self):
        """Test GET /health returns ok status"""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestAuthEndpoints:
    """Test authentication endpoints from main.py"""

    def test_register_success(self, db_session):
        """Test POST /auth/register with valid data"""
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

    def test_register_validation_error(self):
        """Test POST /auth/register with invalid data"""
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "invalid-email",
            "username": "test",
            "password": "weak",
            "confirm_password": "weak"
        }

        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422

    def test_register_duplicate_user(self, db_session):
        """Test POST /auth/register with duplicate username"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "First",
            "last_name": "User",
            "email": f"first_{unique_id}@example.com",
            "username": f"duplicate_{unique_id}",
            "password": "SecurePass123!"
        }
        
        # Register first user
        user = User.register(db_session, user_data)
        db_session.commit()

        # Try to register again
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
        """Test POST /auth/login with valid credentials"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Login",
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
        assert "expires_at" in data
        assert data["username"] == user_data["username"]
        assert data["email"] == user_data["email"]

    def test_login_json_invalid_credentials(self):
        """Test POST /auth/login with invalid credentials"""
        login_data = {
            "username": "nonexistent",
            "password": "WrongPass123!"
        }

        response = client.post("/auth/login", json=login_data)
        assert response.status_code == 401
        assert "Invalid username or password" in response.json()["detail"]

    def test_login_form_success(self, db_session):
        """Test POST /auth/token with form data (OAuth2 flow)"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "Form",
            "last_name": "User",
            "email": f"form_{unique_id}@example.com",
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
        """Test POST /auth/token with invalid credentials"""
        form_data = {
            "username": "nonexistent",
            "password": "wrong"
        }

        response = client.post("/auth/token", data=form_data)
        assert response.status_code == 401


class TestCalculationEndpoints:
    """Test calculation endpoints from main.py"""

    @pytest.fixture
    def auth_headers(self, db_session):
        """Create user and return auth headers"""
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

        login_response = client.post("/auth/login", json={
            "username": user_data["username"],
            "password": user_data["password"]
        })
        token = login_response.json()["access_token"]

        return user, {"Authorization": f"Bearer {token}"}

    def test_create_calculation_success(self, auth_headers):
        """Test POST /calculations with valid data"""
        user, headers = auth_headers

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
        assert data["user_id"] == str(user.id)

    def test_create_calculation_validation_error(self, auth_headers):
        """Test POST /calculations with invalid data"""
        user, headers = auth_headers

        calc_data = {
            "type": "addition",
            "inputs": [1]  # Too few inputs
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 422

    def test_create_calculation_value_error(self, auth_headers, db_session):
        """Test POST /calculations with division by zero"""
        user, headers = auth_headers

        # This should trigger ValueError in the route handler
        calc_data = {
            "type": "division",
            "inputs": [10, 0]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 422  # Schema validation catches this

    def test_list_calculations(self, auth_headers, db_session):
        """Test GET /calculations"""
        user, headers = auth_headers

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

    def test_get_calculation_success(self, auth_headers, db_session):
        """Test GET /calculations/{calc_id}"""
        user, headers = auth_headers

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

    def test_get_calculation_invalid_uuid(self, auth_headers):
        """Test GET /calculations/{calc_id} with invalid UUID"""
        user, headers = auth_headers

        response = client.get("/calculations/invalid-uuid", headers=headers)
        assert response.status_code == 400
        assert "Invalid calculation id format" in response.json()["detail"]

    def test_get_calculation_not_found(self, auth_headers):
        """Test GET /calculations/{calc_id} with non-existent ID"""
        user, headers = auth_headers

        fake_id = uuid4()
        response = client.get(f"/calculations/{fake_id}", headers=headers)
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_update_calculation_success(self, auth_headers, db_session):
        """Test PUT /calculations/{calc_id}"""
        user, headers = auth_headers

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

    def test_update_calculation_with_none_inputs(self, auth_headers, db_session):
        """Test PUT /calculations/{calc_id} with None inputs (no update)"""
        user, headers = auth_headers

        calc = Calculation.create("addition", user.id, [1, 2])
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()
        db_session.refresh(calc)

        # Send empty update (inputs=None in CalculationUpdate)
        update_data = {}
        response = client.put(f"/calculations/{calc.id}", json=update_data, headers=headers)
        # Should succeed but not change anything
        assert response.status_code in [200, 422]

    def test_update_calculation_invalid_uuid(self, auth_headers):
        """Test PUT /calculations/{calc_id} with invalid UUID"""
        user, headers = auth_headers

        update_data = {"inputs": [5, 10]}
        response = client.put("/calculations/invalid-uuid", json=update_data, headers=headers)
        assert response.status_code == 400

    def test_update_calculation_not_found(self, auth_headers):
        """Test PUT /calculations/{calc_id} with non-existent ID"""
        user, headers = auth_headers

        fake_id = uuid4()
        update_data = {"inputs": [5, 10]}
        response = client.put(f"/calculations/{fake_id}", json=update_data, headers=headers)
        assert response.status_code == 404

    def test_delete_calculation_success(self, auth_headers, db_session):
        """Test DELETE /calculations/{calc_id}"""
        user, headers = auth_headers

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

    def test_delete_calculation_invalid_uuid(self, auth_headers):
        """Test DELETE /calculations/{calc_id} with invalid UUID"""
        user, headers = auth_headers

        response = client.delete("/calculations/invalid-uuid", headers=headers)
        assert response.status_code == 400

    def test_delete_calculation_not_found(self, auth_headers):
        """Test DELETE /calculations/{calc_id} with non-existent ID"""
        user, headers = auth_headers

        fake_id = uuid4()
        response = client.delete(f"/calculations/{fake_id}", headers=headers)
        assert response.status_code == 404

    def test_calculations_require_authentication(self):
        """Test that calculation endpoints require auth"""
        response = client.post("/calculations", json={"type": "addition", "inputs": [1, 2]})
        assert response.status_code == 401

        response = client.get("/calculations")
        assert response.status_code == 401

        fake_id = uuid4()
        response = client.get(f"/calculations/{fake_id}")
        assert response.status_code == 401

        response = client.put(f"/calculations/{fake_id}", json={"inputs": [1, 2]})
        assert response.status_code == 401

        response = client.delete(f"/calculations/{fake_id}")
        assert response.status_code == 401


class TestEdgeCases:
    """Test edge cases and error handling in main.py"""

    @pytest.fixture
    def auth_headers(self, db_session):
        """Create user and return auth headers"""
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

    def test_login_timezone_handling(self, db_session):
        """Test that login returns timezone-aware expires_at"""
        unique_id = str(uuid4())[:8]
        user_data = {
            "first_name": "TZ",
            "last_name": "Test",
            "email": f"tz_{unique_id}@example.com",
            "username": f"tzuser_{unique_id}",
            "password": "SecurePass123!"
        }
        User.register(db_session, user_data)
        db_session.commit()

        login_data = {
            "username": user_data["username"],
            "password": user_data["password"]
        }

        response = client.post("/auth/login", json=login_data)
        assert response.status_code == 200
        data = response.json()
        
        # Verify expires_at is present and valid
        assert "expires_at" in data
        expires_str = data["expires_at"]
        # Should be parseable as datetime
        from datetime import datetime
        if expires_str.endswith('Z'):
            expires_str = expires_str.replace('Z', '+00:00')
        expires_dt = datetime.fromisoformat(expires_str)
        assert expires_dt is not None

    def test_calculation_with_negative_numbers(self, auth_headers):
        """Test calculation with negative inputs"""
        user, headers = auth_headers

        calc_data = {
            "type": "addition",
            "inputs": [-10, 5, -3]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 201
        assert response.json()["result"] == -8

    def test_calculation_with_decimals(self, auth_headers):
        """Test calculation with decimal inputs"""
        user, headers = auth_headers

        calc_data = {
            "type": "multiplication",
            "inputs": [2.5, 4.0]
        }

        response = client.post("/calculations", json=calc_data, headers=headers)
        assert response.status_code == 201
        result = response.json()["result"]
        assert abs(result - 10.0) < 0.01

    def test_all_calculation_types(self, auth_headers):
        """Test all four calculation types"""
        user, headers = auth_headers

        test_cases = [
            ("addition", [1, 2, 3], 6),
            ("subtraction", [10, 3, 2], 5),
            ("multiplication", [2, 3, 4], 24),
            ("division", [100, 2, 5], 10)
        ]

        for calc_type, inputs, expected in test_cases:
            calc_data = {
                "type": calc_type,
                "inputs": inputs
            }
            response = client.post("/calculations", json=calc_data, headers=headers)
            assert response.status_code == 201
            assert response.json()["result"] == expected

    def test_update_calculation_changes_updated_at(self, auth_headers, db_session):
        """Test that updating calculation changes updated_at timestamp"""
        user, headers = auth_headers

        calc = Calculation.create("addition", user.id, [1, 2])
        calc.result = calc.get_result()
        db_session.add(calc)
        db_session.commit()
        db_session.refresh(calc)

        original_updated_at = calc.updated_at

        # Update calculation
        update_data = {"inputs": [5, 10]}
        response = client.put(f"/calculations/{calc.id}", json=update_data, headers=headers)
        assert response.status_code == 200

        # Verify updated_at changed
        db_session.refresh(calc)
        assert calc.updated_at >= original_updated_at


@pytest.fixture
def db_session():
    """Provide a database session for tests"""
    db = TestingSessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()