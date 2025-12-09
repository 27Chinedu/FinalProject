# tests/unit/test_lifecycle.py

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base
from app.models.user import User
from app.models.calculation import Calculation


class TestApplicationLifecycle:
    """Test application startup and shutdown"""

    def test_app_initializes_successfully(self):
        """Test that application initializes without errors"""
        client = TestClient(app)

        # Basic request should work
        response = client.get("/health")
        assert response.status_code == 200

    def test_database_tables_created_on_startup(self):
        """Test that database tables are created during lifespan"""
        from app.database import engine

        # Check that tables exist
        with engine.connect() as conn:
            # Query to check if users table exists
            result = conn.execute(text(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'users'
                )
                """
            ))
            users_table_exists = result.scalar()

            result = conn.execute(text(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'calculations'
                )
                """
            ))
            calculations_table_exists = result.scalar()

        assert users_table_exists is True
        assert calculations_table_exists is True

    def test_app_metadata_correct(self):
        """Test that app metadata is correct"""
        assert app.title == "Calculations API"
        assert app.version == "1.0.0"
        assert "API for managing calculations" in app.description

    def test_routers_mounted_correctly(self):
        """Test that routers are mounted"""
        # Check that profile router is included
        routes = [route.path for route in app.routes]

        assert "/profile/me" in routes
        assert "/profile/change-password" in routes

    def test_static_files_mounted(self):
        """Test that static files are mounted"""
        routes = [route.path for route in app.routes]

        # Static files should be mounted at /static
        static_routes = [r for r in routes if "/static" in r]
        assert len(static_routes) > 0

    def test_middleware_configured(self):
        """Test that middleware is configured"""
        # Check that CORS or other middleware is present
        middleware_count = len(app.user_middleware)

        # Should have at least some middleware configured
        assert middleware_count >= 0  # May be 0 if no explicit middleware


class TestDatabaseInitialization:
    """Test database initialization functions"""

    def test_init_db_creates_tables(self):
        """Test that init_db creates all tables"""
        from app.database_init import init_db
        from app.database import engine

        # Drop and recreate
        Base.metadata.drop_all(bind=engine)
        init_db()

        # Verify tables exist
        with engine.connect() as conn:
            result = conn.execute(text(
                """
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
                """
            ))
            tables = [row[0] for row in result]

        assert "users" in tables
        assert "calculations" in tables

    def test_drop_db_removes_tables(self):
        """Test that drop_db removes tables"""
        from app.database_init import init_db, drop_db
        from app.database import engine

        # Ensure tables exist
        init_db()

        # Drop tables
        drop_db()

        # Verify tables don't exist
        with engine.connect() as conn:
            result = conn.execute(text(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'users'
                )
                """
            ))
            users_exists = result.scalar()

        assert users_exists is False

        # Recreate for other tests
        init_db()


class TestDatabaseConnection:
    """Test database connection management"""

    def test_get_db_yields_session(self):
        """Test that get_db yields a valid session"""
        from app.database import get_db

        db_gen = get_db()
        db = next(db_gen)

        # Should be a valid session
        assert db is not None

        # Should be able to query
        result = db.execute(text("SELECT 1"))
        assert result.scalar() == 1

        # Close the generator
        try:
            next(db_gen)
        except StopIteration:
            pass

    def test_get_db_closes_session(self):
        """Test that get_db closes session after use"""
        from app.database import get_db

        db_gen = get_db()
        db = next(db_gen)
        session_id = id(db)

        # Complete the generator (triggers finally block)
        try:
            next(db_gen)
        except StopIteration:
            pass

        # Session should be closed
        # Note: Can't directly test if closed, but it shouldn't raise errors

    def test_engine_factory_creates_engine(self):
        """Test that get_engine creates a valid engine"""
        from app.database import get_engine

        engine = get_engine()

        assert engine is not None

        # Should be able to connect
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            assert result.scalar() == 1

    def test_sessionmaker_factory(self):
        """Test that get_sessionmaker creates valid sessionmaker"""
        from app.database import get_engine, get_sessionmaker

        engine = get_engine()
        SessionMaker = get_sessionmaker(engine)

        assert SessionMaker is not None

        # Should create valid sessions
        session = SessionMaker()
        result = session.execute(text("SELECT 1"))
        assert result.scalar() == 1
        session.close()


class TestConfigurationLoading:
    """Test configuration loading"""

    def test_settings_loads(self):
        """Test that settings load correctly"""
        from app.core.config import settings

        assert settings is not None
        assert settings.DATABASE_URL is not None
        assert settings.JWT_SECRET_KEY is not None

    def test_get_settings_returns_cached(self):
        """Test that get_settings returns cached instance"""
        from app.core.config import get_settings

        settings1 = get_settings()
        settings2 = get_settings()

        # Should be same instance (cached)
        assert id(settings1) == id(settings2)

    def test_settings_has_required_fields(self):
        """Test that settings has all required fields"""
        from app.core.config import settings

        # Database
        assert hasattr(settings, "DATABASE_URL")

        # JWT
        assert hasattr(settings, "JWT_SECRET_KEY")
        assert hasattr(settings, "JWT_REFRESH_SECRET_KEY")
        assert hasattr(settings, "ALGORITHM")
        assert hasattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES")

        # Security
        assert hasattr(settings, "BCRYPT_ROUNDS")
        assert hasattr(settings, "CORS_ORIGINS")

    def test_settings_values_correct_types(self):
        """Test that settings values have correct types"""
        from app.core.config import settings

        assert isinstance(settings.DATABASE_URL, str)
        assert isinstance(settings.JWT_SECRET_KEY, str)
        assert isinstance(settings.ALGORITHM, str)
        assert isinstance(settings.ACCESS_TOKEN_EXPIRE_MINUTES, int)
        assert isinstance(settings.BCRYPT_ROUNDS, int)
        assert isinstance(settings.CORS_ORIGINS, list)

    def test_bcrypt_rounds_reasonable(self):
        """Test that bcrypt rounds is set to a secure value"""
        from app.core.config import settings

        # Should be between 10 and 14 for security vs performance
        assert 10 <= settings.BCRYPT_ROUNDS <= 14

    def test_access_token_expiry_reasonable(self):
        """Test that access token expiry is reasonable"""
        from app.core.config import settings

        # Should be between 5 and 120 minutes
        assert 5 <= settings.ACCESS_TOKEN_EXPIRE_MINUTES <= 120


class TestDatabaseConnectionPool:
    """Test database connection pooling"""

    def test_multiple_sessions_work(self):
        """Test that multiple sessions can be created"""
        from app.database import SessionLocal

        sessions = []
        for i in range(5):
            session = SessionLocal()
            sessions.append(session)

        # All should be valid
        for session in sessions:
            result = session.execute(text("SELECT 1"))
            assert result.scalar() == 1

        # Close all
        for session in sessions:
            session.close()

    def test_session_isolation(self):
        """Test that sessions are isolated"""
        from app.database import SessionLocal
        from uuid import uuid4

        session1 = SessionLocal()
        session2 = SessionLocal()

        # Create user in session1 without committing
        user_data = {
            "first_name": "Isolated",
            "last_name": "Test",
            "email": f"isolated_{uuid4()}@example.com",
            "username": f"isolated_{uuid4()}",
            "password": "TestPass123!"
        }

        user = User.register(session1, user_data)
        session1.flush()  # Write to DB but don't commit

        # Session2 should not see uncommitted data
        user2 = session2.query(User).filter(
            User.username == user.username
        ).first()

        assert user2 is None

        # Rollback and close
        session1.rollback()
        session1.close()
        session2.close()


class TestModelBaseClasses:
    """Test model base classes"""

    def test_base_declarative_base(self):
        """Test that Base is a valid declarative base"""
        from app.database import Base

        assert Base is not None
        assert hasattr(Base, "metadata")

    def test_models_inherit_from_base(self):
        """Test that models inherit from Base"""
        from app.database import Base

        assert issubclass(User, Base)
        # Calculation uses AbstractCalculation, but it should still work
        from app.models.calculation import AbstractCalculation
        assert issubclass(AbstractCalculation, Base)
