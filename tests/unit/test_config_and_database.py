# tests/unit/test_config_and_database.py

import pytest
from app.core.config import get_settings, Settings
from app.database import get_db, get_engine, get_sessionmaker, Base

def test_get_settings():
    """Test get_settings returns Settings instance"""
    settings = get_settings()
    assert isinstance(settings, Settings)

def test_settings_default_values():
    """Test settings have default values"""
    settings = get_settings()
    assert settings.ALGORITHM == "HS256"
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES > 0
    assert settings.REFRESH_TOKEN_EXPIRE_DAYS > 0
    assert settings.BCRYPT_ROUNDS > 0

def test_settings_database_url():
    """Test settings have database URL"""
    settings = get_settings()
    assert settings.DATABASE_URL is not None
    assert isinstance(settings.DATABASE_URL, str)

def test_settings_jwt_keys():
    """Test settings have JWT keys"""
    settings = get_settings()
    assert settings.JWT_SECRET_KEY is not None
    assert settings.JWT_REFRESH_SECRET_KEY is not None

def test_settings_cors_origins():
    """Test settings have CORS origins"""
    settings = get_settings()
    assert settings.CORS_ORIGINS is not None
    assert isinstance(settings.CORS_ORIGINS, list)

def test_get_db_generator():
    """Test get_db returns a generator"""
    db_gen = get_db()
    assert hasattr(db_gen, '__next__')

def test_get_engine_factory():
    """Test get_engine creates an engine"""
    from app.core.config import settings
    engine = get_engine(settings.DATABASE_URL)
    assert engine is not None
    assert hasattr(engine, 'connect')

def test_get_sessionmaker_factory():
    """Test get_sessionmaker creates a sessionmaker"""
    from app.core.config import settings
    engine = get_engine(settings.DATABASE_URL)
    session_maker = get_sessionmaker(engine)
    assert session_maker is not None
    assert callable(session_maker)

def test_base_metadata():
    """Test Base has metadata"""
    assert Base.metadata is not None
    assert hasattr(Base.metadata, 'create_all')
    assert hasattr(Base.metadata, 'drop_all')

def test_settings_caching():
    """Test that get_settings returns cached instance"""
    settings1 = get_settings()
    settings2 = get_settings()
    assert settings1 is settings2

def test_redis_url_optional():
    """Test REDIS_URL is optional"""
    settings = get_settings()
    # Redis URL can be None since it's optional
    assert settings.REDIS_URL is None or isinstance(settings.REDIS_URL, str)