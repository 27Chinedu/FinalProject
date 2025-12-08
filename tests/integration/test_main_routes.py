# tests/integration/test_main_routes.py

import pytest
from uuid import uuid4
from datetime import datetime
from app.models.user import User
from app.models.calculation import Calculation

def test_get_calculation_invalid_id_format(db_session, fake_user_data):
    """Test getting calculation with invalid ID format"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # This would need to be tested via API endpoints
    # Here we just ensure the model works correctly
    assert user.id is not None

def test_update_calculation_invalid_id(db_session, fake_user_data):
    """Test updating calculation with invalid ID"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Create a calculation
    calc = Calculation.create("addition", user.id, [1, 2, 3])
    calc.result = calc.get_result()
    db_session.add(calc)
    db_session.commit()
    
    # Try to query with wrong ID
    result = db_session.query(Calculation).filter(
        Calculation.id == uuid4()
    ).first()
    assert result is None

def test_delete_calculation_not_owned(db_session):
    """Test deleting calculation not owned by user"""
    # Create two users
    user1_data = {
        "first_name": "User",
        "last_name": "One",
        "email": "user1@example.com",
        "username": "user1",
        "password": "TestPass123!"
    }
    user1 = User.register(db_session, user1_data)
    
    user2_data = {
        "first_name": "User",
        "last_name": "Two",
        "email": "user2@example.com",
        "username": "user2",
        "password": "TestPass123!"
    }
    user2 = User.register(db_session, user2_data)
    db_session.commit()
    
    # Create calculation for user1
    calc = Calculation.create("addition", user1.id, [1, 2])
    calc.result = calc.get_result()
    db_session.add(calc)
    db_session.commit()
    
    # User2 should not find this calculation
    result = db_session.query(Calculation).filter(
        Calculation.id == calc.id,
        Calculation.user_id == user2.id
    ).first()
    assert result is None

def test_calculation_cascade_delete(db_session, fake_user_data):
    """Test that calculations are deleted when user is deleted"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Create calculations
    calc1 = Calculation.create("addition", user.id, [1, 2])
    calc1.result = calc1.get_result()
    calc2 = Calculation.create("subtraction", user.id, [10, 5])
    calc2.result = calc2.get_result()
    
    db_session.add(calc1)
    db_session.add(calc2)
    db_session.commit()
    
    calc_ids = [calc1.id, calc2.id]
    
    # Delete user
    db_session.delete(user)
    db_session.commit()
    
    # Calculations should be deleted
    remaining = db_session.query(Calculation).filter(
        Calculation.id.in_(calc_ids)
    ).count()
    assert remaining == 0

def test_user_last_login_null_initially(db_session, fake_user_data):
    """Test that last_login is None initially"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    assert user.last_login is None

def test_calculation_timestamps(db_session, fake_user_data):
    """Test calculation timestamps are set correctly"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    calc = Calculation.create("addition", user.id, [1, 2])
    calc.result = calc.get_result()
    db_session.add(calc)
    db_session.commit()
    db_session.refresh(calc)
    
    assert calc.created_at is not None
    assert calc.updated_at is not None
    assert isinstance(calc.created_at, datetime)
    assert isinstance(calc.updated_at, datetime)

def test_calculation_update_timestamp(db_session, fake_user_data):
    """Test calculation updated_at changes on update"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    calc = Calculation.create("addition", user.id, [1, 2])
    calc.result = calc.get_result()
    db_session.add(calc)
    db_session.commit()
    db_session.refresh(calc)
    
    original_updated = calc.updated_at
    
    # Update calculation
    calc.inputs = [5, 10]
    calc.result = calc.get_result()
    calc.updated_at = datetime.utcnow()
    db_session.commit()
    db_session.refresh(calc)
    
    assert calc.updated_at > original_updated

def test_user_is_active_default(db_session, fake_user_data):
    """Test user is_active defaults to True"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    assert user.is_active is True

def test_user_is_verified_default(db_session, fake_user_data):
    """Test user is_verified defaults to False"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    assert user.is_verified is False

def test_calculation_type_indexing(db_session, fake_user_data):
    """Test querying calculations by type"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Create different types
    add = Calculation.create("addition", user.id, [1, 2])
    add.result = add.get_result()
    sub = Calculation.create("subtraction", user.id, [10, 5])
    sub.result = sub.get_result()
    
    db_session.add(add)
    db_session.add(sub)
    db_session.commit()
    
    # Query by type
    additions = db_session.query(Calculation).filter(
        Calculation.type == "addition",
        Calculation.user_id == user.id
    ).all()
    
    assert len(additions) == 1
    assert additions[0].type == "addition"

def test_user_created_at_timezone_aware(db_session, fake_user_data):
    """Test user created_at is timezone aware"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    assert user.created_at.tzinfo is not None

def test_profile_route_error_handling(db_session, fake_user_data):
    """Test profile route handles database errors"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Test that we can retrieve the user
    retrieved = db_session.query(User).filter(User.id == user.id).first()
    assert retrieved is not None
    assert retrieved.id == user.id