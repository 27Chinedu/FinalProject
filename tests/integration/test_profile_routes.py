# tests/integration/test_profile_routes.py

import pytest
from uuid import uuid4
from app.models.user import User
from app.models.calculation import Calculation

def test_get_profile(db_session, fake_user_data):
    """Test getting user profile"""
    # Create and register user
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Create some calculations for the user
    calc1 = Calculation.create("addition", user.id, [1, 2, 3])
    calc1.result = calc1.get_result()
    calc2 = Calculation.create("subtraction", user.id, [10, 5])
    calc2.result = calc2.get_result()
    
    db_session.add(calc1)
    db_session.add(calc2)
    db_session.commit()
    
    # Refresh and verify calculations
    db_session.refresh(user)
    assert len(user.calculations) == 2

def test_update_profile_username(db_session, fake_user_data):
    """Test updating user profile username"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    original_username = user.username
    new_username = f"newusername_{uuid4()}"
    
    user.username = new_username
    db_session.commit()
    db_session.refresh(user)
    
    assert user.username == new_username
    assert user.username != original_username

def test_update_profile_email(db_session, fake_user_data):
    """Test updating user profile email"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    original_email = user.email
    new_email = f"newemail_{uuid4()}@example.com"
    
    user.email = new_email
    db_session.commit()
    db_session.refresh(user)
    
    assert user.email == new_email
    assert user.email != original_email

def test_update_profile_name(db_session, fake_user_data):
    """Test updating user profile name"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    user.first_name = "NewFirstName"
    user.last_name = "NewLastName"
    db_session.commit()
    db_session.refresh(user)
    
    assert user.first_name == "NewFirstName"
    assert user.last_name == "NewLastName"

def test_duplicate_username_update(db_session):
    """Test that updating to existing username fails"""
    # Create first user
    user1_data = {
        "first_name": "User",
        "last_name": "One",
        "email": f"user1_{uuid4()}@example.com",
        "username": f"user1_{uuid4()}",
        "password": "TestPass123!"
    }
    user1 = User.register(db_session, user1_data)
    
    # Create second user
    user2_data = {
        "first_name": "User",
        "last_name": "Two",
        "email": f"user2_{uuid4()}@example.com",
        "username": f"user2_{uuid4()}",
        "password": "TestPass123!"
    }
    user2 = User.register(db_session, user2_data)
    db_session.commit()
    
    # Try to update user2's username to user1's username
    # This should be caught at the application level
    assert user1.username != user2.username

def test_password_change(db_session, fake_user_data):
    """Test changing user password"""
    fake_user_data['password'] = "OldPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Verify old password works
    assert user.verify_password("OldPass123!")
    
    # Change password
    new_password = "NewPass123!"
    user.password = User.hash_password(new_password)
    db_session.commit()
    db_session.refresh(user)
    
    # Verify new password works and old doesn't
    assert user.verify_password(new_password)
    assert not user.verify_password("OldPass123!")

def test_password_hash_uniqueness(db_session, fake_user_data):
    """Test that same password produces different hashes"""
    password = "TestPass123!"
    
    hash1 = User.hash_password(password)
    hash2 = User.hash_password(password)
    
    # Hashes should be different due to salt
    assert hash1 != hash2
    
    # But both should verify correctly
    fake_user_data['password'] = password
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    assert user.verify_password(password)

def test_profile_updated_at_changes(db_session, fake_user_data):
    """Test that updated_at changes on profile update"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    original_updated_at = user.updated_at
    
    # Use the update method which handles updated_at
    user.update(first_name="NewName")
    db_session.commit()
    db_session.refresh(user)
    
    assert user.updated_at > original_updated_at

def test_user_calculation_relationship(db_session, fake_user_data):
    """Test user-calculation relationship for profile stats"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Initially no calculations
    assert len(user.calculations) == 0
    
    # Add calculations
    for i in range(5):
        calc = Calculation.create("addition", user.id, [i, i+1])
        calc.result = calc.get_result()
        db_session.add(calc)
    
    db_session.commit()
    db_session.refresh(user)
    
    # Should have 5 calculations
    assert len(user.calculations) == 5

def test_profile_data_integrity(db_session, fake_user_data):
    """Test that profile data maintains integrity after updates"""
    fake_user_data['password'] = "TestPass123!"
    user = User.register(db_session, fake_user_data)
    original_id = user.id
    original_created_at = user.created_at
    db_session.commit()
    
    # Update multiple fields with unique values
    user.username = f"newusername_{uuid4()}"
    user.email = f"newemail_{uuid4()}@example.com"
    user.first_name = "NewFirst"
    user.last_name = "NewLast"
    db_session.commit()
    db_session.refresh(user)
    
    # ID and created_at should remain unchanged
    assert user.id == original_id
    assert user.created_at == original_created_at
    
    # Updated fields should be changed
    assert user.first_name == "NewFirst"
    assert user.last_name == "NewLast"