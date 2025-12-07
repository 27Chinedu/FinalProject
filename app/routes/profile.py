# app/routes/profile.py

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database import get_db
from app.models.user import User
from app.auth.dependencies import get_current_active_user
from app.schemas.profile import (
    ProfileUpdate,
    PasswordChange,
    ProfileResponse,
    PasswordChangeResponse
)
from app.schemas.user import UserResponse

router = APIRouter(prefix="/profile", tags=["profile"])

@router.get("/me", response_model=ProfileResponse)
def get_current_user_profile(
    current_user: UserResponse = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get the current user's profile information.
    
    Returns profile data including calculation count.
    """
    # Get the actual user from database to access relationships
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Count user's calculations
    calculation_count = len(user.calculations) if user.calculations else 0
    
    return ProfileResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login=user.last_login,
        calculation_count=calculation_count
    )

@router.put("/me", response_model=ProfileResponse)
def update_current_user_profile(
    profile_update: ProfileUpdate,
    current_user: UserResponse = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Update the current user's profile information.
    
    Users can update their username, email, first name, and last name.
    At least one field must be provided.
    """
    # Get the actual user from database
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check if username or email is being changed to an existing value
    if profile_update.username or profile_update.email:
        # Build query to check for duplicates
        duplicate_check = db.query(User).filter(
            User.id != current_user.id  # Exclude current user
        )
        
        conditions = []
        if profile_update.username:
            conditions.append(User.username == profile_update.username)
        if profile_update.email:
            conditions.append(User.email == profile_update.email)
        
        if conditions:
            duplicate_check = duplicate_check.filter(or_(*conditions))
            existing_user = duplicate_check.first()
            
            if existing_user:
                if existing_user.username == profile_update.username:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Username already taken"
                    )
                if existing_user.email == profile_update.email:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email already in use"
                    )
    
    # Update fields that were provided
    if profile_update.username is not None:
        user.username = profile_update.username
    if profile_update.email is not None:
        user.email = profile_update.email
    if profile_update.first_name is not None:
        user.first_name = profile_update.first_name
    if profile_update.last_name is not None:
        user.last_name = profile_update.last_name
    
    # Update timestamp
    user.updated_at = datetime.now(timezone.utc)
    
    try:
        db.commit()
        db.refresh(user)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update profile: {str(e)}"
        )
    
    # Count calculations for response
    calculation_count = len(user.calculations) if user.calculations else 0
    
    return ProfileResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login=user.last_login,
        calculation_count=calculation_count
    )

@router.post("/change-password", response_model=PasswordChangeResponse)
def change_password(
    password_change: PasswordChange,
    current_user: UserResponse = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Change the current user's password.
    
    Requires current password for verification.
    New password must meet strength requirements.
    """
    # Get the actual user from database
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Verify current password
    if not user.verify_password(password_change.current_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )
    
    # Hash and set new password
    user.password = User.hash_password(password_change.new_password)
    user.updated_at = datetime.now(timezone.utc)
    
    try:
        db.commit()
        db.refresh(user)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to change password: {str(e)}"
        )
    
    return PasswordChangeResponse(
        message="Password successfully updated",
        updated_at=user.updated_at
    )