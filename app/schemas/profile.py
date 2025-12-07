# app/schemas/profile.py

from typing import Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict, model_validator

class ProfileUpdate(BaseModel):
    """Schema for updating user profile information"""
    username: Optional[str] = Field(
        None,
        min_length=3,
        max_length=50,
        example="newusername",
        description="New username (optional)"
    )
    email: Optional[EmailStr] = Field(
        None,
        example="newemail@example.com",
        description="New email address (optional)"
    )
    first_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=50,
        example="John",
        description="New first name (optional)"
    )
    last_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=50,
        example="Doe",
        description="New last name (optional)"
    )

    @model_validator(mode='after')
    def validate_at_least_one_field(self) -> "ProfileUpdate":
        """Ensure at least one field is being updated"""
        if not any([self.username, self.email, self.first_name, self.last_name]):
            raise ValueError("At least one field must be provided for update")
        return self

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "newusername",
                "email": "newemail@example.com",
                "first_name": "Jane",
                "last_name": "Smith"
            }
        }
    )

class PasswordChange(BaseModel):
    """Schema for changing user password"""
    current_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        example="OldPass123!",
        description="Current password for verification"
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        example="NewPass123!",
        description="New password"
    )
    confirm_new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        example="NewPass123!",
        description="Confirm new password"
    )

    @model_validator(mode='after')
    def verify_passwords(self) -> "PasswordChange":
        """Verify that new password and confirmation match"""
        if self.new_password != self.confirm_new_password:
            raise ValueError("New password and confirmation do not match")
        if self.current_password == self.new_password:
            raise ValueError("New password must be different from current password")
        return self

    @model_validator(mode='after')
    def validate_password_strength(self) -> "PasswordChange":
        """Validate new password strength requirements"""
        password = self.new_password
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(char.isupper() for char in password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(char.islower() for char in password):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(char.isdigit() for char in password):
            raise ValueError("Password must contain at least one digit")
        if not any(char in "!@#$%^&*()_+-=[]{}|;:,.<>?" for char in password):
            raise ValueError("Password must contain at least one special character")
        return self

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "current_password": "OldPass123!",
                "new_password": "NewPass123!",
                "confirm_new_password": "NewPass123!"
            }
        }
    )

class ProfileResponse(BaseModel):
    """Schema for profile response"""
    id: UUID
    username: str
    email: EmailStr
    first_name: str
    last_name: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    calculation_count: int = Field(default=0, description="Total number of calculations")

    model_config = ConfigDict(from_attributes=True)

class PasswordChangeResponse(BaseModel):
    """Schema for password change response"""
    message: str = Field(..., description="Success message")
    updated_at: datetime = Field(..., description="Time when password was updated")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Password successfully updated",
                "updated_at": "2025-01-01T00:00:00"
            }
        }
    )