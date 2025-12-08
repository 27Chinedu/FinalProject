from datetime import datetime
from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.schemas.user import UserResponse
from app.models.user import User
from jose import jwt, JWTError
from app.core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

def get_current_user(
        
    token: str = Depends(oauth2_scheme)
) -> UserResponse:
    """
    Dependency to get the current user from the JWT token without a database lookup.
    This function decodes the JWT token directly to extract user information.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decode the JWT token directly
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        
        # Check if we have a full user payload with username
        # Note: The token must contain ALL these fields to use the full payload path
        if all(key in payload for key in ["id", "username", "email", "first_name", "last_name", 
                                          "is_active", "is_verified", "created_at", "updated_at"]):
            # Full payload - use all the fields
            return UserResponse(
                id=UUID(payload["id"]),
                username=payload["username"],
                email=payload["email"],
                first_name=payload["first_name"],
                last_name=payload["last_name"],
                is_active=payload["is_active"],
                is_verified=payload["is_verified"],
                created_at=datetime.fromisoformat(payload["created_at"]),
                updated_at=datetime.fromisoformat(payload["updated_at"])
            )
        
        # Minimal payload - only has 'sub' field
        sub = payload.get("sub")
        if sub is None:
            raise credentials_exception
        
        # Create a minimal UserResponse with just the ID
        return UserResponse(
            id=UUID(sub),
            username="unknown",
            email="unknown@example.com",
            first_name="Unknown",
            last_name="User",
            is_active=True,
            is_verified=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
    except (JWTError, ValueError, KeyError) as e:
        raise credentials_exception
    
def get_current_active_user(
    current_user: UserResponse = Depends(get_current_user)
) -> UserResponse:
    """
    Dependency to ensure that the current user is active.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user