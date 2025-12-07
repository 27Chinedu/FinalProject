# app/auth/redis.py
# This is optional for token blacklisting
# For now, we'll create stub functions that don't require Redis

async def add_to_blacklist(jti: str, exp: int):
    """Add a token's JTI to the blacklist (stub implementation)"""
    # TODO: Implement with Redis if needed
    pass

async def is_blacklisted(jti: str) -> bool:
    """Check if a token's JTI is blacklisted (stub implementation)"""
    # TODO: Implement with Redis if needed
    return False