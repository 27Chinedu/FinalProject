# tests/unit/test_redis.py

import pytest
from app.auth.redis import add_to_blacklist, is_blacklisted

@pytest.mark.asyncio
async def test_add_to_blacklist():
    """Test add_to_blacklist stub function"""
    # Should not raise any errors
    await add_to_blacklist("test_jti", 3600)
    # Stub function returns None
    result = await add_to_blacklist("test_jti_2", 7200)
    assert result is None

@pytest.mark.asyncio
async def test_is_blacklisted():
    """Test is_blacklisted stub function"""
    # Should always return False (stub implementation)
    result = await is_blacklisted("any_jti")
    assert result is False
    
    result2 = await is_blacklisted("another_jti")
    assert result2 is False

@pytest.mark.asyncio
async def test_blacklist_flow():
    """Test the flow of adding and checking blacklist"""
    jti = "test_flow_jti"
    
    # Add to blacklist
    await add_to_blacklist(jti, 3600)
    
    # Check if blacklisted (stub always returns False)
    is_blocked = await is_blacklisted(jti)
    assert is_blocked is False