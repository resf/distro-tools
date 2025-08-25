"""
API Key authentication utilities
"""
import secrets
import hashlib
import datetime
from typing import Optional

from fastapi import Request, HTTPException, status
from passlib.context import CryptContext

from apollo.db import APIKey, User
from apollo.server.roles import ADMIN
from common.fastapi import RenderErrorTemplateException

# Context for hashing API keys
api_key_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def generate_api_key() -> tuple[str, str]:
    """
    Generate a new API key and return (raw_key, key_hash)
    
    Returns:
        tuple: (raw_api_key, hashed_key_for_db)
    """
    # Generate random key: apollo_sk_ + 32 random chars
    raw_key = f"apollo_sk_{secrets.token_urlsafe(32)}"
    key_hash = api_key_context.hash(raw_key)
    return raw_key, key_hash


def get_api_key_prefix(raw_key: str) -> str:
    """Extract prefix for identification (first 12 chars after apollo_sk_)"""
    if raw_key.startswith("apollo_sk_"):
        return raw_key[:22]  # apollo_sk_ + first 12 chars
    return raw_key[:16]


async def verify_api_key(raw_key: str) -> Optional[APIKey]:
    """
    Verify an API key and return the APIKey model if valid
    
    Args:
        raw_key: The raw API key from the request
        
    Returns:
        APIKey model if valid, None if invalid
    """
    if not raw_key or not raw_key.startswith("apollo_sk_"):
        return None
    
    # Get prefix for faster lookup
    prefix = get_api_key_prefix(raw_key)
    
    # Find potential matching keys
    api_keys = await APIKey.filter(
        key_prefix=prefix,
        revoked_at__isnull=True
    ).prefetch_related("user").all()
    
    # Check each key (should only be one, but hash verification needed)
    for api_key in api_keys:
        if api_key_context.verify(raw_key, api_key.key_hash):
            # Check if expired
            if api_key.expires_at and api_key.expires_at < datetime.datetime.now(datetime.timezone.utc):
                continue
                
            # Update last used timestamp
            api_key.last_used_at = datetime.datetime.now(datetime.timezone.utc)
            await api_key.save()
            
            return api_key
    
    return None


async def api_key_auth(request: Request, required_permission: str = None) -> User:
    """
    FastAPI dependency for API key authentication
    
    Args:
        request: FastAPI request object
        required_permission: Permission required (e.g., "workflow:trigger")
        
    Returns:
        User object if authenticated
        
    Raises:
        HTTPException: If authentication fails
    """
    # Extract API key from Authorization header
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Use: Authorization: Bearer apollo_sk_..."
        )
    
    raw_key = auth_header.replace("Bearer ", "")
    api_key = await verify_api_key(raw_key)
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Check permissions if required
    if required_permission:
        if required_permission not in api_key.permissions and "*" not in api_key.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key does not have required permission: {required_permission}"
            )
    
    return api_key.user


async def workflow_api_key_auth(request: Request) -> User:
    """Specific dependency for workflow endpoints requiring workflow permissions"""
    return await api_key_auth(request, "workflow:trigger")


async def api_key_or_session_auth(request: Request) -> User:
    """
    Allow either API key or session authentication
    Useful for endpoints that need to work with both web UI and API access
    """
    # Try API key first
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer apollo_sk_"):
        return await api_key_auth(request)
    
    # Fall back to session auth (existing admin_user_scheme)
    from apollo.server.utils import admin_user_scheme
    return await admin_user_scheme(request)