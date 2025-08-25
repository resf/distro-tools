"""
API endpoints for API key management
"""
import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from apollo.db import APIKey, User
from apollo.server.utils import admin_user_scheme
from apollo.server.auth import generate_api_key, get_api_key_prefix
from common.logger import Logger

router = APIRouter(tags=["api-keys"])


class APIKeyCreateRequest(BaseModel):
    name: str
    permissions: List[str] = ["workflow:trigger", "workflow:status"]
    expires_days: Optional[int] = None  # None = never expires


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str  # Only show prefix for security
    permissions: List[str]
    created_at: datetime.datetime
    expires_at: Optional[datetime.datetime]
    last_used_at: Optional[datetime.datetime]
    revoked_at: Optional[datetime.datetime]

    class Config:
        orm_mode = True


class APIKeyCreateResponse(BaseModel):
    """Response when creating a new API key - includes the actual key"""
    api_key: str  # The actual key - only shown once!
    key_info: APIKeyResponse


class APIKeyListResponse(BaseModel):
    api_keys: List[APIKeyResponse]
    total_count: int


@router.post("/", response_model=APIKeyCreateResponse)
async def create_api_key(
    request: APIKeyCreateRequest,
    user: User = Depends(admin_user_scheme)
):
    """
    Create a new API key (admin only).
    The actual key is only returned once - store it securely!
    """
    try:
        # Generate API key
        raw_key, key_hash = generate_api_key()
        key_prefix = get_api_key_prefix(raw_key)
        
        # Calculate expiration
        expires_at = None
        if request.expires_days:
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=request.expires_days)
        
        # Create API key record
        api_key = await APIKey.create(
            name=request.name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            user_id=user.id,
            permissions=request.permissions,
            expires_at=expires_at
        )
        
        logger = Logger()
        logger.info(f"User {user.email} created API key '{request.name}' with permissions {request.permissions}")
        
        # Return response with actual key (only time it's shown)
        return APIKeyCreateResponse(
            api_key=raw_key,
            key_info=APIKeyResponse(
                id=api_key.id,
                name=api_key.name,
                key_prefix=api_key.key_prefix,
                permissions=api_key.permissions,
                created_at=api_key.created_at,
                expires_at=api_key.expires_at,
                last_used_at=api_key.last_used_at,
                revoked_at=api_key.revoked_at
            )
        )
        
    except Exception as e:
        logger = Logger()
        logger.error(f"Error creating API key: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )


@router.get("/", response_model=APIKeyListResponse)
async def list_api_keys(
    user: User = Depends(admin_user_scheme)
):
    """
    List all API keys for the current user (admin only).
    Actual keys are never returned - only metadata.
    """
    try:
        api_keys = await APIKey.filter(user_id=user.id).order_by("-created_at").all()
        
        return APIKeyListResponse(
            api_keys=[
                APIKeyResponse(
                    id=key.id,
                    name=key.name,
                    key_prefix=key.key_prefix,
                    permissions=key.permissions,
                    created_at=key.created_at,
                    expires_at=key.expires_at,
                    last_used_at=key.last_used_at,
                    revoked_at=key.revoked_at
                )
                for key in api_keys
            ],
            total_count=len(api_keys)
        )
        
    except Exception as e:
        logger = Logger()
        logger.error(f"Error listing API keys: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list API keys"
        )


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: int,
    user: User = Depends(admin_user_scheme)
):
    """
    Revoke an API key (admin only).
    Only the owner can revoke their own keys.
    """
    try:
        api_key = await APIKey.get_or_none(id=key_id, user_id=user.id)
        
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        if api_key.revoked_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="API key is already revoked"
            )
        
        # Revoke the key
        api_key.revoked_at = datetime.datetime.now(datetime.timezone.utc)
        await api_key.save()
        
        logger = Logger()
        logger.info(f"User {user.email} revoked API key '{api_key.name}' (ID: {key_id})")
        
        return {"message": f"API key '{api_key.name}' has been revoked"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger = Logger()
        logger.error(f"Error revoking API key {key_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key"
        )


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: int,
    user: User = Depends(admin_user_scheme)
):
    """
    Get details about a specific API key (admin only).
    Only the owner can view their own keys.
    """
    try:
        api_key = await APIKey.get_or_none(id=key_id, user_id=user.id)
        
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        return APIKeyResponse(
            id=api_key.id,
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            permissions=api_key.permissions,
            created_at=api_key.created_at,
            expires_at=api_key.expires_at,
            last_used_at=api_key.last_used_at,
            revoked_at=api_key.revoked_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger = Logger()
        logger.error(f"Error getting API key {key_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get API key"
        )