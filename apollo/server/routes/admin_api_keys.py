import datetime
from math import ceil
from typing import Optional

from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi_pagination import Params
from fastapi_pagination.ext.tortoise import paginate

from apollo.db import APIKey, User
from apollo.server.utils import templates, admin_user_scheme
from apollo.server.auth import generate_api_key, get_api_key_prefix
from common.logger import Logger

router = APIRouter(tags=["non-api"])


@router.get("/", response_class=HTMLResponse)
async def admin_api_keys(request: Request, params: Params = Depends()):
    user = request.state.user
    params.size = 50
    api_keys = await paginate(
        APIKey.filter(user_id=user.id).order_by("-created_at"),
        params=params,
    )

    return templates.TemplateResponse(
        "admin_api_keys.jinja", {
            "request": request,
            "api_keys": api_keys,
            "api_keys_pages": ceil(api_keys.total / api_keys.size),
        }
    )


@router.get("/new", response_class=HTMLResponse)
async def admin_api_key_new(request: Request):
    return templates.TemplateResponse(
        "admin_api_key_new.jinja", {
            "request": request,
        }
    )


@router.post("/new", response_class=HTMLResponse)
async def admin_api_key_new_post(request: Request):
    user = request.state.user
    
    form_data = await request.form()
    
    name = form_data.get("name", "")
    expires_days = form_data.get("expires_days")
    if expires_days:
        try:
            expires_days = int(expires_days)
        except ValueError:
            expires_days = None
    else:
        expires_days = None
    
    # For checkboxes, check if the key exists in form_data
    workflow_trigger = "workflow_trigger" in form_data
    workflow_status = "workflow_status" in form_data
    
    if not name or len(name) < 2:
        return templates.TemplateResponse(
            "admin_api_key_new.jinja", {
                "request": request,
                "error": "Name must be at least 2 characters long",
                "name": name,
                "expires_days": expires_days,
                "workflow_trigger": workflow_trigger,
                "workflow_status": workflow_status,
            }
        )

    # Build permissions list
    permissions = []
    if workflow_trigger:
        permissions.append("workflow:trigger")
    if workflow_status:
        permissions.append("workflow:status")
    
    if not permissions:
        return templates.TemplateResponse(
            "admin_api_key_new.jinja", {
                "request": request,
                "error": "At least one permission must be selected",
                "name": name,
                "expires_days": expires_days,
                "workflow_trigger": workflow_trigger,
                "workflow_status": workflow_status,
            }
        )

    try:
        # Generate API key
        raw_key, key_hash = generate_api_key()
        key_prefix = get_api_key_prefix(raw_key)
        
        # Calculate expiration
        expires_at = None
        if expires_days and expires_days > 0:
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=expires_days)
        
        # Create API key record
        api_key = await APIKey.create(
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            user_id=user.id,
            permissions=permissions,
            expires_at=expires_at
        )
        
        logger = Logger()
        logger.info(f"User {user.email} created API key '{name}' with permissions {permissions}")
        
        return templates.TemplateResponse(
            "admin_api_key_new.jinja", {
                "request": request,
                "success": True,
                "api_key": raw_key,
                "key_info": api_key,
            }
        )
        
    except Exception as e:
        logger = Logger()
        logger.error(f"Error creating API key: {str(e)}")
        return templates.TemplateResponse(
            "admin_api_key_new.jinja", {
                "request": request,
                "error": "Failed to create API key. Please try again.",
                "name": name,
                "expires_days": expires_days,
                "workflow_trigger": workflow_trigger,
                "workflow_status": workflow_status,
            }
        )


@router.post("/{key_id}/revoke", response_class=HTMLResponse)
async def admin_api_key_revoke(request: Request, key_id: int):
    user = request.state.user
    
    api_key = await APIKey.get_or_none(id=key_id, user_id=user.id)
    if not api_key:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"API key with id {key_id} not found",
            }
        )
    
    if api_key.revoked_at:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": "API key is already revoked",
            }
        )
    
    # Revoke the key
    api_key.revoked_at = datetime.datetime.now(datetime.timezone.utc)
    await api_key.save()
    
    logger = Logger()
    logger.info(f"User {user.email} revoked API key '{api_key.name}' (ID: {key_id})")
    
    return RedirectResponse("/admin/api-keys", status_code=302)


@router.post("/{key_id}/delete", response_class=HTMLResponse)
async def admin_api_key_delete(request: Request, key_id: int):
    user = request.state.user
    
    api_key = await APIKey.get_or_none(id=key_id, user_id=user.id)
    if not api_key:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"API key with id {key_id} not found",
            }
        )
    
    logger = Logger()
    logger.info(f"User {user.email} deleted API key '{api_key.name}' (ID: {key_id})")
    
    await api_key.delete()
    
    return RedirectResponse("/admin/api-keys", status_code=302)