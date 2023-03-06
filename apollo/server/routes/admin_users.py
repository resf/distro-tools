import secrets
from math import ceil

from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi_pagination import Params
from fastapi_pagination.ext.tortoise import paginate

from apollo.db import User
from apollo.server import roles
from apollo.server.utils import templates, pwd_context

router = APIRouter(tags=["non-api"])


def validate_user(request: Request, user: User):
    if user.role not in roles.POSSIBLE_ROLES:
        return templates.TemplateResponse(
            "admin_user_new.jinja", {
                "request": request,
                "should_hide_form": True,
                "error": f"Invalid role {user.role}",
            }
        )

    if not user.name or len(user.name) < 2:
        return templates.TemplateResponse(
            "admin_user_new.jinja", {
                "request": request,
                "should_hide_form": True,
                "error": "Name is too short",
            }
        )

    if not user.email or len(user.email) < 3 or "@" not in user.email:
        return templates.TemplateResponse(
            "admin_user_new.jinja", {
                "request": request,
                "should_hide_form": True,
                "error": "Invalid email",
            }
        )


@router.get("/", response_class=HTMLResponse)
async def admin_users(request: Request, params: Params = Depends()):
    params.size = 50
    users = await paginate(
        User.all().order_by("created_at"),
        params=params,
    )

    return templates.TemplateResponse(
        "admin_users.jinja", {
            "request": request,
            "users": users,
            "users_pages": ceil(users.total / users.size),
        }
    )


@router.get("/new", response_class=HTMLResponse)
async def admin_user_new(request: Request):
    return templates.TemplateResponse(
        "admin_user_new.jinja", {
            "request": request,
        }
    )


@router.post("/new", response_class=HTMLResponse)
async def admin_user_new_post(
    request: Request,
    name: str = Form(default=None),
    email: str = Form(default=None),
    role: str = Form(default=None),
):
    user = User(name=name, email=email, role=role)
    validation = validate_user(request, user)
    if validation:
        return validation

    random_password = secrets.token_urlsafe(16)
    user.password = pwd_context.hash(random_password)

    await user.save()

    return templates.TemplateResponse(
        "admin_user_new.jinja", {
            "request": request,
            "should_hide_form": True,
            "gen_password": random_password,
            "email": email,
        }
    )


@router.get("/{user_id}", response_class=HTMLResponse)
async def admin_user(request: Request, user_id: int):
    user = await User.get_or_none(id=user_id)
    if user is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"User with id {user_id} not found",
            }
        )

    return templates.TemplateResponse(
        "admin_user.jinja", {
            "request": request,
            "user": user,
        }
    )


@router.post("/{user_id}", response_class=HTMLResponse)
async def admin_user_post(
    request: Request,
    user_id: int,
    name: str = Form(default=None),
    email: str = Form(default=None),
    role: str = Form(default=None),
):
    user = await User.get_or_none(id=user_id)
    if user is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"User with id {user_id} not found",
            }
        )

    user.name = name
    user.email = email
    user.role = role

    validation = validate_user(request, user)
    if validation:
        return validation

    await user.save()

    return templates.TemplateResponse(
        "admin_user.jinja", {
            "request": request,
            "user": user,
            "title": "Successfully updated user",
            "kind": "success",
        }
    )


@router.post("/{user_id}/password", response_class=HTMLResponse)
async def admin_user_password_post(
    request: Request,
    user_id: int,
    new_password: str = Form(default=None),
    confirm_password: str = Form(default=None),
):
    user = await User.get_or_none(id=user_id)
    if user is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"User with id {user_id} not found",
            }
        )

    if new_password != confirm_password:
        return templates.TemplateResponse(
            "admin_user.jinja", {
                "request": request,
                "user": user,
                "title": "Passwords do not match",
                "kind": "error",
            }
        )

    if not new_password or len(new_password) < 8:
        return templates.TemplateResponse(
            "admin_user.jinja", {
                "request": request,
                "user": user,
                "title": "Password is too short",
                "kind": "error",
            }
        )

    user.password = pwd_context.hash(new_password)
    await user.save()

    return templates.TemplateResponse(
        "admin_user.jinja", {
            "request": request,
            "user": user,
            "title": "Successfully updated password",
            "kind": "success",
        }
    )


@router.post("/{user_id}/delete", response_class=HTMLResponse)
async def admin_user_delete(request: Request, user_id: int):
    user = await User.get_or_none(id=user_id)
    if user is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"User with id {user_id} not found",
            }
        )

    # Cannot delete yourself
    if user.id == request.state.user.id:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": "Cannot delete yourself",
            }
        )

    # Cannot delete admins
    if user.role == "admin":
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": "Cannot delete admin users",
            }
        )

    await user.delete()

    return RedirectResponse("/admin/users", status_code=302)
