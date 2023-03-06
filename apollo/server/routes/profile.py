from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from apollo.server.utils import templates, pwd_context

router = APIRouter(tags=["non-api"])


@router.get("/", response_class=HTMLResponse)
async def profile(request: Request):
    return templates.TemplateResponse("profile.jinja", {
        "request": request,
    })


@router.post("/", response_class=HTMLResponse)
async def profile_post(
    request: Request,
    current_password: str = Form(default=None),
    new_password: str = Form(default=None),
    confirm_password: str = Form(default=None),
):
    if not current_password or not new_password or not confirm_password:
        return templates.TemplateResponse(
            "profile.jinja", {
                "request": request,
                "notification":
                    {
                        "kind": "error",
                        "title": "Please fill out all fields",
                    }
            }
        )

    actual_current_password = request.state.user.password
    if not pwd_context.verify(current_password, actual_current_password):
        return templates.TemplateResponse(
            "profile.jinja", {
                "request": request,
                "notification":
                    {
                        "kind": "error",
                        "title": "Current password is incorrect",
                    }
            }
        )

    if new_password != confirm_password:
        return templates.TemplateResponse(
            "profile.jinja", {
                "request": request,
                "notification":
                    {
                        "kind": "error",
                        "title": "New passwords do not match",
                    }
            }
        )

    if len(new_password) < 8:
        return templates.TemplateResponse(
            "profile.jinja", {
                "request": request,
                "notification":
                    {
                        "kind": "error",
                        "title": "New password must be at least 8 characters",
                    }
            }
        )

    request.state.user.password = pwd_context.hash(new_password)
    await request.state.user.save()

    return templates.TemplateResponse(
        "profile.jinja", {
            "request": request,
            "notification": {
                "kind": "success",
                "title": "Password updated",
            }
        }
    )
