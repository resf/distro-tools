from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from tortoise.expressions import Q

from apollo.server.utils import templates
from apollo.server.roles import ADMIN
from apollo.server.utils import pwd_context
from apollo.server.settings import OIDC_PROVIDER_NAME, OIDC_PROVIDER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET
from apollo.db import User, Settings

router = APIRouter(tags=["non-api"])


@router.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=302)

    user_count = await User.all().count()
    should_show_setup = user_count == 0

    ctx = {
        "request": request,
        "should_show_setup": should_show_setup,
    }
    if not should_show_setup:
        # Check if we have OIDC_PROVIDER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET set
        # If so, show the OIDC login button
        # If OIDC_PROVIDER_NAME is set, use that as the button text
        # Otherwise, use "Login with OIDC"
        settings = await Settings.filter(
            Q(name=OIDC_PROVIDER_NAME) | Q(name=OIDC_PROVIDER) |
            Q(name=OIDC_CLIENT_ID) | Q(name=OIDC_CLIENT_SECRET)
        ).all()
        if len(settings) >= 3:
            provider_name = "Login with OIDC"
            # Check if we have OIDC_PROVIDER_NAME set
            for setting in settings:
                if setting.name == OIDC_PROVIDER_NAME:
                    provider_name = setting.value
                    break
            ctx["oidc_provider_name"] = provider_name

    return templates.TemplateResponse("login.jinja", ctx)


@router.post("/", response_class=HTMLResponse)
async def do_login(
    request: Request,
    email: str = Form(default=None),
    password: str = Form(default=None)
):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=302)
    if not email or not password:
        return templates.TemplateResponse(
            "login.jinja", {
                "request": request,
                "error": "Email and password are required",
            }
        )

    user = await User.get(email=email)
    if not user:
        return templates.TemplateResponse(
            "login.jinja", {
                "request": request,
                "error": "Invalid email or password",
            }
        )

    if not pwd_context.verify(password, user.password):
        return templates.TemplateResponse(
            "login.jinja", {
                "request": request,
                "error": "Invalid email or password",
            }
        )

    request.session["user"] = user.id
    request.session["user.name"] = user.name
    request.session["user.role"] = user.role
    return RedirectResponse("/", status_code=302)


@router.post(
    "/setup",
    response_class=HTMLResponse,
)
async def setup_page(
    request: Request,
    name: str = Form(default=None),
    email: str = Form(default=None),
    password: str = Form(default=None),
    confirm_password: str = Form(default=None),
):
    user_count = await User.all().count()
    if user_count > 0:
        return RedirectResponse("/")

    error = None
    if not name:
        error = "Name is required"
    elif not email:
        error = "Email is required"
    elif "@" not in email:
        error = "Email is invalid"
    elif not password:
        error = "Password is required"
    elif not confirm_password:
        error = "Confirm password is required"
    elif password != confirm_password:
        error = "Passwords do not match"

    if error:
        return templates.TemplateResponse(
            "login.jinja", {
                "request": request,
                "should_show_setup": True,
                "error": error,
            }
        )

    await User.create(
        name=name, email=email, password=pwd_context.hash(password), role=ADMIN
    )
    return templates.TemplateResponse(
        "login.jinja", {
            "request": request,
            "should_show_setup_success": True,
        }
    )
