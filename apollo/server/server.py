import secrets

from tortoise import Tortoise

Tortoise.init_models(["apollo.db"], "models")  # noqa # pylint: disable=wrong-import-position

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi_pagination import add_pagination

from apollo.server.routes.advisories import router as advisories_router
from apollo.server.routes.statistics import router as statistics_router
from apollo.server.routes.login import router as login_router
from apollo.server.routes.logout import router as logout_router
from apollo.server.routes.admin_index import router as admin_index_router
from apollo.server.routes.api_advisories import router as api_advisories_router
from apollo.server.routes.api_updateinfo import router as api_updateinfo_router
from apollo.server.routes.api_red_hat import router as api_red_hat_router
from apollo.server.routes.api_compat import router as api_compat_router
from apollo.server.routes.red_hat_advisories import router as red_hat_advisories_router
from apollo.server.settings import SECRET_KEY, SettingsMiddleware, get_setting
from apollo.server.utils import admin_user_scheme, templates
from apollo.db import Settings

from common.info import Info
from common.logger import Logger
from common.database import Database
from common.fastapi import StaticFilesSym, RenderErrorTemplateException

app = FastAPI()

app.mount(
    "/static", StaticFilesSym(directory="apollo/server/static"), name="static"
)
app.mount(
    "/assets", StaticFilesSym(directory="apollo/server/assets"), name="assets"
)

app.add_middleware(SettingsMiddleware)

app.include_router(advisories_router)
app.include_router(statistics_router, prefix="/statistics")
app.include_router(login_router, prefix="/login")
app.include_router(logout_router, prefix="/logout")
app.include_router(
    admin_index_router,
    prefix="/admin",
    dependencies=[Depends(admin_user_scheme)]
)
app.include_router(red_hat_advisories_router, prefix="/red_hat")
app.include_router(api_advisories_router, prefix="/api/v3/advisories")
app.include_router(api_updateinfo_router, prefix="/api/v3/updateinfo")
app.include_router(api_red_hat_router, prefix="/api/v3/red_hat")
app.include_router(api_compat_router, prefix="/v2/advisories")

add_pagination(app)

Info("apollo2")
Logger()
Database(True, app, ["apollo.db"])


@app.get("/_/healthz")
async def health():
    return {"status": "ok"}


@app.exception_handler(404)
async def not_found_handler(request, exc):
    if request.url.path.startswith("/api"
                                  ) or request.url.path.startswith("/v2"):
        return JSONResponse({"error": "Not found"}, status_code=404)
    return await render_template_exception_handler(request, None)


@app.exception_handler(RenderErrorTemplateException)
async def render_template_exception_handler(
    request: Request, exc: RenderErrorTemplateException
):
    if request.url.path.startswith("/api"
                                  ) or request.url.path.startswith("/v2"):
        return JSONResponse(
            {"error": exc.msg if exc and exc.msg else "Not found"},
            status_code=exc.status_code if exc and exc.status_code else 404,
        )
    return templates.TemplateResponse(
        "error.jinja", {
            "request": request,
            "message": exc.msg if exc and exc.msg else "Page not found",
        },
        status_code=exc.status_code if exc and exc.status_code else 404
    )


@app.on_event("startup")
async def startup():
    # Generate secret-key if it does not exist in the database
    secret_key = await get_setting(SECRET_KEY)
    if not secret_key:
        # Generate random secret key
        secret_key = secrets.token_hex(32)
        await Settings.create(name=SECRET_KEY, value=secret_key)

    # Mount SessionMiddleware
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key,
        max_age=60 * 60 * 24 * 7,  # 1 week
    )
