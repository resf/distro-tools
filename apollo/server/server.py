import secrets

from tortoise import Tortoise

Tortoise.init_models(["apollo.db"], "models")  # noqa # pylint: disable=wrong-import-position

from fastapi import FastAPI, Request, Depends
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi_pagination import add_pagination

from apollo.server.routes.advisories import router as advisories_router
from apollo.server.routes.statistics import router as statistics_router
from apollo.server.routes.login import router as login_router
from apollo.server.routes.logout import router as logout_router
from apollo.server.routes.profile import router as profile_router
from apollo.server.routes.admin_index import router as admin_index_router
from apollo.server.routes.admin_users import router as admin_users_router
from apollo.server.routes.red_hat_advisories import router as red_hat_advisories_router
from apollo.server.routes.api_advisories import router as api_advisories_router
from apollo.server.routes.api_updateinfo import router as api_updateinfo_router
from apollo.server.routes.api_red_hat import router as api_red_hat_router
from apollo.server.routes.api_compat import router as api_compat_router
from apollo.server.routes.api_osv import router as api_osv_router
from apollo.server.routes.api_workflows import router as api_workflows_router
from apollo.server.settings import SECRET_KEY, SettingsMiddleware, get_setting
from apollo.server.utils import admin_user_scheme, user_scheme, templates
from apollo.db import Settings

from common.info import Info
from common.logger import Logger
from common.database import Database
from common.temporal import Temporal
from common.fastapi import StaticFilesSym, RenderErrorTemplateException

app = FastAPI()

# Global Temporal client instance
temporal_client = None

app.mount(
    "/static",
    StaticFilesSym(directory="apollo/server/static"),
    name="static",
)
app.mount(
    "/assets",
    StaticFilesSym(directory="apollo/server/assets"),
    name="assets",
)

app.add_middleware(SettingsMiddleware)

app.include_router(advisories_router)
app.include_router(statistics_router, prefix="/statistics")
app.include_router(login_router, prefix="/login")
app.include_router(logout_router, prefix="/logout")
app.include_router(
    profile_router,
    prefix="/profile",
    dependencies=[Depends(user_scheme)],
)
app.include_router(
    admin_index_router,
    prefix="/admin",
    dependencies=[Depends(admin_user_scheme)]
)
app.include_router(
    admin_users_router,
    prefix="/admin/users",
    dependencies=[Depends(admin_user_scheme)]
)
app.include_router(red_hat_advisories_router, prefix="/red_hat")
app.include_router(api_advisories_router, prefix="/api/v3/advisories")
app.include_router(api_updateinfo_router, prefix="/api/v3/updateinfo")
app.include_router(api_red_hat_router, prefix="/api/v3/red_hat")
app.include_router(api_compat_router, prefix="/v2/advisories")
app.include_router(api_osv_router, prefix="/api/v3/osv")
app.include_router(api_workflows_router, prefix="/api/v3/workflows")

Info("apollo2")
Logger()
Database(True, app, ["apollo.db"])


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Peridot Apollo",
        version="0.1.0",
        description="Apollo Errata Management",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://apollo.build.resf.org/assets/pd-logo-np.svg"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

add_pagination(app)


@app.get("/_/healthz")
async def health():
    return {"status": "ok"}


@app.get("/_/set_color")
async def set_color(request: Request):
    valid_colors = ["dark", "light"]
    color = request.query_params.get("color")
    response = RedirectResponse(
        request.headers["referer"] if "referer" in request.headers else "/"
    )

    # First check if the color is valid
    # If valid, set the color in the cookie, then
    # redirect back to referrer
    if color in valid_colors:
        response.set_cookie("color", color)

    return response


@app.exception_handler(404)
async def not_found_handler(request, exc):  # pylint: disable=unused-argument
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
    global temporal_client
    
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
    
    # Initialize Temporal client for workflow management
    temporal = Temporal(True)
    await temporal.connect()
    temporal_client = temporal


@app.on_event("shutdown")
async def shutdown():
    global temporal_client
    # Close Temporal client connection if it exists
    if temporal_client and temporal_client.client:
        await temporal_client.client.close()
