from typing import Optional
from dataclasses import dataclass

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from apollo.db import Settings
from apollo.server.utils import is_admin_user

SECRET_KEY = "secret-key"
OIDC_PROVIDER_NAME = "oidc-provider-name"
OIDC_PROVIDER = "oidc-provider"
OIDC_CLIENT_ID = "oidc-client-id"
OIDC_CLIENT_SECRET = "oidc-client-secret"
OIDC_ADMIN_ROLE = "oidc-admin-role"
OIDC_ELEVATED_ROLE = "oidc-elevated-role"
RH_MATCH_STALE = "rh-match-stale"
DISABLE_SERVING_RH_ADVISORIES = "disable-serving-rh-advisories"
UI_URL = "ui-url"
COMPANY_NAME = "company-name"
MANAGING_EDITOR = "managing-editor"


async def get_setting(name: str) -> Optional[str]:
    setting = await Settings.filter(name=name).get_or_none()
    if setting is None:
        return None
    return setting.value


async def get_setting_bool(name: str) -> Optional[bool]:
    setting = await Settings.filter(name=name).get_or_none()
    if setting is None:
        return None
    return setting.value == "True"


async def should_serve_red_hat_advisories(request: Request) -> bool:
    setting = await get_setting_bool(DISABLE_SERVING_RH_ADVISORIES)
    admin_user = await is_admin_user(request)

    if setting and not admin_user:
        return False

    return True


@dataclass
class SettingsContext:
    serve_rh_advisories: bool
    is_admin: bool


class SettingsMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        should_serve_rh_advisories = await should_serve_red_hat_advisories(
            request
        )

        request.state.settings = SettingsContext(
            serve_rh_advisories=should_serve_rh_advisories,
            is_admin=await is_admin_user(request),
        )

        return await call_next(request)
