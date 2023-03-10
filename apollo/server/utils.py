from fastapi import Request
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext

from apollo.db import User
from apollo.server.roles import ADMIN

from common.fastapi import RenderErrorTemplateException

# Do not remove import (for gazelle)
import jinja2  # noqa # pylint: disable=unused-import
import multipart  # noqa # pylint: disable=unused-import
import itsdangerous  # noqa # pylint: disable=unused-import

templates = Jinja2Templates(directory="apollo/server/templates")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def admin_user_scheme(request: Request) -> User:
    user = await user_scheme(request, raise_exc=False)
    if not user:
        raise RenderErrorTemplateException(
            "You need to log in to access this page",
            status_code=401,
        )
    elif user.role != ADMIN:
        raise RenderErrorTemplateException(
            "You are not authorized to view this page",
            status_code=403,
        )
    return user


async def user_scheme(request: Request, raise_exc=True) -> User:
    user_id = request.session.get("user")
    if not user_id:
        if raise_exc:
            raise RenderErrorTemplateException(
                "You need to log in to access this page",
                status_code=401,
            )
        else:
            return None
    user = await User.get(id=user_id)
    request.state.user = user
    return user


async def is_admin_user(request: Request) -> bool:
    user = await user_scheme(request, raise_exc=False)
    return user.role == ADMIN if user else False
