from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

router = APIRouter(tags=["non-api"])


@router.get("/")
async def logout(request: Request):
    if request.session.get("user"):
        request.session.pop("user")
    if request.session.get("user.name"):
        request.session.pop("user.name")
    if request.session.get("user.role"):
        request.session.pop("user.role")

    return RedirectResponse("/", status_code=302)
