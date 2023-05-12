from fastapi import APIRouter, Depends, HTTPException, status

from .oauth2 import get_current_active_user

from .. import schemas

from ..models import User

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[],
)


@router.get("/me", response_model=schemas.UserRead)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user
