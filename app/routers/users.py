from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from jose import JWTError, jwt

from .auth import oauth2_password_scheme
from ..utils import decode_access_token

from ..schemas import TokenData
from ..schemas import User, UserInDB

from ..db import fake_users_db
from ..db import get_user
from ..db import SessionLocal

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[],
)


# by OAuth2 spec,
# any HTTP error status 401 is supposed to also return a `WWW-Authenticate` header
# in our case (Bearer token), the value should be set to "Bearer"
async def get_current_user(token: Annotated[str, Depends(oauth2_password_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    db = SessionLocal()
    user = db.query(User).filter(User.username == token_data.username).first()
    # user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    print(f">> current user: {current_user}")
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )
    return current_user


# build a dependency chain
# get_current_active_user < get_current_user < fake_decode_token_to_user
@router.get("/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user
