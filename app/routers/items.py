from typing import Annotated
from fastapi import (
    HTTPException,
    Query,
    Path,
    status,
    Depends,
    APIRouter,
)
from pydantic import BaseModel

# import with relative package path
from ..utils import verify_dummy_token
from ..utils import CommonsQueryParamsDep
from .auth import oauth2_password_scheme

from ..schemas import Item
from ..db import items_db, next_item_id

router = APIRouter(
    prefix="/items",
    tags=["items"],
    # dependency injection
    dependencies=[],
    responses={404: {"description": "Not Found"}},
)


# response_model is useful to specify a return schema in openapi doc
# a pydantic model can be declared in openapi when a database dict data
# object is the actual json body
# this is useful when the return type is not exactly the model class
@router.get(
    "/",
    # openapi operation_id
    operation_id="read_items",
    # if summary is not given, summary will be created from method name
    summary="get list of items",
    status_code=status.HTTP_200_OK,
    response_model=list[Item],
    # use dependencies=[..] to inject token verification
    dependencies=[Depends(verify_dummy_token)],
)
async def read_items(
    # q: str | None = None,
    q: Annotated[str | None, Query(max_length=50)],
    limit: int = 10,
    offset: int = 0,
):
    if q:
        # todo: filter logic
        pass
    return items_db[offset : offset + limit]


# v2:
# - use common query params
# - specify response model
# - dependency inject token verification by Annotated
@router.get("/v2/", status_code=status.HTTP_200_OK, response_model=list[Item])
async def read_items_v2(
    commons: CommonsQueryParamsDep, token: Annotated[str, Depends(verify_dummy_token)]
):
    return items_db[commons.offset : commons.offset + commons.limit]


# v3:
# - dependency inject oauth2 jwt token validation
@router.get("/v3/", status_code=status.HTTP_200_OK, response_model=list[Item])
async def read_items_v3(
    commons: CommonsQueryParamsDep,
    token: Annotated[str, Depends(oauth2_password_scheme)],
):
    return items_db[commons.offset : commons.offset + commons.limit]


# use type hint for input data validation
@router.get("/{item_id}", status_code=status.HTTP_200_OK, response_model=Item)
async def read_item(
    # item_id: int,
    item_id: int = Path(title="The ID of the item to get", ge=1),
    code: str = None,
    q: str | None = None,
):
    return {"item_id": item_id, "q": q, "code": code}


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=Item,
)
async def create_item(item: Item):
    item_dict = item.dict()
    item_dict["id"] = next_item_id()
    items_db.append(item_dict)
    return item_dict


@router.put(
    "/{item_id}",
    status_code=status.HTTP_200_OK,
    response_model=Item,
    dependencies=[Depends(verify_dummy_token)],
)
async def update_item(item_id: int, item: Item):
    try:
        db_item = next(itm for itm in items_db if itm["id"] == item_id)
    except StopIteration:
        db_item = None
    if db_item is None:
        raise HTTPException(status_code=400, detail="invalid item id")
    item_dict = item.dict()
    if item_dict.get("id") and item_dict["id"] != item_id:
        raise HTTPException(status_code=400, detail="invalid item id in body")

    db_item.update(item_dict)
    return db_item
