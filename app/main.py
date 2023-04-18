from typing import Annotated
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.security import OAuth2PasswordRequestForm

from .schemas import Token
from .routers import auth, items, users

app = FastAPI(
    dependencies=[],
    title="Test FastAPI OpenAPI doc",
    version="0.0.1",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:8080",
    ],
    # allow cookies for cross-origin requests, when allow_credentials is set
    # True, allow_origins can not be set to ["*"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"hello": "fastapi!"}


@app.get("/async")
async def read_root_async():
    return {"hello": "fastapi async!"}


app.include_router(auth.router)
app.include_router(items.router)
app.include_router(users.router)
