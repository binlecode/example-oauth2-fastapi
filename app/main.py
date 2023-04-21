from typing import Annotated
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status

from .schemas import Token
from .routers import auth, items, users, idp

app = FastAPI(
    dependencies=[],
    title="OAuth 2 Provider with FastAPI OpenAPI doc",
    version="0.0.1",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # "*",
        "http://127.0.0.1:8000",  # allow local (/docs) swagger-ui
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
app.include_router(idp.router)
app.include_router(items.router)
app.include_router(users.router)


#
# database and initial data load
#

# create database tables
import os
from datetime import datetime
from .db import engine, Base

if os.environ.get("RESET_DB"):
    print(">> database reset enabled")

    print(">> sqlalchemy create or add tables")
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    # load a couple of initial users
    # todo: move this to a data load script
    from .db import SessionLocal
    from .db import User, Item, OAuth2Client

    session = SessionLocal()

    u1 = User(
        username="johndoe",
        full_name="John Doe",
        email="johndoe@example.com",
        # plain pswd: "secret"
        hashed_password="$2b$12$mV7rTpEAAk77POssNFkBfO.F0UvhU5Z2llYTbu3RcS8s8C3S2hNUC",
    )
    u2 = User(
        username="alice",
        full_name="Alice Wonderson",
        email="alice@example.com",
        # plain pswd: "secret2"
        hashed_password="$2b$12$Th16FzsG7bexKod7DpgKZORxIpoV1E8hu0Xh/jZOhM2hAJV03HKCu",
    )
    session.add_all([u1, u2])
    session.commit()
    # now u1 and u2 have id after commit
    session.add_all(
        [
            Item(title="Foo", owner=u1),
            Item(title="Bar", owner=u1),
            Item(title="Baz", owner=u2),
        ]
    )
    session.commit()

    # add oauth2 clients
    oc1 = OAuth2Client(
        client_id="swagger",
        client_secret="secret",
        client_id_issued_at=datetime.utcnow(),
    )
    oc1.set_client_metadata(
        {
            "client_name": "swagger",
            "client_uri": "http://localhost",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["http://127.0.0.1:8000/docs/oauth2-redirect"],
            "response_types": ["code"],
            "scope": "profile openid email",
            "token_endpoint_auth_method": ["client_secret_basic"],
        }
    )
    oc2 = OAuth2Client(
        client_id="postman",
        client_secret="secret",
        client_id_issued_at=datetime.utcnow(),
    )
    oc2.set_client_metadata(
        {
            "client_name": "postman",
            "client_uri": "http://localhost",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["https://oauth.pstmn.io/v1/callback"],
            "response_types": ["code"],
            "scope": "profile openid email",
            "token_endpoint_auth_method": ["client_secret_basic"],
        }
    )
    session.add_all([oc1, oc2])
    session.commit()
