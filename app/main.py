import os
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from .routers import auth, users, idp
from .db_migration import init_db

app = FastAPI(
    dependencies=[],
    title="Example OAuth 2 Provider Service with FastAPI",
    description="Main components: OpanAPI doc v3, JWT with RS256, OAuth 2.0 grant flows with federated user authentication with IdP login, Sqlalchemy",
    version="0.1",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*",
        # "http://127.0.0.1:8000",  # allow local (/docs) swagger-ui
    ],
    # allow cookies for cross-origin requests, when allow_credentials is set
    # True, allow_origins can not be set to ["*"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {
        "app": {
            "title": app.title,
            "description": app.description,
            "version": app.version,
        }
    }


# for kubernetes pod health check, give 200 status code with minimal payload
@app.get("/health", status_code=status.HTTP_200_OK)
async def read_health():
    return {"status": "up"}


app.include_router(auth.router)
app.include_router(idp.router)
app.include_router(users.router)


# initialize database if enabled
if os.environ.get("RESET_DB"):
    print(">> database reset enabled")
    init_db()
