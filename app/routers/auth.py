from typing import Annotated
from datetime import timedelta

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi import Request
from fastapi import Form
from fastapi.responses import RedirectResponse
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

from pydantic import BaseModel

from jose import jwt

from ..schemas import Token

from ..db import fake_users_db
from ..db import get_user

from ..utils import verify_password
from ..utils import create_access_token
from ..utils import decode_access_token
from ..utils import create_auth_code
from ..utils import decode_auth_code
from ..utils import create_jwk

ACCESS_TOKEN_EXPIRE_MINUTES = 30

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    dependencies=[],
)


#
# password grant flow and endpoints
#


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


# this is oauth2 token endpoint for password grant type
# it expects a form with user password credentials
# by OAuth2 spec, the response of the token endpoint
# - must be a JSON object
# - should have a `token_type` key
# - should have a `access_token` key
@router.post("/token_by_password", response_model=Token)
async def token_by_password(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)]
):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires_delta
    )
    return {"access_token": access_token, "token_type": "bearer"}


#
# code grant flow and endpoints
# Ref: https://datatracker.ietf.org/doc/html/rfc6749#page-24
#

OAUTH2_AUTHZ_URL = "http://localhost:8000/auth/authorize"
OAUTH2_TOKEN_URL = "http://localhost:8000/auth/token_by_code"
# by oauth2 specs, issuer should be authorization server token endpoint url
ISSUER = OAUTH2_TOKEN_URL

# client application id and secret
# this pair should be registered along with its associated users (if any)
# in authorization server database
# todo: replace this hard-coded pair with database records
CLIENT_ID = "client-app"
CLIENT_SECRET = "secret"

# permission scopes that user (resource owner) can grant the client application
# during the authorization grant stage
CLIENT_SCOPES = {
    "openid": "openid scope",
    "profile": "profile scope",
    "email": "email scope",
}

# a code grant authorize request is like:
# https://authorization-server.com/oauth/authorize
# ?response_type=code
# &client_id=a17c21ed
# &state=5ca75bd30
# &redirect_uri=https%3A%2F%2Fexample-app.com%2Fauth
# &scope=read
#

# By OAuth2 spec, authorize endpoint should at least support http GET.
# The authorization endpoint requires the user to be authenticated with
# a specific IdP, in this example, the IdP is the application itself.
#
# The user is typically redirected to IdP's login url.
#
# OAuth2 doesn't specify how the IdP authenticates the user.
# Usually the IdP should have some sort of web form to receive and validate
# user credentials.
#

# since IdP is this example app itself, the login url is local
IDP_LOGIN_URL = "/auth/login"


@router.get("/authorize")
async def authorize_code_grant(request: Request):
    # expecting required params keys from request
    params = request.query_params
    if params.get("response_type") != "code":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect grant type",
        )

    # todo: check client_id
    client_id = params.get("client_id")
    print(client_id)
    # todo: check redirect_uri registered with this client_id
    redirect_uri = params.get("redirect_uri")
    print(redirect_uri)
    # todo: check scope if given
    scope = params.get("scope")
    # todo: check state if given
    state = params.get("state")

    # all checks ok, redirect to IdP's authentication url for user authentication
    # in this example, it is the local login form web page
    redirect_url = f"{IDP_LOGIN_URL}?client_id={params.get('client_id')}&redirect_uri={redirect_uri}"
    if scope:
        redirect_url += f"&scope={scope}"
    if state:
        redirect_url += f"&state={state}"

    return RedirectResponse(url=redirect_url)


# this is the form for user to put credentials in order to grant the client
# application access to resource service
@router.get("/login", response_class=HTMLResponse)
async def get_login_grant(req: Request):
    print("redirected to login page:", req.url)
    # convert query params to a python dict
    # this is not always a good practice when there are multiple parameters
    # with same name, but in this OAuth2 login case, it is safe
    params = dict(req.query_params)
    print("query_params:", params)
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <title>User Login and Grant</title>
</head>
<body>
  <h1>Login and Grant</h1>
  <form method="post" action="{IDP_LOGIN_URL}">
    <label for="username">Username:</label>
    <input type="text" name="username" id="username">
    <br>
    <label for="password">Password:</label>
    <input type="password" name="password" id="password">
    <br>
    <label for="grant">Access Token Grant:</label>
    <input type="checkbox" name="user_grant" id="user_grant">
    <br>
    <input type="submit" value="Log In">
    <br>
    <input type="hidden" name="redirect_uri" id="redirect_uri" value="{params.get('redirect_uri')}">
    <input type="hidden" name="client_id" id="client_id" value="{params.get('client_id')}">
    <input type="hidden" name="scope" id="scope" value="{params.get('scope') or ''}">
    <input type="hidden" name="state" id="state" value="{params.get('state') or ''}">
  </form>
</body>
</html>
    """
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)


@router.post("/login")
async def post_login_grant(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    user_grant: bool | None = Form(None),
    scope: str | None = Form(None),
    state: str | None = Form(None),
):
    # check user credentials from form data
    user = authenticate_user(fake_users_db, username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # todo: validate client_id, throw 401 if invalid

    # usually the redirect_url is known to authorization server (this app)
    # this redirect_url should be registered at service provider setup
    # for this client
    # in this example, the client application and authorization server are
    # the same one (this app)
    # the redirect_url should be validated with known list as well
    # todo: validate redirect_uri with this specific client_id
    print(f"redirect_uri: {redirect_uri}")
    print(f"client_id: {client_id}")

    # todo: optional PKCE challenge validation

    # todo: validate state if given, this requires server-side session
    print(f"state: {state}")

    # check grant
    print(f"user_grant: {user_grant}")
    if not user_grant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing user grant",
        )

    # todo: validate and grant scope from the request
    print(f"scope: {scope}")

    # when all validations pass, generate authorization code
    # by OAuth2 specs, authorization_code should be short-lived, with
    # expiration window of several minutes
    # and the code should be associated to the user, the resource owner
    # it is usually saved in database FK'ed to user table
    # authorization code is mainly dependent on:
    # - client_id
    # - user_id
    # - redirect_uri
    # - approved scopes, aka authorized_scopes
    # - expiration time
    auth_code = create_auth_code(
        {
            "username": username,
            "client_id": client_id,
        },
        expires_minutes=5,
    )

    # following OAuth2 specs, redirect response to the given redirect_uri
    # with generated code
    redirect_url = redirect_uri + "?code=" + auth_code

    if scope:
        redirect_url += f"&scope={scope}"

    if state:
        redirect_url += f"&state={state}"

    # by default, FastAPI use status code 307 for redirect, which will keep
    # the original http method, in this case a POST
    # to change the redirect from POST to GET, set status_code to 303
    # ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/303
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


# a typical request to exchange authorization_code for token is like:
# https://authorization-server.com/oauth/token
#  &grant_type=authorization_code
#   &client_id=xxxxx
#   &client_secret=zzzzzzz
#   &code=yyyyyyy
#   &redirect_uri=https//your-web-app.com/redirect


# client authentication is required when exchange code for token
# there are multiple options to supply client credentials
# in this example, client_secret is provided in POST body
class OAuth2CodeGrantTokenRequestForm(BaseModel):
    # in code grant flow, response_type must be 'code'
    grant_type: str = "authorization_code"
    client_id: str
    client_secret: str
    code: str
    redirect_uri: str
    scope: str = ""
    state: str = None


# this is oauth2 callback token endpoint
# it expects a form with authorization code in exchange for an access token
# this endpoint usually should be `/token`
@router.post("/token_by_code", response_model=Token)
async def token_by_code(
    grant_type: Annotated[str, Form()],
    code: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    client_secret: Annotated[str, Form()],
    scope: str | None = Form(None),
    state: str | None = Form(None),
):
    # async def token_by_code(req: Request):
    #     async with req.form() as frm:
    #         for k, v in frm.items():
    #             print(k, v)

    if grant_type != "authorization_code":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect grant_type",
        )

    # todo: validate client_id and client_secret
    # client_id and client_secret should be provided by
    # - HTTP Basic Auth header
    # - OR, form-encoded POST body
    print(f">> client_id: {client_id}")
    print(f">> client_secret: {client_secret}")

    # todo: validate authorization code
    print(f">> auth_code: {code}")
    try:
        code_data = decode_auth_code(code)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization code signature has expired",
        )
    print(f">> auth_code payload: {code_data}")
    if "client_id" in code_data and client_id != code_data["client_id"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization code has invalid client",
        )

    # todo: validate state if given, this requires a server-side session,
    #   which keeps the original state value from previous authorization code
    #   request on `/authorize` endpoint
    # todo: generate jwt Bearer token

    access_token_expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # initialize token data with issuer and audience claims
    # By JWT, "iss" identifies the principal that issued the JWT,
    # in OAuth2, issuer is usually the `/token` endpoint url.
    # By JWT, "aud" identifies the receiver of the JWT,
    # in OAuth2 specs, audience claim must match the client_id
    # of the registered application
    token_data = {"iss": ISSUER, "aud": CLIENT_ID}

    # todo: get subject (aka resource owner) user id
    #   this is usually by looking up auth code and client_id
    # in our simplified case, since we encoded username in the auth_code
    # we can avoid database lookup
    if "username" in code_data:
        token_data["sub"] = code_data["username"]

    if scope:
        token_data["scope"] = scope

    # todo: if scope contains "openid", add id token claims
    # todo: if scope contains "profile", add required claims
    # todo: if scope contains "email", add email claim

    # todo: add additional custom claim k-vs if any

    access_token = create_access_token(
        data=token_data, expires_delta=access_token_expires_delta
    )

    # todo: add scope property
    token_resp = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": access_token_expires_delta.seconds,
    }
    return JSONResponse(content=token_resp)


# example:
# OAuth2 specs defined userinfo endpoint is secured by token from code grant
#

from fastapi.security import OAuth2AuthorizationCodeBearer

oauth2_code_schema = OAuth2AuthorizationCodeBearer(
    authorizationUrl=OAUTH2_AUTHZ_URL,
    tokenUrl=OAUTH2_TOKEN_URL,
    scopes=CLIENT_SCOPES,
)


@router.post("/userinfo")
async def get_userinfo(token: Annotated[str, Depends(oauth2_code_schema)]):
    print("token:", token)
    # decode access Bearer token and retrieve user info
    payload = decode_access_token(token, audience=CLIENT_ID)
    return {"endpoint": "userinfo", "token": token, "payload": payload}


@router.get(
    "/jwks", operation_id="get_jwks", summary="get JWK Set", response_class=JSONResponse
)
async def get_jwks():
    jwk_dict = create_jwk()
    return {"keys": [jwk_dict]}


# By OAuth2 specs, authorization server should provide an endpoint to
# register a client application.
# When registering the redirect_uri for the client, its string value should be
# validated that it must not contain uri fragment (the part with a leading
# hash `#`, ref: https://en.wikipedia.org/wiki/URI_fragment).
#
# Also, the redirect_uri for a registered client should not be changed (at least
# not often) between authorization requests.
# If the client wants to carry request specific data, such data should be
# encoded in the `state` parameter instead, or use the `state` parameter as
# a session id to store the custom data on the client application datastore.
@router.post("/register_client")
async def register_client():
    raise NotImplemented()
