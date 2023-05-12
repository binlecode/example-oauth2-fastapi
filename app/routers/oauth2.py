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

from sqlalchemy.orm import Session

from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError

# import schemas level only, to force each pydantic model to be used as
# schemas.model, this is to avoid confusion with orm entity models
from .. import schemas
from ..db import SessionLocal
from ..models import User, OAuth2Client

from ..security import verify_password
from ..security import create_access_token
from ..security import decode_access_token
from ..security import create_auth_code
from ..security import decode_auth_code
from ..security import create_jwk
from config import Config

from .oauth2_schemes import oauth2_password_scheme
from .oauth2_schemes import oauth2_code_schema
from .oauth2_schemes import oauth2_implicit_scheme


router = APIRouter(
    # prefix="/auth",
    prefix=Config.OAUTH2_ROUTE_PREFIX,
    tags=["oauth2"],
    dependencies=[],
)


# OAuth 2.0 standardizes authorization, and delegates user (resource owner)
# authentication.
# The user authentication is typically implemented in a user identity provider
# (IdP). This IdP can be local or remote 3rd party, depending on where the
# user information is managed.

# IdP authentication form url.
# In this example a 3rd party IdP is simulated by a different route in the
# same web app, but it can be from any domain
# this url should contain absolute path as it can be from any domain.
# IDP_LOGIN_URL = "http://127.0.0.1:8000/identity/login"
IDP_LOGIN_URL = Config.IDP_LOGIN_URL
print(f">> Authorization server uses IdP user authentication URL: {IDP_LOGIN_URL}")


# Authorization server callback url is used to receive authentication response
# from the authentication server, aka IdP.
# The response should be a POST redirect to protect the content in the body.
# This url MUST contain absolute path because it is passed as a request
# parameter to the IdP authentication server as the callback redirect url for
# the authentication response.
# AUTHORIZATION_CALLBACK_URL = "http://127.0.0.1:8000/auth/authorization_callback"
AUTHORIZATION_CALLBACK_URL = Config.OAUTH2_AUTHORIZATION_CALLBACK_URL


# Grant form url, this is the url for user to grant the client application
# with the requested scopes for the access token.
# This is a local endpoint of the authorization server.
# AUTHORIZATION_GRANT_URL = "/auth/form_grant"
AUTHORIZATION_GRANT_URL = Config.OAUTH2_AUTHORIZATION_GRANT_URL

# access_token should always be short-lived
# ACCESS_TOKEN_EXPIRE_MINUTES = 30
ACCESS_TOKEN_EXPIRE_MINUTES = Config.OAUTH2_ACCESS_TOKEN_EXPIRE_MINUTES

# in code grant flow, authorization code should be really short-lived
AUTHORIZATION_CODE_EXPIRE_MINUTES = Config.OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES

# define OpenAPI security schemes to secure service endpoints
#
OAUTH2_AUTHZ_URL = Config.OAUTH2_AUTHORIZATION_CALLBACK_URL
OAUTH2_TOKEN_URL = Config.OAUTH2_TOKEN_URL
# by oauth2 specs, issuer should be authorization server token endpoint url
ISSUER = OAUTH2_TOKEN_URL
# permission scopes that user (resource owner) can grant the client application
# during the authorization grant stage
CLIENT_SCOPES = Config.OAUTH2_CLIENT_SCOPES


@router.get("/test_implicit_grant_resource")
async def test_implicit_grant_resource(
    token: Annotated[str, Depends(oauth2_implicit_scheme)]
):
    return JSONResponse(content={"implicit token": token})


@router.get("/test_code_grant_resource")
async def test_code_grant_resource(token: Annotated[str, Depends(oauth2_code_schema)]):
    return JSONResponse(content={"code grant token": token})


@router.get("/test_password_grant_resource")
async def test_password_grant_resource(
    token: Annotated[str, Depends(oauth2_password_scheme)]
):
    return JSONResponse(content={"password grant token": token})


#
# /authorize endpoint
# supports:
# - code grant: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
# - implicit grant: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
#
# By OAuth2 spec, authorize endpoint should at least support http GET.
# The authorization server delegates the user authentication to IdP.
# - authorization endpoint redirects the user to IdP user login url
# - if login successful, IdP redirects response back to authorization server's
#   callback url
# - authorization server callback endpoint receives this federated user identity
#   confirmation, and redirects to token scope grant web form
# - if grant approved, authorization server generates authorization code
#   (if code grant) or access_token (if implicit grant) and redirects
#   response back to client application's callback uri (the redirect_uri
#   value in the original client application request)
#
# a typical code grant /authorize endpoint request is like:
# https://authorization-server.com/oauth/authorize
# ?response_type=code
# &client_id=a17c21ed
# &state=5ca75bd30
# &redirect_uri=https%3A%2F%2Fexample-app.com%2Fauth
# &scope=openid%20read
#
# a typical implicit grant authorize request is like:
# https://authorization-server.com/oauth/authorize
#  ?response_type=token
#  &client_id=2935291028237423
#  &redirect_uri=https%3A%2F%2Fexample-app.com%2Fcallback
#  &scope=create+delete
#  &state=xcoiv98y3md22vwsuye3kch
#


@router.get(Config.OAUTH2_AUTHORIZATION_PATH)
async def authorize(request: Request):
    params = dict(request.query_params)
    # check response_type, aka the grant type
    response_type = request.query_params.get("response_type")
    if response_type not in ["code", "token"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect grant type",
        )

    # check client_id
    db = SessionLocal()
    client_id = params.get("client_id")
    client = db.query(OAuth2Client).filter(OAuth2Client.client_id == client_id).first()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect client",
        )
    print(f"found client: {client_id}")

    # check scope
    scope = params.get("scope") or ""
    scope_items = scope.strip().split(" ")
    print(f"requested scope: {scope_items}")
    client_scope = client.scope or ""
    client_scope_items = client_scope.split(" ")
    print(f"client supported scope: {client_scope_items}")
    if not set(scope_items).issubset(client_scope_items):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect scope",
        )

    # check redirect_uri in the request
    # it should be within the list of request_uris during client registration
    redirect_uri = params.get("redirect_uri")
    print(f"requested redirect_uri: {redirect_uri}")
    client_redirect_uris = client.redirect_uris
    print(f"client supported redirect_uris: {client_redirect_uris}")
    if redirect_uri not in client_redirect_uris:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect redirect_uri",
        )

    # if above checks are ok
    # todo: check if user if already authenticated
    # delegate user authentication if user is not authenticated yet

    # redirect to IdP's user authentication url
    idp_url = f"{IDP_LOGIN_URL}?client_id={params.get('client_id')}&redirect_uri={redirect_uri}"
    idp_url += f"&response_type={response_type}"
    idp_url += f"&scope={scope}"
    state = params.get("state") or ""
    idp_url += f"&state={state}"

    # add authorization server callback url
    # the authentication response should be redirected to this callback
    # endpoint for authorization server to continue with user grant web form
    idp_url += f"&authorization_callback_uri={AUTHORIZATION_CALLBACK_URL}"

    # redirects to IdP's authentication web url
    return RedirectResponse(url=idp_url)


#
# oauth2 /token endpoint
# support following grant types:
# - grant_type == "authorization_code"
# - grant_type == "password"
# - todo: support client_credentials
# it expects a form as POST body
#
# a typical request to exchange authorization_code for token is like:
# https://authorization-server.com/oauth/token
#  &grant_type=authorization_code
#   &client_id=xxxxx
#   &client_secret=zzzzzzz
#   &code=yyyyyyy
#   &redirect_uri=https//your-web-app.com/redirect
#
# client authentication is required when exchange code for token
# there are three options to supply client credentials:
# - in POST body, either form or JSON serialized
# - in http basic auth header
# - none
#
# by OAuth2 spec, the response of the token endpoint:
# - must be a JSON object
# - must have `token_type` key, almost always "Bearer"
# - must have `access_token` key to hold token content string
# - should have `expires_in` key with value in seconds
#
@router.post(Config.OAUTH2_TOKEN_PATH, response_class=JSONResponse)
async def token_by_grant_type(
    grant_type: str = Form(),
    # for code grant token request
    code: str | None = Form(None),
    # for password grant token request
    username: str | None = Form(None),
    password: str | None = Form(None),
    #
    redirect_uri: str | None = Form(None),
    # client credentials
    client_id: str = Form(),
    client_secret: str = Form(),
    scope: str | None = Form(None),
    state: str | None = Form(None),
):
    if grant_type == "authorization_code":
        token_response = await build_token_by_code(
            code=code,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            state=state,
        )
    elif grant_type == "password":
        token_response = await build_token_by_password(
            username=username,
            password=password,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            state=state,
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Incorrect grant_type: {grant_type}",
        )

    return JSONResponse(content=token_response)


async def build_token_by_password(
    username: str,
    password: str,
    client_id: str,
    client_secret: str,
    scope: str | None,
    state: str | None,
):
    user = authenticate_user(SessionLocal(), username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # todo: validate client credentials
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect client",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # db = SessionLocal()
    # client = db.query(OAuth2Client).filter(OAuth2Client.client_id == client_id).first()

    token_data = {"iss": ISSUER, "sub": user.username}
    if scope:
        token_data["scope"] = scope

    access_token_expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=token_data,
        expires_delta=access_token_expires_delta,
    )
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": access_token_expires_delta.seconds,
    }


async def build_token_by_code(
    code: str,
    client_id: str,
    client_secret: str,
    scope: str | None,
    state: str | None,
):
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

    # validate client_id in auth code payload
    if client_id != code_data["client_id"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization code has invalid client",
        )

    # todo: validate scope if given
    #   usually for code grant across multiple redirects between authz server
    #   and IdP, the original requested scopes should be persistent with the
    #   the duration of the lifespan of the authorization code, which is
    #   usually saved in database along with the authorization code
    # at the moment for simplicity, the scope value is included in code payload
    # instead of saved in db, this will increase the content size of the code
    if not scope and code_data.get("scope"):
        scope = code_data["scope"]

    # todo: validate state if given, this requires a server-side session,
    #   which keeps the original state value from previous authorization code
    #   request on `/authorize` endpoint

    # initialize token data with issuer and audience claims
    # By JWT, "iss" identifies the principal that issued the JWT,
    # in OAuth2, issuer is usually the `/token` endpoint url.
    # By JWT, "aud" identifies the receiver of the JWT,
    # in OAuth2 specs, audience claim must match the client_id
    # of the registered application
    token_data = {"iss": ISSUER, "aud": client_id}

    # todo: get subject (aka resource owner) user id
    #   this is usually by looking up auth code and client_id
    # in our simplified case, since we encoded username in the auth_code
    # we can avoid database lookup
    if "username" in code_data:
        token_data["sub"] = code_data["username"]

    if scope:
        token_data["scope"] = scope

    # todo: add additional custom claim k-vs if any

    access_token_expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=token_data, expires_delta=access_token_expires_delta
    )

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": access_token_expires_delta.seconds,
    }


# OAuth2 jwks endpoint
@router.get(
    Config.OAUTH2_JWKS_PATH,
    operation_id="get_jwks",
    summary="get JWK Set",
    response_class=JSONResponse,
)
async def jwks():
    jwk_dict = create_jwk()
    return {"keys": [jwk_dict]}


# authentication method used by user password grant
def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    print(f"authenticate user: {user}")
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


# common token retrieval interceptor dependency function
# it tries all supported security schemes to get the access token
# in order to do that, multiple token variables are defined, each one binds
# to a specific grant flow
async def get_request_token(
    token_by_password: str = Depends(oauth2_password_scheme),
    token_by_code: str = Depends(oauth2_code_schema),
    token_by_implicit: str = Depends(oauth2_implicit_scheme),
):
    try:
        # get token from any of the supported grant schemes
        token = token_by_password or token_by_code or token_by_implicit
        token_payload = decode_access_token(token)
        return token_payload
    except JWTError as e:
        err_desc = str(e)
        # give auth error info by OAuth 2 specs
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={
                "WWW-Authenticate": f'error="invalid_token", error_description="{err_desc}"'
            },
        )


async def get_current_user(payload: dict = Depends(get_request_token)):
    # By OAuth2 spec, any HTTP error status 401 is supposed to also return a
    # `WWW-Authenticate` header.
    # In our case (Bearer token), the value should be set to "Bearer".
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
    token_data = schemas.TokenData(username=username)
    db = SessionLocal()
    user = db.query(User).filter(User.username == token_data.username).first()
    # user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


# build a dependency chain
# get_current_active_user < get_current_user < fake_decode_token_to_user
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )
    return current_user


# OAuth 2 delegated user authentication response call back endpoint
# This callback endpoint receives IdP user authentication response,
# which is a redirect POST to this callback endpoint.
# Authorization server will check the authentication response, then
# redirect to grant web form for user to grant token scope.
@router.post(Config.OAUTH2_AUTHORIZATION_CALLBACK_PATH)
async def authorization_callback(
    username: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    scope: str | None = Form(None),
    state: str | None = Form(None),
    response_type: str | None = Form(None),
):
    # todo: validate state if given, this requires server-side session
    print(f">> grant_callback POST >> state: {state}")
    # todo: validate client_id
    # the redirect_url should be validated with known list as well
    # todo: validate redirect_uri with this specific client_id
    print(f"redirect_uri: {redirect_uri}")
    print(f"client_id: {client_id}")
    # todo: optional PKCE challenge validation

    # if all good, redirect (GET) to grant web form
    grant_redirect_url = (
        AUTHORIZATION_GRANT_URL + f"?response_type={response_type or ''}"
    )
    grant_redirect_url += f"&client_id={client_id}"
    grant_redirect_url += f"&username={username}"
    grant_redirect_url += f"&scope={scope}"
    grant_redirect_url += f"&state={state}"
    grant_redirect_url += f"&redirect_uri={redirect_uri}"
    return RedirectResponse(
        url=grant_redirect_url,
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Location": grant_redirect_url},
    )


# user grant approval web form for the client application
@router.get(Config.OAUTH2_AUTHORIZATION_GRANT_PATH, response_class=HTMLResponse)
async def get_form_grant(req: Request):
    # convert query params to a python dict
    # this is not always a good practice when there are multiple parameters
    # with same name, but in this OAuth2 login case, it is safe
    params = dict(req.query_params)
    print("query_params:", params)
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <title>User grant for client application</title>
</head>
<body>
  <h1>Token Scope Grant</h1>
  <form method="post" action="{AUTHORIZATION_GRANT_URL}">
    <h4>The client is asking for scope: {params.get('scope')}</h4>
    <label for="grant">Do you approve the grant and issuance of an access token:</label>
    <input type="checkbox" name="user_grant" id="user_grant">
"""
    # relay all request params as form hidden fields
    for k, v in params.items():
        html_content += f"""
        <input type="hidden" name="{k}" id="k" value="{v}">
    """

    html_content += """
    <hr>
    <input type="submit" value="Submit">
  </form>
</body>
</html>
    """
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)


# handle web form POST for the user to approve or reject the grant.
# with approved grant, authorization server will send redirect response
# to the user-agent (browser) with the redirect_uri provided in the original
# client application request (or during client registration).
# This redirection response contains an authorization_code or access_token
# depending on grant type, and any local state included in the original
# client application request.
#
# By OAuth2 specs, authorization_code should be short-lived, with expiration
# window of several minutes, and the code should be specific to the user.
#
# The authorization code can be implemented as a self-encoded JWT token.
# The scope and state data is relayed via the grant form hidden fields.
#
@router.post(Config.OAUTH2_AUTHORIZATION_GRANT_PATH)
async def post_form_grant(
    username: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    user_grant: bool | None = Form(None),
    scope: str | None = Form(None),
    state: str | None = Form(None),
    response_type: str | None = Form(None),
):
    # todo: validate client_id
    # the redirect_url should be validated with known list as well
    # todo: validate redirect_uri with this specific client_id
    print(f">> POST form_grant >> redirect_uri: {redirect_uri}")
    print(f">> POST form_grant client_id: {client_id}")

    # todo: optional PKCE challenge validation
    # todo: validate state if given, this requires server-side session
    print(f">> POST form_grant >> state: {state}")

    # check grant
    print(f">> POST form_grant >> user_grant: {user_grant}")
    if not user_grant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing user grant",
        )

    # todo: validate scope
    print(f">> POST form_grant >> scope: {scope}")

    # check response_type
    # if None => default to code grant, generate authorization code and redirect
    # if token => implicit grant, generate access token and redirect
    print(f">> POST form_grant >> response_type: {response_type}")

    # if implicit grant, return access token in redirect response
    if response_type == "token":
        access_token_expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"iss": ISSUER, "sub": username, "scope": scope},
            expires_delta=access_token_expires_delta,
        )
        # by OAuth 2 specs, for implicit grant, access token must be put into
        # url segment (#access_token=..) in the response redirect url for
        # safety reason
        redirect_url = redirect_uri + "#access_token=" + access_token
        redirect_url += "&token_type=Bearer"
        redirect_url += f"&expires_in={access_token_expires_delta.seconds}"
        if scope:
            redirect_url += f"&scope={scope}"
        if state:
            redirect_url += f"&state={state}"

        # by default, FastAPI use status code 307 for redirect, which will keep
        # the original http method, in this case a POST
        # to change the redirect from POST to GET, set status_code to 303
        # ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/303
        return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)

    # otherwise default to code grant, generate authorization code
    # todo: for now include scope in code, need to persist scope along with
    #   auth code for the duration of the code grant flow
    code_data = {
        "username": username,
        "client_id": client_id,
    }
    if scope:
        code_data["scope"] = scope

    auth_code = create_auth_code(
        code_data,
        expires_minutes=AUTHORIZATION_CODE_EXPIRE_MINUTES,
    )

    # By OAuth2 specs, generated code is included in the redirect url as
    # path parameter (?code=..)
    redirect_url = redirect_uri + "?code=" + auth_code
    if scope:
        redirect_url += f"&scope={scope}"
    if state:
        redirect_url += f"&state={state}"

    print(f">> POST form_grant >> redirect_url: {redirect_url}")

    # by default, FastAPI use status code 307 for redirect, which will keep
    # the original http method, in this case a POST
    # to change the redirect from POST to GET, set status_code to 303
    # ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/303
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


# /userinfo endpoint to support OpenID Connect protocol to provide user profile
# information.
# This endpoint expects a Bearer token from the request.
# Ref: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest
# To access this endpoint the provided Bearer token must contain 'openid' scope.
# There are different implementation cases of fetching user data:
# - if authz server is IdP at the same time, then get user data locally
# - if authz server has IdP integration, then ask IdP for user data
# - if authz is alone, then extract all claims included in the Bearer token
@router.post(Config.OAUTH2_USERINFO_PATH, response_class=JSONResponse)
async def userinfo(token_payload: dict = Depends(get_request_token)):
    print(">> /userinfo >> token_payload:", token_payload)

    # todo: check aud, which should be client_id

    # check scope, which MUST contain 'openid'
    token_scope = token_payload.get("scope") or ""
    token_scope_items = token_scope.strip().split(" ")
    if "openid" not in token_scope_items:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="",
            headers={
                "WWW-Authenticate": 'error="invalid_token", error_description="The access token has insufficient scope."'
            },
        )

    # upon successful security check, generate user information response
    # option 1: this authz server is idp or can access idP
    # use sub claim as username to fetch user data
    # sub = token_payload.get("sub")
    # db = SessionLocal()
    # user = db.query(User).filter(User.username == sub).first()
    # if not user:
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED,
    #         detail="",
    #         headers={
    #             "WWW-Authenticate": 'error="invalid_token", error_description="The access token is invalid."'
    #         },
    #     )
    # user_data = {
    #     "sub": token_payload.get("sub"),
    #     "name": user.full_name,
    #     "email": user.email,
    # }

    # option 2: authz server has no access to IdP
    # returned json should simply be the token_payload
    user_data = token_payload.copy()
    # remove exp key if exists
    user_data.pop("exp", None)

    # todo: selectively collect claims by user consent from the available
    #   user_data content
    # for example, if scope includes 'profile' (from openid connect specs),
    # then include profile claims such as family_name, given_name, etc
    # for now, simply expose all from user_data
    user_info = user_data

    return JSONResponse(content=user_info)


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
