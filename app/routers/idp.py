from typing import Annotated

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import status
from fastapi import Request
from fastapi import Form
from fastapi.responses import RedirectResponse
from fastapi.responses import HTMLResponse

from sqlalchemy.orm import Session

from ..db import User
from ..db import SessionLocal

from ..utils import verify_password
from ..utils import create_auth_code


IDP_LOGIN_URL = "/identity/login"


# This immulates a 3rd party Identity Provider, for user authentication
# This IdP provides 'federated' user (identity) authentication and
# (client application token grant) authorization.


router = APIRouter(
    prefix="/identity",
    tags=["identity"],
    dependencies=[],
)


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    print(f"authenticate user: {user}")
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


# for OAuth2 code grant, a redirected GET request from authorization server
# HTTP/1.1" 307 Temporary Redirect
# redirected to login page:
# http://127.0.0.1:8000/identity/login
# ?client_id=swagger
# &scope=openid
# &redirect_uri=http://127.0.0.1:8000/docs/oauth2-redirect
# &state=V2VkIEFwciAxOSAyMDIzIDIy...


# IdP's login web form for user (resource owner) to authenticate in order to
# approve or reject the grant for the client application to access the
# resource service
#
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
  <title>IdP Delegated User Login and Grant</title>
</head>
<body>
  <h1>IdP Delegated Login and Grant</h1>
  <form method="post" action="{IDP_LOGIN_URL}">
    <label for="username">Username:</label>
    <input type="text" name="username" id="username">
    <br>
    <label for="password">Password:</label>
    <input type="password" name="password" id="password">
    <br>
"""
    # if the GET request contains client_id and scope, that makes additional
    # grant approval form fields
    if params.get("client_id"):
        html_content += f"""
    <hr>
    <h4>Client {params.get('client_id')} requests access</h4>
    <h4>requested token scope: {params.get('scope')}</h4> 
    <label for="grant">Do you approve and issue access token:</label>
    <input type="checkbox" name="user_grant" id="user_grant">
    <input type="hidden" name="redirect_uri" id="redirect_uri" value="{params.get('redirect_uri')}">
    <input type="hidden" name="client_id" id="client_id" value="{params.get('client_id')}">
    <input type="hidden" name="scope" id="scope" value="{params.get('scope') or ''}">
    <input type="hidden" name="state" id="state" value="{params.get('state') or ''}">
    <br>
"""
    html_content += f"""
    <hr>
    <input type="submit" value="Submit">
    <br>
  </form>
</body>
</html>
    """
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)


# IdP handles web form post for user to approve or reject the grant
# Assuming the resource owner authenticates and grants access, IdP
# sends an authorization response back to browser with a `302 Found`
# redirect response with the redirect_uri of the original request
# from the authorization server.
#
# This is essentially a redirection flow, where the user's browser is
# redirected to the IdP's authentication page, and then back to the
# redirect_uri in the original request (from the authorization to the IdP).
# The use of the user's web browser as an intermediary allows the
# authorization server to receive the user's authentication response
# from the IdP without needing to expose the user's credentials to the
# client or the authorization server.
# The redirect_uri in the original request is usually the callback endpoint
# of the client application, in other words, in code grant, the client
# application callback endpoint should handle the received authorization code
# and POST to authorization server's /token endpoint to exchange for the
# access token.
#
# an example 302 response that IdP sends back to the browser is like this:
# HTTP/1.1 302 Found
# Location: https://client.app.com/cb?code=AUTHORIZATION_CODE_HERE&state=STATE_STRING_HERE
#
# The `Location` header must have a redirect url that contains the authorization
# code (AUTHORIZATION_CODE_HERE) and a state parameter (STATE_STRING_HERE)
# that is passed through from the original authorization request.
# This redirect url can also include other parameters like scope.
#
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
    user = authenticate_user(SessionLocal(), username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # todo: validate client_id
    # todo: validate redirect_uri with this specific client_id
    print(f"redirect_uri: {redirect_uri}")
    print(f"client_id: {client_id}")

    # todo: optional PKCE challenge validation

    # check grant approval
    print(f"user_grant: {user_grant}")
    if not user_grant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing user grant",
        )

    # when all validations pass, generate authorization code
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

    return RedirectResponse(
        url=redirect_url,
        status_code=status.HTTP_302_FOUND,
        headers={"Location": redirect_url},
    )
