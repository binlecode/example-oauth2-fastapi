from typing import Annotated

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import status
from fastapi import Request
from fastapi import Form
from fastapi.responses import RedirectResponse
from fastapi.responses import HTMLResponse

from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import User

from ..security import verify_password


IDP_LOGIN_URL = "/identity/login"


# This simulates a 3rd party Identity Provider, for user authentication
# This IdP provides 'federated' user (identity) authentication and
# (client application token grant) authorization, via a login web form.


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


# In OAuth 2, authorization server delegates user authentication
# to an Identity Provider, aka IdP, for user login,
# when authenticated, IdP sends back redirect response to authorization
# callback endpoint, where authorization server continues with token
# grant authorization.

# for user to approve or reject the grant of token scope requested by
# the client application.
# Upon user's grant, authorization server responses with authorization code, with the redirect_uri being the client
# application's callback endpoint. The client application callback endpoint
# takes this authorization code, add client_id and client_secret to the
# authorization server's /token endpoint to exchange for access_token
#
# The IdP should provide web browser form to authenticate user and approve
# the grant with specific scope. The IdP can be local or remote 3rd party.
#
#
#
#
# HTTP/1.1" 307 Temporary Redirect
# redirected to login page:
# http://127.0.0.1:8000/identity/login
# ?client_id=swagger
# &scope=openid
# &redirect_uri=http://127.0.0.1:8000/docs/oauth2-redirect
# &state=V2VkIEFwciAxOSAyMDIzIDIy...


# IdP's login web form for user (resource owner) to authenticate in order to
# provide identity claim for the authorization server.
#
@router.get("/login", response_class=HTMLResponse)
async def get_login_grant(req: Request):
    print(">> idp >> redirected to login page:", req.url)
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
    <hr>
"""
    # if the GET request contains client_id and scope, that makes additional
    # grant approval form fields
    if params.get("client_id"):
        html_content += f"""
    <h4>Requesting Client: {params.get('client_id')}</h4>
"""
    # relay all request params as form hidden fields
    for k, v in params.items():
        html_content += f"""
    <input type="hidden" name="{k}" id="k" value="{v}">
"""
    html_content += f"""
    <hr>
    <input type="submit" value="Submit">
  </form>
</body>
</html>
    """
    return HTMLResponse(content=html_content, status_code=status.HTTP_200_OK)


# IdP handles web form POST for user to authenticate.
# If successful, IdP sends response back to user-agent (browser)
# with a redirect response with the redirect_uri of the authorization callback
# url, along with all other parameters from the original request.
#
# an example 302 response that IdP sends back to the browser is like this:
# HTTP/1.1 302 Found
# Location: https://client.app.com/cb?code=AUTHORIZATION_CODE_HERE&state=STATE_STRING_HERE
#
# The `Location` header must have a redirect url that contains the authorization
# code, as well as other parameters passed from the original request.
#
@router.post("/login")
async def post_login_grant(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    authorization_callback_uri: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    scope: str | None = Form(None),
    state: str | None = Form(None),
    response_type: str | None = Form(None),
):
    # todo: validate client_id
    # todo: validate redirect_uri with this specific client_id
    print(f"redirect_uri: {redirect_uri}")
    print(f"client_id: {client_id}")

    # check user credentials from form data
    user = authenticate_user(SessionLocal(), username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # redirect identity claim response to the given callback uri
    # for the authorization server to take over and continue with the
    # grant approval

    authz_callback_url = authorization_callback_uri + f"?redirect_uri={redirect_uri}"

    authz_callback_url += f"&username={username}"
    authz_callback_url += f"&client_id={client_id}"
    authz_callback_url += f"&response_type={response_type}"

    if scope:
        authz_callback_url += f"&scope={scope}"

    if state:
        authz_callback_url += f"&state={state}"

    return RedirectResponse(
        url=authz_callback_url,
        # todo: get data into a json or form body in this post redirect
        #   instead of url params
        # this must be a 307 redirect, which keeps the http POST method
        # with content in body
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        headers={"Location": authz_callback_url},
    )
