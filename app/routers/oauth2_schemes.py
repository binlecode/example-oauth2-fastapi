from typing import Optional, Dict
from fastapi import HTTPException
from fastapi import status
from fastapi import Request
from fastapi.security import OAuth2
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel

from config import Config


# OpenAPI OAuth2 schema for: password grant bearer token
# Ref: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3
# this assumes the token endpoint as "context-root/<tokenUrl>"
oauth2_password_scheme = OAuth2PasswordBearer(
    tokenUrl=Config.OAUTH2_TOKEN_URL, scopes=Config.OAUTH2_CLIENT_SCOPES
)

# OpenAPI OAuth2 schema for: authorization code grant bearer token
# Ref: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
oauth2_code_schema = OAuth2AuthorizationCodeBearer(
    authorizationUrl=Config.OAUTH2_AUTHORIZATION_URL,
    tokenUrl=Config.OAUTH2_TOKEN_URL,
    scopes=Config.OAUTH2_CLIENT_SCOPES,
)


# FastAPI has no built-in security scheme class definition for implicit grant
# token, we define one here.
class OAuth2ImplicitBearer(OAuth2):
    def __init__(
        self,
        authorizationUrl: str,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(
            implicit={
                "authorizationUrl": authorizationUrl,
                "scopes": scopes,
            }
        )
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> Optional[str]:
        authorization = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None  # pragma: nocover
        return param


# OpenAPI OAuth2 scheme for: implicit grant flow
oauth2_implicit_scheme = OAuth2ImplicitBearer(
    authorizationUrl=Config.OAUTH2_AUTHORIZATION_URL, scopes=Config.OAUTH2_CLIENT_SCOPES
)
