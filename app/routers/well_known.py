from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..security import create_jwk
from config import Config


router = APIRouter(
    # prefix="/.well-known",
    prefix=Config.OIDC_WELL_KNOWN_PATH_PREFIX,
    tags=["well-known"],
    dependencies=[],
)


# jwks endpoint
@router.get(
    # "/jwks.json",
    Config.OIDC_JWKS_PATH,
    operation_id="get_jwks",
    summary="get JWK Set",
    response_class=JSONResponse,
)
async def read_well_known_jwks():
    jwk_dict = create_jwk()
    return JSONResponse(content={"keys": [jwk_dict]})


# discovery document endpoint for an OpenID Connect (OIDC) provider
# used by clients like jwt.io to fetch jwks_uri, etc.
@router.get(
    Config.OIDC_OPENID_CONFIGURATION_PATH,
    operation_id="get_issuer_well_known_openid_configuration",
    summary="get issuer openid configuration",
    response_class=JSONResponse,
)
async def openid_config():
    openid_cfg = {
        "scope_supported": Config.OAUTH2_CLIENT_SCOPES,
        "issuer": Config.OIDC_ISSUER_URL,
        "authorization_endpoint": Config.OAUTH2_AUTHORIZATION_URL,
        "token_endpoint": Config.OAUTH2_TOKEN_URL,
        "grant_types_supported": [
            "password",
            "client_credentials",
            "authorization_code",
            "implicit",
        ],
        "userinfo_endpoint": Config.OAUTH2_USERINFO_URL,
        "jwks_uri": Config.OIDC_JWKS_URL,
    }

    return JSONResponse(content=openid_cfg)
