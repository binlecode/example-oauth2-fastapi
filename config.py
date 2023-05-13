import os
from dotenv import load_dotenv
import logging


load_dotenv()


class Config(object):
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    logging.basicConfig(level=LOG_LEVEL)
    logger = logging.getLogger(__name__)
    logger.info(f"Config.LOG_LEVEL: {LOG_LEVEL}")

    RESET_DB = os.environ.get("RESET_DB", False)
    logger.info(f"Config.RESET_DB: {RESET_DB}")

    basedir = os.path.abspath(os.path.dirname(__file__))
    # SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_db.db"
    # SQLALCHEMY_DATABASE_URI = "postgresql://user:password@postgresserver/db"
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SQLALCHEMY_DATABASE_URI", "sqlite:///" + os.path.join(basedir, "sql_db.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = os.environ.get("SQLALCHEMY_ECHO", False)
    logger.info(f"Config.SQLALCHEMY_ECHO: {SQLALCHEMY_ECHO}")

    ## web stack

    PAGINATION_LIMIT = 5
    logger.info(f"Config.PAGINATION_LIMIT: {PAGINATION_LIMIT}")

    CORS_ALLOW_ORIGINS = [
        "*",
        # "http://127.0.0.1:8000",  # allow local (/docs) swagger-ui
    ]
    logger.info(f"Config.CORS_ALLOW_ORIGINS: {CORS_ALLOW_ORIGINS}")

    ## OAuth2 configurations

    OAUTH2_URL_BASE = os.environ.get("OAUTH2_URL_BASE", "http://127.0.0.1:8000")
    logger.info(f"Config.OAUTH2_URL_BASE: {OAUTH2_URL_BASE}")

    OAUTH2_ROUTE_PREFIX = "/oauth2"
    OAUTH2_AUTHORIZATION_PATH = "/authorize"
    OAUTH2_AUTHORIZATION_URL = OAUTH2_ROUTE_PREFIX + OAUTH2_AUTHORIZATION_PATH
    logger.info(f"Config.OAUTH2_AUTHORIZATION_URL: {OAUTH2_AUTHORIZATION_URL}")

    OAUTH2_TOKEN_PATH = "/token"
    OAUTH2_TOKEN_URL = OAUTH2_ROUTE_PREFIX + OAUTH2_TOKEN_PATH
    logger.info(f"Config.OAUTH2_TOKEN_URL: {OAUTH2_TOKEN_URL}")

    # issuer identification should have absolute path
    OAUTH2_ISSUER_URL = OAUTH2_URL_BASE + OAUTH2_TOKEN_URL
    logger.info(f"Config.OAUTH2_ISSUER_URL: {OAUTH2_ISSUER_URL}")

    OAUTH2_AUTHORIZATION_GRANT_PATH = "/form_grant"
    OAUTH2_AUTHORIZATION_GRANT_URL = (
        OAUTH2_ROUTE_PREFIX + OAUTH2_AUTHORIZATION_GRANT_PATH
    )
    logger.info(
        f"Config.OAUTH2_AUTHORIZATION_GRANT_URL: {OAUTH2_AUTHORIZATION_GRANT_URL}"
    )

    OAUTH2_AUTHORIZATION_CALLBACK_PATH = "/authorization_callback"
    OAUTH2_AUTHORIZATION_CALLBACK_URL = (
        OAUTH2_URL_BASE + OAUTH2_ROUTE_PREFIX + OAUTH2_AUTHORIZATION_CALLBACK_PATH
    )
    logger.info(
        f"Config.OAUTH2_AUTHORIZATION_CALLBACK_URL: {OAUTH2_AUTHORIZATION_CALLBACK_URL}"
    )

    OAUTH2_JWKS_PATH = "/jwks"
    OAUTH2_USERINFO_PATH = "/userinfo"

    OAUTH2_ACCESS_TOKEN_EXPIRE_MINUTES = 30
    logger.info(
        f"Config.OAUTH2_ACCESS_TOKEN_EXPIRE_MINUTES: {OAUTH2_ACCESS_TOKEN_EXPIRE_MINUTES}"
    )

    OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES = 5
    logger.info(
        f"Config.OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES: {OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES}"
    )

    # default list of supported client scopes
    OAUTH2_CLIENT_SCOPES = {
        "openid": "openid scope",
        "profile": "profile scope",
        "email": "email scope",
    }
    logger.info(f"Config.OAUTH2_CLIENT_SCOPES: {OAUTH2_CLIENT_SCOPES}")

    ## IdP configuration

    IDP_ROUTE_PREFIX = "/identity"
    IDP_LOGIN_PATH = "/login"
    # override this with env var for an external 3rd party idp
    # for a local IdP, the url is a relative path: "/identity/login"
    IDP_LOGIN_URL = os.environ.get("IDP_LOGIN_URL", IDP_ROUTE_PREFIX + IDP_LOGIN_PATH)
    logger.info(f"Config.IDP_LOGIN_URL: {IDP_LOGIN_URL}")
