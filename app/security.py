import os
import base64
from datetime import timedelta, datetime
from typing import Annotated
from fastapi import (
    HTTPException,
    Query,
    Path,
    status,
    Depends,
    Header,
    APIRouter,
)

from passlib.context import CryptContext
from jose import JWTError, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

#
# security utils
#

DUMMY_X_TOKEN = "a-secret-token"

JWK_DEFAULT_KID = "default-jwk-kid"
ALGORITHM = "RS256"

RS256_PRIVATE_PEM_FILE_PATH = os.path.dirname(__file__) + "/../jwt-private-key.pem"
# RS256_PRIVATE_PEM_FILE_PATH = os.path.dirname(__file__) + "/../jwt-key-not-exist"
RS256_PUBLIC_PEM_FILE_PATH = os.path.dirname(__file__) + "/../jwt-public-key.pem"
# RS256_PUBLIC_PEM_FILE_PATH = os.path.dirname(__file__) + "/../jwt-key.pub-not-exist"

# RS256 secret key (PEM format), used the private key for jwt signing
SECRET_KEY = None
try:
    # SECRET_KEY is the pem binary form loaded from pem file
    # it is used for jwt signing
    SECRET_KEY = open(RS256_PRIVATE_PEM_FILE_PATH).read()
    private_key_obj = serialization.load_pem_private_key(
        SECRET_KEY.encode("utf-8"), password=None, backend=default_backend()
    )
    print(f"RSA private key pem file loaded: {RS256_PRIVATE_PEM_FILE_PATH}")
except OSError:
    pass
if not SECRET_KEY:
    print("no private key perm file, generate private key programmatically")
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    # set SECRET_KEY to private key utf-8 decoded string
    SECRET_KEY = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
print(f">> RS256 SECRET_KEY: {SECRET_KEY[:128]} ...")

# RS256 public key (PEM format), used for jwt signature validation
# this key is exposed in standard jwks endpoint json response
PUBLIC_KEY = None
try:
    # PUBLIC_KEY is the pem binary form loaded from pem file
    # it is used for jwt signature validation
    PUBLIC_KEY = open(RS256_PUBLIC_PEM_FILE_PATH).read()
    # public_key_obj is the PublicKeyTypes object to support jwk serialization
    public_key_obj = serialization.load_pem_public_key(PUBLIC_KEY.encode("utf-8"))
    print(f"RSA public key pem file loaded: {RS256_PUBLIC_PEM_FILE_PATH}")
except OSError:
    pass
if not PUBLIC_KEY:
    print("no public key perm file, extract from private_key object")
    public_key_obj = private_key_obj.public_key()
    # set PUBLIC_KEY to public key utf-8 decoded string
    PUBLIC_KEY = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
print(f">> RS256 PUBLIC_KEY: {PUBLIC_KEY}")


# some token settings
ACCESS_TOKEN_EXPIRE_MINUTES = 30
TOKEN_EXPIRES_DELTA_MINUTES = 30
AUTH_CODE_EXPIRES_DELTA_MINUTES = 3


# define an interceptor such as token check to be injected by Depends()
# in openapi operation (aka controller action) methods
async def verify_dummy_token(x_token: Annotated[str | None, Header()]):
    if x_token != DUMMY_X_TOKEN:
        raise HTTPException(status_code=400, detail="X-Token header invalid")


# create JWT access token
# To sign the JWT token set the algorithm to "HS256",
# the input data dict should provide oauth2 jwt token compliant keys
# - sub: the subject of the token, usually the principle identifier,
#   which is username in our case, it can also represent a party or entity
# It is common to add prefix in subject value string to denote its type,
# such as: "username:johndoe", "group:engineer", etc.
# Permissions are defined and applied to the subject for access control,
# in oauth2 terms, they are grouped by `scope`.


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if not expires_delta:
        expires_delta = timedelta(minutes=TOKEN_EXPIRES_DELTA_MINUTES)
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# if token has audience claim, then decode MUST supply audience argument,
# unless options.verify_aud = False
# https://pyjwt.readthedocs.io/en/stable/usage.html?highlight=audience#audience-claim-aud
def decode_access_token(token: str, audience: str = None, options: dict = {}):
    """
    Raises:
        all Exceptions from jwt.decode() method
    """
    # payload = jwt.decode(
    #     token, PUBLIC_KEY, algorithms=[ALGORITHM], audience=audience, options=options
    # )
    payload = jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=[ALGORITHM],
        audience=audience,
        options={"verify_aud": False},
    )
    return payload


def create_jwk(kid=JWK_DEFAULT_KID, public_key=public_key_obj):
    # get n value as integer from public key pem
    n = public_key.public_numbers().n
    # the n number (integer) is too long to be included in json
    # so it is typically encoded to a url-safe base64 string
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    n_b64 = base64.urlsafe_b64encode(n_bytes)
    # convert to utf-8 string for json serialization
    n_b64_str = n_b64.decode("utf-8")
    return {
        "kty": "RSA",  # key type RSA
        "kid": kid,
        "use": "sig",  # intended use is signature
        "alg": "RS256",
        "n": n_b64_str,
        "e": public_key.public_numbers().e,
    }


# create code grant flow authorization code
# by OAuth2 specs, authorization_code should be short-lived, with
# expiration window of several minutes
#
# the code is built as a jwt token with expiration time encoded
# it can optionally encode additional info, such as user id, client id,
# and redirect_uri, etc.
#
def create_auth_code(data: dict = {}, expires_minutes: int | None = None):
    to_encode = data.copy()
    expires_timedelta = timedelta(
        minutes=(expires_minutes or AUTH_CODE_EXPIRES_DELTA_MINUTES)
    )
    expire = datetime.utcnow() + expires_timedelta
    to_encode.update({"exp": expire})
    # pyjwt converts datetime type to int
    encoded = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded


def decode_auth_code(encoded: str):
    # Expiration time is automatically verified in jwt.decode() and raises
    # jwt.ExpiredSignatureError if the expiration time is in the past
    # Ref: https://pyjwt.readthedocs.io/en/stable/usage.html
    # payload = jwt.decode(encoded, SECRET_KEY, algorithms=[ALGORITHM])
    payload = jwt.decode(encoded, PUBLIC_KEY, algorithms=[ALGORITHM])
    return payload


# configure password crypt context with bcrypt algorithm
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# create a hash string fot a password to avoid clear-text persistence
def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)
