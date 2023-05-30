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
from jose import JWTError, jwt, jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from config import Config

#
# security utils
#

# JWK_DEFAULT_KID = "default-jwk-kid"
JWK_DEFAULT_KID = Config.OAUTH2_JWK_DEFAULT_KID
# ALGORITHM = "RS256"
ALGORITHM = Config.OAUTH2_JWT_ALGORITHM

# RS256_PRIVATE_PEM_FILE_PATH = os.path.dirname(__file__) + "/../jwt-private-key.pem"
RS256_PRIVATE_PEM_FILE_PATH = os.path.dirname(__file__) + "/../jwt-key-not-exist"
# RS256_PUBLIC_PEM_FILE_PATH = os.path.dirname(__file__) + "/../jwt-public-key.pem"
RS256_PUBLIC_PEM_FILE_PATH = os.path.dirname(__file__) + "/../jwt-key.pub-not-exist"

# RS256 secret key (PEM format), used the private key for jwt signing
private_key_obj = None
try:
    # SECRET_KEY is the pem binary form loaded from pem file
    # it is used for jwt signing
    # SECRET_KEY = open(RS256_PRIVATE_PEM_FILE_PATH).read()
    # pem file should be read as binary ("rb")
    private_key_obj = serialization.load_pem_private_key(
        open(RS256_PRIVATE_PEM_FILE_PATH, "rb").read(),
        password=None,
        backend=default_backend(),
    )
    print(f"RSA private key pem file loaded: {RS256_PRIVATE_PEM_FILE_PATH}")
except OSError:
    pass
if not private_key_obj:
    print("no private key pem file, generate private key programmatically")
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

# define SECRET_KEY to be private key utf-8 decoded string
# format: PKCS1 TraditionalOpenSSL => PEM header: `BEGIN RSA PRIVATE KEY`
# format: PKCS8 PrivateKeyInfo => PEM header: `BEGIN PRIVATE KEY`
SECRET_KEY = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    # format=serialization.PrivateFormat.TraditionalOpenSSL,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("utf-8")
print(f">> RS256 SECRET_KEY: {SECRET_KEY[:128]} ...")

# RS256 public key (PEM format), used for jwt signature validation
# this key is exposed in standard jwks endpoint json response
public_key_obj = None
try:
    # load pem file in binary mode ("rb")
    public_key_obj = serialization.load_pem_public_key(
        open(RS256_PUBLIC_PEM_FILE_PATH, "rb").read()
    )
    print(f"RSA public key pem file loaded: {RS256_PUBLIC_PEM_FILE_PATH}")
except OSError:
    pass
if not public_key_obj:
    print("no public key pem file, extract from private_key object")
    public_key_obj = private_key_obj.public_key()


# define PUBLIC_KEY as PEM format decoded utf-8 string
# this public key string value is used to validate jwt signature
# this public key is to be exposed as jwk in jwks endpoint
#
# format: X.509 SubjectPublicKeyInfo => PEM header: BEGIN PUBLIC KEY
# format: PKCS#1 Raw PKCS#1 => PEM header: BEGIN RSA PUBLIC KEY
PUBLIC_KEY = public_key_obj.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
    # format=serialization.PublicFormat.PKCS1,
).decode("utf-8")
print(f">> RS256 PUBLIC_KEY: {PUBLIC_KEY}")


# create JWT access token
# To sign the JWT token set the algorithm to "HS256" (symmetric) or
# "RS256" (asymmetric, preferred to share public key with 3rd party).
# The input data dict should provide oauth2 jwt token compliant keys:
# - sub: the subject of the token, usually the principle identifier,
#   which is username in our case, it can also represent a party or entity
# It is common to add prefix in subject value string to denote its type,
# such as: "username:johndoe", "group:engineer", etc.
# Usually access control is defined by permissions and applied to the subject,
# in oauth2 terms, they are grouped by `scope`.


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if not expires_delta:
        expires_delta = timedelta(minutes=Config.OAUTH2_ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# if token has audience claim, then decode MUST supply audience argument,
# unless `options.verify_aud = False`
# https://pyjwt.readthedocs.io/en/stable/usage.html?highlight=audience#audience-claim-aud
def decode_access_token(token: str, audience: str = None, options: dict = {}):
    """
    Raises:
        all Exceptions from jwt.decode() method
    """
    payload = jwt.decode(
        token, PUBLIC_KEY, algorithms=[ALGORITHM], audience=audience, options=options
    )
    # payload = jwt.decode(
    #     token,
    #     PUBLIC_KEY,
    #     algorithms=[ALGORITHM],
    #     audience=audience,
    #     options={"verify_aud": False},
    # )
    return payload


def create_jwk(kid=JWK_DEFAULT_KID, public_key=public_key_obj):
    jwk_obj = jwk.construct(PUBLIC_KEY, algorithm=ALGORITHM)
    jwk_dict = jwk_obj.to_dict()
    # attach key id and use metadata
    jwk_dict.update(
        {
            "kid": kid,
            # usage key for jwk, "sig" means for signing/signature
            "use": "sig",
        }
    )
    return jwk_dict


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
        minutes=(expires_minutes or Config.OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES)
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
