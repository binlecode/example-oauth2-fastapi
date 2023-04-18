# A basic OAuth2 authorization server with FastAPI framework

Table of content:

- [A basic OAuth2 authorization server with FastAPI framework](#a-basic-oauth2-authorization-server-with-fastapi-framework)
  - [project structure](#project-structure)
  - [OAuth2 framework implementation](#oauth2-framework-implementation)
    - [code grant flow and implicit grant flow](#code-grant-flow-and-implicit-grant-flow)
    - [authorization code](#authorization-code)
    - [password grant](#password-grant)
    - [client credentials grant](#client-credentials-grant)
    - [token response](#token-response)
    - [OAuth2 access token and bearer token](#oauth2-access-token-and-bearer-token)
    - [self-encoded token encoding](#self-encoded-token-encoding)
    - [client application registration](#client-application-registration)
    - [client application redirect\_uri validation](#client-application-redirect_uri-validation)
    - [user password hash](#user-password-hash)
    - [access token JWT signing and JWKS endpoint](#access-token-jwt-signing-and-jwks-endpoint)
  - [OAuth2 and OpenID connect](#oauth2-and-openid-connect)
    - [OAuth2 framework](#oauth2-framework)
  - [scratch pad](#scratch-pad)
  - [References](#references)

## project structure

FastAPI is ASGI framework, it supports sync ans async request handling seamlessly.
Think of FastAPI as the glue that brings together Starlette, Pydantic, OpenAPI,
and JSON Schema.

Use pyenv to select python version 3.10+

Python 3.10+ has better python type hint syntax and support, the type hint
is used by pydantic for data validation in fastapi web framework.

```sh
# optional: pip install ipython
pip install black
pip install fastapi
pip install sqlalchemy
# install uvicorn as ASGI server
pip install "uvicorn[standard]"
# install multipart support for form and file post
pip install python-multipart
# install cryptography lib python-jose for jwt
# JOSE stands for JavaScript Object Signing and Encryption
pip install "python-jose[cryptography]"
# install passlib for password hashing
# choose bcrypt as password hashing algorithm
# ref: https://en.wikipedia.org/wiki/Bcrypt
pip install "passlib[bcrypt]"
```

run app in development mode with reload enabled

```sh
uvicorn app.main:app --reload
```

openapi doc v3 auto-generated at:
http://127.0.0.1:8000/docs

With openapi doc loaded in swagger editor interface, it is recommended to use
it for interactive requests during development.

Project structure:

```
app                  # app root folder
├── __init__.py      # makes "app" a "Python package"
├── main.py          # "main" module of the application
├── schemas.py  # pydantic schema models
├── utils.py   # common utils functions
├── db.py      # database impl
└── routers          # "routers" is a "Python subpackage"
│   ├── __init__.py  # makes "routers" a "Python subpackage"
│   ├── items.py     # "items" submodule, e.g. import app.routers.items
│   └── users.py     # "users" submodule, e.g. import app.routers.users
│   └── auth.py      # "auth" submodule for security and access control
```

## OAuth2 framework implementation

OAuth 2 framework implies the collaboration between the four following roles:

- Resource Owner: Usually, this is the end-user – it's the entity that has some resources worth protecting
- Resource Server: An service that protects the resource owner's data, usually publishing it through a REST API
- Client: An application that uses the resource owner's data
- Authorization Server: An application that grants permission – or authority – to clients in the form of expiring tokens

A **grant type** is how a client gets permission to use the resource owner's data,
in the form of an access token.

Different types of clients prefer different types of grants:

- Authorization Code: Preferred most often – whether it is a web application,
  a native application, or a single-page application, though native and
  single-page apps require additional protection called PKCE.
  It's more secure thus preferred to use the authorization code grant with PKCE.
- Implicit grant: user is authenticated, authorized, and issued a token from
  the authorization endpoint directly.
- Client Credentials: Preferred for service-to-service communication, say when the resource owner isn't an end-user
- Resource Owner Password: Preferred for the first-party authentication of
  native applications, say when the mobile app needs its own login page
- Refresh Token: A special renewal grant, suitable for web applications to
  renew their existing token

Authorization code grant and implicit grant begin the flow with calling
the `/authorize` endpoint.

Client credential grant and password grant directly calls the `/token` endpoint.

Although password grant is defined as one of the grant flows in OAuth 2, it is
exactly why OAuth 2 is created to prevent in the first place.
Therefore, password grant should be discouraged or avoided.

In fact the password grant is being removed in OAuth 2.1 update.

### code grant flow and implicit grant flow

Authorization Code Grant Flow:

1. An application, the client, requests permission by redirecting to the
   authorization server's `/authorize` endpoint. In calling this endpoint,
   the application sets `response_type=code`, and gives a callback url.
2. The authorization server will usually ask the end-user, the resource owner,
   for permission grant. If the end-user grants the permission, the authorization
   server redirects back to the callback url with an authorization code.
3. The application receives this code and then call the authorization server's
   `/token` endpoint, with the authorization code (granted by the end-user)
   along with client_id and client_secret (in BasicAuth header or POST form body).
   The authorization server responds with the access token after validating
   the authorization code.

With access token, the application makes its request to the API, the resource
server, and that API will verify the access token. It can ask the authorization
server to verify the token using its `/introspect` endpoint. Or, if the token is
self-contained, the resource server can optimize by locally verifying the
token's signature, as is the case with a JWT.

Implicit grant flow:

The client application calls `/authorize` endpoint with `response_type=token`.
The authorization server responds with access token and redirect
the client application to the callback URL given in the request.

### authorization code

The authorization code should be hard to guss or interpret. It must be short
lived, usually with a time window of a few minutes. To implement, the code
can be a self-contained token with expiration time encoded, so that it can be
checked when it is passed to authorization server in exchange for the access
token. This avoids the session state on the authorization server side to
track the code lifetime.

### password grant

Password grant request calls `/token` endpoint to request token directly.

The access token request will contain the following parameters in POST body.

- grant_type (required) – The grant_type parameter must be set to “password”.
- username (required) – The user’s username.
- password (required) – The user’s password.
- scope (optional) – The scope requested by the application.
- Client Authentication (required if the client was issued a secret)

Client Authentication has two options for the client application to pass
the client_id and client_secret:

- basic auth header
- POST body form fields

### client credentials grant

Client credential grant request calls `/token` endpoint to request token.

- grant_type must be set to "client_credentials"
- scope (optional)
- Client Authentication required, passed in the request with two options
  same as password grant

### token response

The entire response is a JSON string.

Successful response:

- access_token
- token_type, usually "Bearer", meaning the access_token is a Bearer Token
- expires_in, optional but recommended, its the duration of time the access_token
  is valid for
- refresh_token, should be provided except for implicit grant
- scope, optional, if the scope the user granted is identical to the scope
  the client app requested, this parameter is optional. If the granted scope
  is different from the requested scope, such as if the user modified the scope,
  then this parameter is required in response
- id_token, optional, only provided if the request scope includes 'openid'
  is indeed granted by user, which means the client application is requesting
  for an id token besides the access token

Unsuccessful response:

- return http 400 bad request status code
- error: will always be one of the following:
  - invalid_request
  - invalid_client, 401 status code is preferred in this case
  - invalid_grant
  - invalid_scope
  - unauthorized_client
  - unsupported_grant_type
- error_description, optional message of the error

### OAuth2 access token and bearer token

OAuth2 access token is obtained by the client application to access the resource API.
It is issued by authorization server upon user （the resource owner） granted
permission. Access token is usually application specific, and can include
information about user and client application.

OAuth2 Bearer token is a type of access token. It is used to authenticate the
client application to the resource server. "Bearer" means it can be used by
any party who possesses it. Because of this, a bearer token does **not** contain
any information about the user or the client application, and it does **not**
include any encryption or digital signature to ensure their authenticity.
Instead, a bearer token relies on transport layer security to protect the
access to the resource server.

Comparing to access token, a bearer token is less specific and only include
information necessary to authenticate the client application in accessing
the resource server APIs.

### self-encoded token encoding

Self-encoded token avoid storing token in a database by encoding all necessary
information in the token string itself. It eliminates database lookup in every
resource API call, a huge performance benefit.

The most common way to implement self-encoded token is to use JWT, JSON Web
Token, which creates a JSON representation of all the data to include in the
token, and signs the resulting JSON string with a private key known only to
the authorization server.

Ref: OAuth 2 JWT access token specs:
https://oauth.net/2/jwt-access-tokens/

To decode the token, public key is needed that corresponds to the private key
used in signing the token.

Public key can be obtained from `/jwks` endpoint from the authorization server.

### client application registration

Authorization server is responsible for creating `client_id` and `client_secret`
when a new client application is registered.

Not specified by OAuth2 specs, but typically the following information is
collected during client registration:

- application name
- authorization callback url (aka redirect_uri by OAuth2 specs)
  - this can be a list or a comma-separated string to store multiple
    redirect_uri's, during the authorization flow the redirect_uri provided
    in the request should be checked against this list
- homepage url
- a short description
- a link to application's privacy policy (can be used in consent approval)

### client application redirect_uri validation

The redirect_uri specifies where the users should be redirected after
they have chosen whether or not to authenticate the client application.

There are three cases where redirect_uri should be validated:

- when the developer registers the redirect URL as part of creating an application
- in the authorization request (both authorization code and implicit grant types)
- when the application exchanges an authorization code for an access token

### user password hash

Create hash string for a password before saving to database.

In python/ipython venv: run below script:

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
password = "secret"
hashed_password = pwd_context.hash(password)
```

### access token JWT signing and JWKS endpoint

By OAuth2 specs, authorization server should provide JSON Web Key (JWK)
Set (JWKS) endpoint for token-receiving parties to verify the issued JWT
token, specifically with RSA signing algorithm.
Two signing algorithms are commonly used in signing a JWT:

- RS256: stands for RS256+SHA256, RS256 is for signing, SHA256 is for hashing
  RS256 encrypts with an asymmetric key pair, which means a private key is used
  to sign the JWT and a public key must be used to verify the signature
  RS256 is usually preferred due to its asymmetric nature to support 3rd party
  (public) key sharing
- HS256: stands for HMAC+SHA256, HMAC is for signing
  HS256 encrypts with symmetric key, which means the JWT is signed and
  validated by the same key

For HS256 symmetric key signing, a simple random key can be generated with
openssl:

```sh
openssl rand -hex 32
09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7
```

RS256 should be used in production system for OAuth 2 JWT signing, with its
public key being distributed via the JWKS endpoint, which is usually
"<auth-server-url-root>/.well-known/jwks.json".

To generate the key pair for JWT RS256 signing algorithm,
use `openssl` to generate RSA private key pem file:

```sh
openssl genpkey -algorithm RSA -out jwt-private-key.pem -pkeyopt rsa_keygen_bits:2048
```

```sh
openssl rsa -in jwt-private-key.pem -pubout -outform PEM -out jwt-public-key.pem
```

These two key files can be loaded in authorization server and used in
signing jwt tokens. However, this may not be sufficient when the key
pair is additionally required to be:

- rotated for certain period of time for enhanced security
- client specific for enhanced tenancy isolation

In such case, the key pair should be generated programmatically.
In Python, the [cryptography lib](https://cryptography.io/en/latest/) is
mostly used for RS256 key implementation.

```python
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate RSA key pair
# `public_exponent` is a prime integer, which should be sufficiently large
# to make generated keys secure
# 65537 is what industry commonly uses to generate secure rs256 private keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# a private key can also be loaded from a pem file like the
# one generated above
src_private_key_pem = open("jwt-key").read()
private_key = serialization.load_pem_private_key(
    # serialization needs pem content to be in utf-8 format
    src_private_key_pem.encode("utf-8"),
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()

private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

assert private_key_pem == src_private_key_pem.encode("utf-8")

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# key-id key for jwk
kid = "mykey"
# usage key for jwk, "sig" means for signing/signature
use = "sig"
n = public_key.public_numbers().n

# in the jwk above, the n (integer) is too long to be included in json
# so it is typically encoded to a url-safe base64 string
import base64

n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
n_b64 = base64.urlsafe_b64encode(n_bytes)

# to serialize it to json string, it needs to be converted to utf-8 string
n_b64_str = n_b64.decode("utf-8")

jwk = {
    "kty": "RSA",
    "kid": kid,
    "use": use,
    "alg": "RS256",
    "n": n_b64_str,
    "e": public_key.public_numbers().e,
}

jwks = {
    "keys": [jwk]
}

jwks_json = json.dumps(jwks)

# To use jwks json for jwt validation:
# first, extract public key from jwk
import base64

pub_key = None
for jwk in jwks["keys"]:
    if jwk["kid"] == kid:
        jwk_n = jwk["n"]
        n = None
        e = None
        if isinstance(jwk_n, str):
            n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + "=="), byteorder='big')
        e = jwk["e"]
        if n and e:
            #
            pub_key = rsa.RSAPublicNumbers(e=e, n=n).public_key()
            break

if pub_key is None:
    raise Exception("Public key for kid not found")

pub_key_pem = pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# the jwk extracted pub_key pem byte array should match its source byte array
assert public_key_pem == pub_key_pem

# then: Verify JWT signature using public key
from jose import jwt, JWTError

jwt_str = "<JWT string to validate>"
try:
    decoded = jwt.decode(jwt_str, key=pub_key_pem, algorithms=["RS256"])
except JWTError as e:
    print(e)
```

## OAuth2 and OpenID connect

OAuth 2 only defines authorization specs, leaves authentication up to the
identity provider (IdP). This potential gap of authentication **protocol**
standardization is filled by OpenID Connect.

Besides authorization, OAuth 2 framework can also be used to build authentication
and identity protocol:

- authorization server can provide an endpoint for user information, which
  usually takes the `/userinfo` uri.
- define scopes dedicated for user identify and information, `openid`, `profile`, etc

OpenID Connect protocol can be used to carry user id and other information
between enterprise entities. The core of OpenID Connect is a user **ID token**.

In contrast to access tokens, which are only intended to be understood by the
resource server, ID tokens are intended to be understood by the OAuth client.
When the client makes an OpenID Connect request, it can request an ID token
along with an access token.

OpenID Connect’s ID Tokens take the form of a JWT (JSON Web Token).
Inside the JWT are a handful of defined property names that provide information
to the application:

- sub: subject, identity of the resource owner
- iss: issuer, the server that issues the id token
- aud: audience, identity of the client that requests the id token
- exp: expiration time of the id token
- iat: issued at, the time the token is issued

When OAuth request contains `openid` scope, the above properties should
be present in returned access token.

### OAuth2 framework

## scratch pad

```sh
curl -X 'POST' \
  'http://127.0.0.1:8000/items' \
  -H 'X-Token: a-secret-token-123'  \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "string",
    "price": 0,
    "is_offer": true
    }'
```

## References

A good OAuth2 provider server java implementation tutorial:
https://www.baeldung.com/java-ee-oauth2-implementation
