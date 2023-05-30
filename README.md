# A basic OAuth2 authorization server with FastAPI framework

This is a PoC implementation of an OAuth2 authorization
server with plain python. FastAPI is used as the stack framework.

FastAPI is ASGI framework, it supports sync and async request handling seamlessly.
Think of FastAPI as the glue that brings together Starlette, Pydantic, OpenAPI,
and JSON Schema.

A mature OAuth2 python library to use in implementing a production OAuth2
provider service is [authlib](https://github.com/lepture/authlib).

Table of content:

- [A basic OAuth2 authorization server with FastAPI framework](#a-basic-oauth2-authorization-server-with-fastapi-framework)
  - [project setup](#project-setup)
  - [Dockerfile](#dockerfile)
  - [GKE cluster deployment](#gke-cluster-deployment)
    - [build image and deploy workload](#build-image-and-deploy-workload)
    - [expose workload with ingress, static IP and TLS](#expose-workload-with-ingress-static-ip-and-tls)
  - [OpenApi doc endpoint](#openapi-doc-endpoint)
  - [Pre-register client applications in database](#pre-register-client-applications-in-database)
  - [OAuth2 framework implementation](#oauth2-framework-implementation)
    - [core entities](#core-entities)
    - [federated IdP user authentication](#federated-idp-user-authentication)
    - [code grant](#code-grant)
      - [authorization code](#authorization-code)
    - [implicit grant](#implicit-grant)
    - [user password grant](#user-password-grant)
      - [user password hashing](#user-password-hashing)
    - [client credentials grant](#client-credentials-grant)
    - [token response](#token-response)
    - [OAuth2 access token and bearer token](#oauth2-access-token-and-bearer-token)
    - [self-encoded token encoding](#self-encoded-token-encoding)
    - [client application registration](#client-application-registration)
    - [client application redirect\_uri validation](#client-application-redirect_uri-validation)
  - [access token JWT signing and JWKS endpoint](#access-token-jwt-signing-and-jwks-endpoint)
    - [openssl key generation](#openssl-key-generation)
    - [python cryptography key generation](#python-cryptography-key-generation)
  - [OAuth2 and OpenID connect](#oauth2-and-openid-connect)

## project setup

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
# reset local sqlite db during app start up
RESET_DB=true uvicorn app.main:app --reload
```

By default, uvicorn web server listens at port 8000.
Therefore, default OAuth2 endpoint url base is set to http://127.0.0.1:8000.

To change port number, say, 8080:

```sh
OAUTH2_URL_BASE=http://127.0.0.1:8080 \
RESET_DB=true \
  uvicorn app.main:app --reload --port=8080
```

## Dockerfile

Build docker image and run container locally:

```sh
docker build -t example-oauth2-fastapi .

# run docker container with env vars
docker run --name example-oauth2-fastapi -p 8080:8080 \
  -e LOG_LEVEL=DEBUG \
  -e OAUTH2_URL_BASE=http://127.0.0.1:8080 \
  -e RESET_DB=true \
  --rm example-oauth2-fastapi
```

## GKE cluster deployment

### build image and deploy workload

Use Google cloud builds service to build and upload image to
gcr repository:

```sh
export VER=1.0.7
# gcloud builds --project <project-id> \
#   submit --tag gcr.io/<project-id>/<app-name>:<ver-or-tag> .
gcloud builds --project poc-data-platform-289915 \
    submit --tag gcr.io/poc-data-platform-289915/oauth2-fastapi:v$VER .
```

Before deployment, create or update the GKE configmap to support
application configuration.

```sh
kubectl apply -f gke-configmap.yaml
```

Use `sed` to update [gke-deployment.yaml](./gke-deployment.yaml) manifest to
for the desired image version and configmap, then deploy the workload:

```sh
export VER=1.0.7
# linux
# sed -i "/oauth2-fastapi:/s/v.*/v$ver/" gke-deployment.yaml
# macos
sed -i '' -e "/oauth2-fastapi:/s/v.*/v$VER/" gke-deployment.yaml
kubectl apply -f gke-deployment.yaml
```

If there's no change in application, but only configuration update, then
workload deployment is not needed. Instead, we can use kubectl scale to
refresh workload.

```sh
kubectl describe deployment oauth2-fastapi
kubectl scale deployment oauth2-fastapi --replicas=0
kubectl scale deployment oauth2-fastapi --replicas=1
```

### expose workload with ingress, static IP and TLS

To expose the workload, there are two options:

- option1: expose workload with LoadBalancer service
- option2: expose workload with NodePort service + Ingress load balancer

Both options create an external load balancer with an external IP.
This external IP, by default, is dynamically generated by GCP, and is recycled
when the service is deleted.

For a more realistic deployment for an OAuth2 provider, a static external IP
is preferred. To create a static IP:

```sh
gcloud compute addresses create oauth2-fastapi-static-ip --global

# check created
gcloud compute addresses list | grep oauth2-fastapi
->
oauth2-fastapi-static-ip   34.117.165.110  EXTERNAL RESERVED
```

With static ip enabled in ingress manifest, apply it:

```sh
kubectl apply -f gke-np-service-ingress-tls.yaml
# check
kubectl get service | grep oauth2-fastapi
kubectl get ingress | grep oauth2-fastapi
->
oauth2-fastapi-ingress   <none>   *       34.117.165.110   80, 443   12m
```

To check in-cluster service access,
create a temp standalone pod, and test calling service via cluster DNS name.

```sh
kubectl run tmp-shell --rm -i --tty --restart=Never --image python:3.9 -- bin/bash

root@tmp-shell:/# curl http://oauth2-fastapi-service.default.svc.cluster.local:80/health
->
{"status":"up"}
```

To use the created static IP, update `OAUTH2_URL_BASE` in
[configmap](./gke-configmap.yaml) manifest and apply change.

The workload needs to be refreshed to take the updated config, by using
`kubectl scale` command described above.

## OpenApi doc endpoint

Openapi doc v3 is auto-generated by fastapi framework, and served at url:
http://127.0.0.1:8000/docs

With openapi doc loaded in swagger editor interface, it is recommended to use
it for interactive requests during development.

An openapi v2 doc yaml file is available [openapi_v2.yaml](openapi_v2.yaml).
This yaml can be loaded to an online swagger-UI editor for testing.

An OAuth 2 client is pre-registered for the official swagger-ui (https://editor.swagger.io/).

## Pre-register client applications in database

For demo/testing, the embedded sqlite database has an initial migration script
that loads three pre-defined oauth2 clients:

- local swagger UI client, via built-in openapi v3 '/docs' endpoint
- postman client
- online swagger editor client (https://editor.swagger.io/)

See: [db_migration.py](app/db_migration.py).

Properties, such as client credentials, redirect_uri, grant_types, token scopes,
can be used in swagger UI or postman authorization flows.

For example, for online-swagger client, paste the content of
[openapi_v2.yaml](openapi_v2.yaml) to https://editor.swagger.io.
To authorize with code grant flow, check client entity and user entity
specified in the database migration script and set:

- client_id=online-swagger
- client_secret=secret

And choose one of the two preloaded users, `johndoe` and `alice`, with his/her
respective password for authentication and token scope grant.

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

### core entities

A good java implementation tutorial is helpful to learn basic
OAuth2 concept is: https://www.baeldung.com/java-ee-oauth2-implementation.

### federated IdP user authentication

OAuth2 doesn't standardize user authentication.
The authorization server delegates the user authentication to an Identity
Provider (IdP). If the IdP is not local but a third party entity, this
becomes a federated user authentication.

The authorization endpoint redirects the user to be authenticated with
an IdP, if user is not authenticated yet.

Usually the IdP should have some sort of endpoint or web interface to
receive and validate user credentials. There are standard protocols designed
for this, such as OpenID connect and SAML.

In this example, an IdP with a web form user login interface is provided
in a different route path, to mimic a third party IdP. It can be from any
url or domain.

This delegated user authentication, aka a federated user identity retrieval,
is essentially a redirection flow, where the user-agent (web browser) serves
as the intermediary:
user is redirected to the IdP's authentication page, upon successful
authentication, user is redirected back to the authorization callback url,
where user approves the token grant, then redirected to the `redirect_uri`
from the original client application's request with the grant asset, which
is either an authorization code (code grant), or an access_token (implicit
grant).

The use of the user's web browser as an intermediary allows the
authorization server to receive the user's authentication response
from the IdP without needing to expose the user's credentials to the
client or the authorization server.
The redirect_uri in the original request is the callback endpoint
of the client application. In the use case of code grant, the client
application callback endpoint should handle the received authorization code
and POST to authorization server's /token endpoint to exchange for the
access token.

### code grant

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

#### authorization code

The authorization code should be hard to guess or interpret. It must be short
lived, usually with a time window of a few minutes. To implement, the code
can be a self-contained token with expiration time encoded, so that it can be
checked when it is passed to authorization server in exchange for the access
token. This avoids the session state on the authorization server side to
track the code lifetime.

### implicit grant

The client application calls `/authorize` endpoint with `response_type=token`.
The authorization server responds with access token and redirect
the client application to the callback URL given in the request.

### user password grant

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

#### user password hashing

Create hash string for a password before saving to database.

In python/ipython venv: run below script:

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
password = "secret"
hashed_password = pwd_context.hash(password)
```

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
when a new client application is being registered.

Not specified by OAuth2 specs, but typically the following information is
collected during client registration:

- client (application) name
- callback_uri (aka redirect_uri)
  - this can be a list or a comma-separated string to store multiple
    redirect_uri's, during the authorization flow the redirect_uri provided
    in the request should be checked against this list
- grant types: one or more grant types that this client can be authorized
  by resource owner
- scope: one or more token scopes that this client can be authorized by resource
  owner
- token endpoint auth methods: the methods that the token endpoint can use to
  authenticate the client, some common options are:
  - client_secret_basic: http basic auth header
  - client_secret_post: post body, either form or JSON
  - client_secret_jwt: openID connect jwt bearer token containing client secret
  - private_key_jwt: openID connect jwt bearer token containing private key
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

## access token JWT signing and JWKS endpoint

By OAuth2 specs, authorization server should provide JSON Web Key (JWK)
Set (JWKS) endpoint for token-receiving parties to verify the issued JWT
token signature, specifically with RSA signing algorithm.
Two signing algorithms are commonly used in signing a JWT:

- RS256: stands for RS256+SHA256, RS256 is for signing, SHA256 is for hashing
  RS256 encrypts with an asymmetric key pair, which means a private key is used
  to sign the JWT and a public key must be used to verify the signature
  RS256 is usually preferred due to its asymmetric nature to support 3rd party
  (public) key sharing
- HS256: stands for HMAC+SHA256, HMAC is for signing
  HS256 encrypts with symmetric key, which means the JWT is signed and
  validated by the same key

### openssl key generation

For HS256 symmetric key signing, a simple random key can be generated with
openssl:

```sh
openssl rand -hex 32
09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7
```

RSA asymmetric algorithm should be used for OAuth 2 JWT signing, with its
public key being distributed via the JWKS endpoint, which is usually at
"<auth-server-url-root>/oauth2/jwks" (legacy path) or under well-known URI
(IETF 8615 https://datatracker.ietf.org/doc/html/rfc8615):
"<auth-server-url-root>/.well-known/jwks.json".

Use `openssl` to generate RSA private key pem file:

```sh
# genrsa command generates rsa key pair, and saves to a pem file
# the pem file has header:
# `-----BEGIN RSA PRIVATE KEY-----`
openssl genrsa -out rsa-private-key.pem 2048

# genpkey command is newer and more general, and is preferred over genrsa
# the pem file has header:
# `-----BEGIN PRIVATE KEY-----`
openssl genpkey -algorithm RSA -out rsa-private-key.pem -pkeyopt rsa_keygen_bits:2048
```

Generate the public key from the private key:

```sh
openssl rsa -in rsa-private-key.pem -pubout -outform PEM -out rsa-public-key.pem
```

The key pair files can be loaded in authorization server and used in
signing jwt tokens.

However, this may not be sufficient when the key
pair is required to be:

- rotated for certain period of time for enhanced security
- client specific for enhanced tenancy isolation

In such case, the key pair should be generated programmatically.

### python cryptography key generation

In Python, the [cryptography lib](https://cryptography.io/en/latest/) is
widely used for cryptography implementations, including RS256.

> Notes on RSA private key PEM formats:
> RSA private key files stored in PEM format typically have PKCS#1 or PKCS#8
> encoding. PKCS#8 is a more recent standard that defines a syntax for encoding
> private keys. It supports RSA as well as other key types. That's why
> its pem header is `BEGIN PRIVATE KEY` rather than `BEGIN RSA PRIVATE KEY` as
> in PKCS#1 format.

> Notes on RSA public key pem formats:
> RSA public keys stored in PEM format can be in either X.509 or PKCS#1 format.
> X.509 is a widely-used for SSL/TLS certificates and code signing.
> PKCS#1 defines the syntax for RSA encryption and decryption operations.
> A PKCS#1 PEM format contains the key's modulus and exponent, and is used
> primarily for secure session key exchange and digital signatures.

```python
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate RSA key pair programmatically.
# `public_exponent` is a prime integer, which should be sufficiently large
# to make generated keys secure
# 65537 is what industry commonly uses to generate secure rs256 private keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Alternatively, load an existing private key from a pem file like the
# one generated by openssl utility above.
# pem file has to be read in binary mode ("rb")
src_private_key_pem = open("rsa-private-key.pem", "rb").read()
private_key = serialization.load_pem_private_key(
    src_private_key_pem,
    password=None,
    backend=default_backend()
)

# extract public key from private key
public_key = private_key.public_key()

# we can also export pem binary from the key object
# format: TraditionalOpenSSL => header `BEGIN RSA PRIVATE KEY`
# format: PKCS#8 => header `BEGIN PRIVATE KEY`
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    # format=serialization.PrivateFormat.TraditionalOpenSSL,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# The exported byte array should match the source version
# if not match, usually the difference is in pem format header
assert private_key_pem == src_private_key_pem

# similarly, we can export pem binary from public key object
# format: X.509 SubjectPublicKeyInfo => PEM header: BEGIN PUBLIC KEY
# format: PKCS#1 Raw PKCS#1 => PEM header: BEGIN RSA PUBLIC KEY
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    # format=serialization.PublicFormat.PKCS1
)

# The public key needs to be converted to string format for JSON web key (jwk)
# creation.
# Inside the jose.jwk.construct util, the low-level processing is basically
# extracting public key's public number modulus (n) and exponent (e), and
# convert them to url-safe base64 encoded string values for jwks JSON
# serialization.

public_key_str = public_key_pem.decode("utf-8")

from jose import jwk

jwk_obj = jwk.construct(public_key_str, algorithm="RS256")

jwk_dict = jwk_obj.to_dict()

# attach key id and usage keys
jwk_dict.update({
    # key id
    "kid": "my-kid",
    # usage key for jwk, "sig" means for signing/signature
    "use": "sig",
})

jwks = {
    "keys": [jwk_dict]
}
jwks_json = json.dumps(jwks)

# To use jwks json for jwt validation:
# first, construct jwk object from jwk dict
# then, extract public_key from jwk
jwk_obj = jwk.construct(jwk_dict, algorithm="RS256")
pub_key = jwk_obj.public_key()

# it turns out that the jwk_obj is pub_key itself, just different representation
import jose

assert type(jwk_obj) == type(pub_key) == jose.backends.cryptography_backend.CryptographyRSAKey

# to_pem() takes two format options:
# PKCS1 => header `BEGIN RSA PUBLIC KEY`
# PKCS8 (default) => header `BEGIN PUBLIC KEY`
pub_key_pem = pub_key.to_pem(
    pem_format="PKCS8"
)
pub_key_str = pub_key_pem.decode("utf-8")

# the jwk extracted pub_key pem byte array should match its source byte array
assert public_key_pem == pub_key_pem
assert public_key_str == pub_key_str

# now: Verify JWT signature using public key
from jose import jwt, JWTError

jwt_str = "<JWT string to validate>"

# jwt.decode can take different format of public key content for validation
try:
    decoded = jwt.decode(jwt_str, key=jwk_dict, algorithms=["RS256"])
    decoded = jwt.decode(jwt_str, key=pub_key, algorithms=["RS256"])
    decoded = jwt.decode(jwt_str, key=pub_key_pem, algorithms=["RS256"])
    decoded = jwt.decode(jwt_str, key=pub_key_str, algorithms=["RS256"])
except JWTError as e:
    print(e)

# under the hood, jwt.decode is a wrapper of jws.verify() util
# jws.verify() splits the token into header, payload and signature segments, and validate each of them with provided key
from jose import jws

jwt_payload = jws.verify(jwt_str, jwk_dict, ["RS256"])
```

## OAuth2 and OpenID connect

OAuth 2 only defines authorization specs, leaves authentication up to the
identity provider (IdP). This potential gap of authentication **protocol**
standardization is filled by OpenID Connect.

Besides authorization, OAuth 2 framework can also be used to implement
authentication and identity protocol:

- provide an endpoint for user information, which usually exposes the
  `/userinfo` endpoint
- define authorization scopes dedicated for user identify and information,
  such as `openid`, `profile`, etc

To call `useinfo` endpoint, the request must be POST.

```sh
curl -X 'POST' \
  'http://127.0.0.1:8000/oauth2/userinfo' \
  -H 'X-Token: a-secret-token-123'  \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d {}
```

OpenID Connect protocol can be used to carry user id and other information
between enterprise entities. The core of OpenID Connect is user **ID token**.

In contrast to access tokens, which are only intended to be understood by the
resource server, ID tokens are intended to be understood by the OAuth client.
When the client makes an OpenID Connect request, it can request an ID token
along with an access token.

OpenID Connect’s ID Tokens take the form of a JWT (JSON Web Token).
Inside the JWT are a handful of defined properties that provide information
to the client application:

- sub: subject, identity of the resource owner
- iss: issuer, the server that issues the id token
- aud: audience, identity of the client that requests the id token
- exp: expiration time of the id token
- iat: issued at, the time the token is issued

When OAuth request contains `openid` scope, the above properties should
be present in returned access token.

In addition, OpenID Connect provides a set of standard claims that can be
included in the ID token, such as the user's name, email address, and preferred
language. Additional custom claims can be added too.

Besides ID token, OpenID Connect protocol also defines a well-known discovery
endpoint, `<domain>/.well-known/openid-configuration`.
See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
