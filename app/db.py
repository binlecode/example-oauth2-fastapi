import json
import time
from typing import Generator
from .schemas import UserInDB
from sqlalchemy import select

fake_client_db = {
    "swagger": {
        "client_id": "swagger",
        "client_secret": "secret",
        # swagger_ui web page is local openapi doc url + '/oauth2-redirect'
        "redirect_uri": "http://localhost:8000/docs/oauth2-redirect",
    },
    "postman": {
        "client_id": "postman",
        "client_secret": "secret",
        # postman
        "redirect_uri": "https://oauth.pstmn.io/v1/callback",
    },
}

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        # the plain password is "secret"
        "hashed_password": "$2b$12$mV7rTpEAAk77POssNFkBfO.F0UvhU5Z2llYTbu3RcS8s8C3S2hNUC",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        # the plain password is "secret2"
        "hashed_password": "$2b$12$Th16FzsG7bexKod7DpgKZORxIpoV1E8hu0Xh/jZOhM2hAJV03HKCu",
        "disabled": True,
    },
}


# query and hydrate user object from db
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


items_db = [
    {"id": 1, "name": "Foo"},
    {"id": 2, "name": "Bar"},
    {"id": 3, "name": "Baz"},
]


def next_item_id():
    max_id = max(itm["id"] for itm in items_db)
    return max_id + 1


# sqlalchemy with datasource sqlite3 db

from sqlalchemy import create_engine
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_db.db"
# SQLALCHEMY_DATABASE_URL = "postgresql://user:password@postgresserver/db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    # add custom DBAPI connect() arguments
    # set check_same_thread to false specifically for sqlite3 file database
    # This is to allow multiple threads to access same connection in FastAPI
    # Ref: https://docs.sqlalchemy.org/en/20/dialects/sqlite.html#pysqlite-threading-pooling
    # check_same_thread custom setting is not needed for other databases
    connect_args={"check_same_thread": False},
    pool_recycle=3600,
    # enable sql statements logging
    echo=True,
)

# define a session maker function
# it is used to create db session (local) for each request thread
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


#
# entity models
#

# define base class for declarative SQLAlchemy model definitions
Base = declarative_base()


class OAuth2Client(Base):
    __tablename__ = "oauth2_client"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(48), index=True)
    client_secret = Column(String(120))
    client_id_issued_at = Column(Integer, nullable=False, default=0)
    client_secret_expires_at = Column(Integer, nullable=False, default=0)
    _client_metadata = Column("client_metadata", Text)

    @property
    def client_metadata(self):
        if "client_metadata" in self.__dict__:
            return self.__dict__["client_metadata"]
        if self._client_metadata:
            data = json.loads(self._client_metadata)
            self.__dict__["client_metadata"] = data
            return data
        return {}

    def set_client_metadata(self, value):
        self._client_metadata = json.dumps(value)
        if "client_metadata" in self.__dict__:
            del self.__dict__["client_metadata"]

    @property
    def redirect_uris(self):
        return self.client_metadata.get("redirect_uris", [])

    @property
    def grant_types(self):
        return self.client_metadata.get("grant_types", [])

    @property
    def response_types(self):
        return self.client_metadata.get("response_types", [])

    @property
    def client_name(self):
        return self.client_metadata.get("client_name")

    @property
    def scope(self):
        return self.client_metadata.get("scope", "")


class OAuth2AuthorizationCode(Base):
    __tablename__ = "oauth2_code"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    user = relationship("User")
    code = Column(String(120), unique=True, nullable=False)
    # no FK to client model because it is optional for code grant
    client_id = Column(String(48))
    redirect_uri = Column(Text, default="")
    response_type = Column(Text, default="")
    scope = Column(Text, default="")
    nonce = Column(Text)
    auth_time = Column(Integer, nullable=False, default=lambda: int(time.time()))
    code_challenge = Column(Text)
    code_challenge_method = Column(String(48))

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return self.auth_time

    def get_nonce(self):
        return self.nonce


class OAuth2Token(Base):
    __tablename__ = "oauth2_token"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    user = relationship("User")

    client_id = Column(String(48))
    token_type = Column(String(40))
    access_token = Column(String(255), unique=True, nullable=False)
    refresh_token = Column(String(255), index=True)
    scope = Column(Text, default="")
    issued_at = Column(Integer, nullable=False, default=lambda: int(time.time()))
    access_token_revoked_at = Column(Integer, nullable=False, default=0)
    refresh_token_revoked_at = Column(Integer, nullable=False, default=0)
    expires_in = Column(Integer, nullable=False, default=0)

    def check_client(self, client):
        return self.client_id == client.get_client_id()

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def is_revoked(self):
        return self.access_token_revoked_at or self.refresh_token_revoked_at

    def is_expired(self):
        if not self.expires_in:
            return False

        expires_at = self.issued_at + self.expires_in
        return expires_at < time.time()

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(40), unique=True, nullable=False, index=True)
    hashed_password = Column(String)
    email = Column(String(128), unique=True, index=True)
    disabled = Column(Boolean, default=False)
    full_name = Column(String)
    items = relationship("Item", back_populates="owner")


class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="items")


#
# crud operations, uses sqlalchemy session and models
#
