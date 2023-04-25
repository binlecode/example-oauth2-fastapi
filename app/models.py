import json
import time

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base


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
