from .schemas import UserInDB

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
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
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
# entity orm models
#

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

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
