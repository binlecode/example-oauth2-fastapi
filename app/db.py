from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config import Config

# SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_db.db"
SQLALCHEMY_DATABASE_URL = Config.SQLALCHEMY_DATABASE_URI

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


# prefer context-manager (with .. as ..) syntax, which auto-closes session
def get_db():
    with SessionLocal() as db:
        yield db
