from datetime import datetime
from .db import engine
from .db import SessionLocal
from .models import Base, User, OAuth2Client


def init_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    # load initial data
    session = SessionLocal()

    u1 = User(
        username="johndoe",
        full_name="John Doe",
        email="johndoe@example.com",
        # plain pswd: "secret"
        hashed_password="$2b$12$mV7rTpEAAk77POssNFkBfO.F0UvhU5Z2llYTbu3RcS8s8C3S2hNUC",
    )
    u2 = User(
        username="alice",
        full_name="Alice Wonderson",
        email="alice@example.com",
        # plain pswd: "secret2"
        hashed_password="$2b$12$Th16FzsG7bexKod7DpgKZORxIpoV1E8hu0Xh/jZOhM2hAJV03HKCu",
    )
    session.add_all([u1, u2])
    session.commit()

    # add oauth2 clients
    oc1 = OAuth2Client(
        client_id="swagger",
        client_secret="secret",
        client_id_issued_at=datetime.utcnow(),
    )
    oc1.set_client_metadata(
        {
            "client_name": "swagger",
            "client_uri": "http://localhost",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["http://127.0.0.1:8000/docs/oauth2-redirect"],
            "response_types": ["code"],
            "scope": "profile openid email",
            "token_endpoint_auth_method": ["client_secret_basic"],
        }
    )
    oc2 = OAuth2Client(
        client_id="postman",
        client_secret="secret",
        client_id_issued_at=datetime.utcnow(),
    )
    oc2.set_client_metadata(
        {
            "client_name": "postman",
            "client_uri": "http://localhost",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["https://oauth.pstmn.io/v1/callback"],
            "response_types": ["code"],
            "scope": "profile openid email",
            "token_endpoint_auth_method": ["client_secret_basic"],
        }
    )
    session.add_all([oc1, oc2])
    session.commit()
