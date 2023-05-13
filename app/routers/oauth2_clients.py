from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from config import Config
from ..db import get_db
from .oauth2 import get_current_active_user

from .. import schemas

from ..models import User, OAuth2Client

router = APIRouter(
    prefix="/clients",
    tags=["clients"],
    dependencies=[],
)


@router.get("/", response_model=list[schemas.OAuth2ClientRead])
async def read_clients(
    # OPTIONAL: secured by user token
    # current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    offset: int = 0,
    limit: int = Config.PAGINATION_LIMIT,
):
    clients = db.query(OAuth2Client).offset(offset).limit(limit).all()
    return clients


@router.get("/{id}", response_model=schemas.OAuth2ClientRead)
def read_client(id: int, db: Session = Depends(get_db)):
    client = db.query(OAuth2Client).get(id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2Client not found"
        )
    return client


@router.post(
    "/", response_model=schemas.OAuth2ClientRead, status_code=status.HTTP_201_CREATED
)
def create_client(
    # current_user: User = Depends(get_current_active_user),
    client_data: schemas.OAuth2ClientCreate,
    db: Session = Depends(get_db),
):
    client = OAuth2Client(
        client_id=client_data.client_id,
        client_secret=client_data.client_secret,
    )
    client.set_client_metadata(client_data.client_metadata)
    db.add(client)
    db.commit()
    db.refresh(client)
    return client


@router.put(
    "/{id}", response_model=schemas.OAuth2ClientRead, status_code=status.HTTP_200_OK
)
def update_client(
    # current_user: User = Depends(get_current_active_user),
    id: str,
    client_data: schemas.OAuth2ClientUpdate,
    db: Session = Depends(get_db),
):
    client = db.query(OAuth2Client).filter(OAuth2Client.id == id).first()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2Client not found"
        )
    client.client_id = client_data.client_id
    client.client_secret = client_data.client_secret
    client.set_client_metadata(client_data.client_metadata)
    db.commit()
    db.refresh(client)
    return client
