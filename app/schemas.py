from datetime import datetime
from pydantic import BaseModel, validator, root_validator

#
# a list of pydantic schema models
# they are used in API endpoint request and response validation
#


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

    # a naive example of using custom validator on a property
    @validator("email")
    def validate_bad_email(cls, value):
        if value is not None and "@baddomain.com" in value:
            raise ValueError("user email domain not allowed")
        return value

    @root_validator()
    def validate_email_full_name_both_none(cls, values):
        # values is a dict object that holds property k-vs
        email = values.get("email")
        full_name = values.get("full_name")
        if not email and not full_name:
            raise ValueError("both email and full_name are not given")
        return values


# db user is a subclass of User
# with one more attribute for hashed password
class UserSave(User):
    id: int
    hashed_password: str


class UserRead(User):
    id: int

    # set orm_mode to convert orm to dict for json
    class Config:
        orm_mode = True


class OAuth2ClientCreate(BaseModel):
    client_id: str
    client_secret: str
    client_metadata: dict


class OAuth2ClientUpdate(OAuth2ClientCreate):
    id: int


class OAuth2ClientRead(OAuth2ClientUpdate):
    client_id_issued_at: datetime
    client_secret_expires_at: datetime

    class Config:
        orm_mode = True
