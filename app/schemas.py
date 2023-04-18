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
class UserInDB(User):
    hashed_password: str


class Item(BaseModel):
    name: str
    price: float | None = None  # type float and nullable
    is_offer: bool | None = None  # type boolean and nullable

    # @validator("id")
    # def id_PK(cls, v):
    #     if v is None or v < 0:
    #         raise ValueError(f"id value invalid: {v}")
