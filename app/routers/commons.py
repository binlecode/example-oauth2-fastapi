from typing import Annotated
from fastapi import Depends


# define common parameters to be injected by Depends() in action methods
# useful for common params like q str, pagination, etc
class CommonQueryParams:
    def __init__(self, q: str | None = None, offset: int = 0, limit: int = 10):
        self.q = q
        self.offset = offset
        self.limit = limit


# then define an alias for the annotated type with injected dependency
# this type alias can be used in all action methods that need common params
CommonsQueryParamsDep = Annotated[CommonQueryParams, Depends(CommonQueryParams)]
