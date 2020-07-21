"""A single module that imports all external data types."""

from .db import User, UserMaybe, ApiKey, ApiKeyMaybe
from .constants import Policy
from dataclasses import dataclass
from typing import Tuple, Union

@dataclass
class Authz:
    user: User
    api_key: ApiKey
    method: str

AuthzMaybe = Union[Authz, None]
