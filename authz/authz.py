import re
from dataclasses import dataclass
from datetime import datetime
from typing import Tuple, Union
from http.client import UNAUTHORIZED
from flask import Response
from .db import (
    user_from_login,
    api_key,
    deactivate_api_key,
)
from .types import User, UserMaybe, ApiKey
from .settings import max_api_key_length
from .constants import Policies, STATUS_ACTIVE


@dataclass
class Authz:
    user: User
    api_key: ApiKey
    method: str


AuthzMaybe = Union[Authz, None]


HEADER = "api key in header"
COOKIE = "api key in cookie"
BASIC_AUTH = "http basic auth"


# TODO investigate more authz methods:
# - API key in URL
# - Basic HTTP auth


def key_within_policy(key: ApiKey) -> bool:
    if not key.status == STATUS_ACTIVE:
        return False
    check_expiration = lambda exp: datetime.fromisoformat(exp) > datetime.now()
    return {
        Policies.UseForever.name: lambda _: True,
        Policies.UseUntil.name: check_expiration,
        Policies.UseOnceBefore.name: check_expiration,
    }.get(key.policy, lambda _: False)(key.policy_data)


def authenticated_user(request) -> AuthzMaybe:
    methods = (
        (api_key_from_header, HEADER),
        (api_key_from_cookie, COOKIE),
        (lambda r: True, None),
    )
    # try methods until one returns a truthy value
    key_string, method = next(
        ((k, method) for func, method in methods if (k := func(request)))
    )

    # Test whether API key is within policy
    if not method or not (key := api_key(key_string)) or not key_within_policy(key):
        return None
    if key.policy == Policies.UseOnceBefore.name:
        deactivate_api_key(key.key)
    return Authz(user=key.user, api_key=key, method=method)


def login_user(request) -> AuthzMaybe:
    return (
        Authz(user=user, api_key=None, method=BASIC_AUTH)
        if (user := user_from_basic_auth(request))
        else None
    )


def api_key_from_header(request) -> str:
    token_pattern = r"^Token\s+(.+)$"
    auth_header = request.headers.get("Authorization", "")[:max_api_key_length]
    match = re.search(token_pattern, auth_header)
    if match:
        api_key = match.group(1)
        return api_key
    return None


def api_key_from_cookie(request) -> str:
    return request.cookies.get("api-key", None)


def user_from_basic_auth(request) -> UserMaybe:
    authz = request.authorization
    if authz and authz.type == "basic":
        username, password = authz.username, authz.password
        return user_from_login(username, password)
    return None


def not_authorized():
    return Response("not authorized", UNAUTHORIZED)
