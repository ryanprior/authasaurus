import re
from datetime import datetime
from typing import Tuple
from http.client import UNAUTHORIZED
from flask import Response
from .db import User, ApiKey, get_user, user_from_login, api_key
from .settings import max_api_key_length
from .constants import (
    POLICY_USE_FOREVER,
    POLICY_USE_UNTIL,
    POLICY_USE_ONCE_BEFORE,
    POLICY_ROTATE_EVERY,
)

HEADER = "api key in header"
COOKIE = "api key in cookie"
BASIC_AUTH = "http basic auth"


# TODO investigate more authz methods:
# - API key in URL
# - Basic HTTP auth


def key_within_policy(key: ApiKey) -> bool:
    check_expiration = lambda exp: datetime.fromisoformat(exp) > datetime.now()
    return {
        POLICY_USE_FOREVER: lambda _: True,
        POLICY_USE_UNTIL: check_expiration,
        POLICY_USE_ONCE_BEFORE: check_expiration,
        POLICY_ROTATE_EVERY: lambda _: True,
    }.get(key.policy, lambda _: False)(key.policy_data)


def authenticated_user(request) -> Tuple[User, ApiKey, str]:
    methods = (
        (api_key_from_header, HEADER),
        (api_key_from_cookie, COOKIE),
        (lambda r: True, None),
    )
    # try methods until one returns a truthy value
    key_string, method = next(
        ((key, method) for func, method in methods if (key := func(request)))
    )

    if not method:
        return None, None, None
    if key := api_key(key_string):
        # Test whether API key is within policy
        return (key.user, key, method) if key_within_policy(key) else (None, None, None)
    return None, None, None


def login_user(request):
    return user_from_basic_auth(request), None, BASIC_AUTH


def api_key_from_header(request):
    token_pattern = r"^Token\s+(.+)$"
    auth_header = request.headers.get("Authorization", "")[:max_api_key_length]
    match = re.search(token_pattern, auth_header)
    if match:
        api_key = match.group(1)
        return api_key
    return None


def api_key_from_cookie(request):
    return request.cookies.get("api-key", None)


def user_from_basic_auth(request):
    authz = request.authorization
    if authz and authz.type == "basic":
        username, password = authz.username, authz.password
        return user_from_login(username, password)
    return None


def not_authorized():
    return Response("not authorized", UNAUTHORIZED)
