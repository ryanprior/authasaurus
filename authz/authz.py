import re
from http.client import UNAUTHORIZED
from flask import Response
from .db import get_user, user_from_login
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


def authenticated_user(request):
    methods = (
        (api_key_from_header, HEADER),
        (api_key_from_cookie, COOKIE),
        (lambda r: True, None),
    )
    # try methods until one returns a truthy value
    api_key, method = next(
        ((key, method) for func, method in methods if (key := func(request)))
    )

    if method:
        return get_user(api_key = api_key), api_key, method
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
