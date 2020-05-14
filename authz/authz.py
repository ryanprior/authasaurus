from .db import get_user, api_key_from_login
from .settings import max_api_key_length
from flask import Response
from http.client import UNAUTHORIZED
import re

HEADER = "api key in header"
COOKIE = "api key in cookie"
BASIC_AUTH = "http basic auth"

token_pattern = r"^Token\s+(.+)$"

# TODO investigate more authz methods:
# - API key in URL


def authenticated_user(request):
    methods = (
        (api_key_from_header, HEADER),
        (api_key_from_cookie, COOKIE),
        (api_key_from_basic_auth, BASIC_AUTH),
        (lambda r: True, None),
    )
    # try methods until one returns a truthy value
    api_key, method = next(
        ((key, method) for func, method in methods if (key := func(request)))
    )

    if method:
        return get_user(api_key), method
    return None, None


def login_user(request):
    api_key = api_key_from_basic_auth(request)
    if api_key:
        return get_user(api_key), BASIC_AUTH
    return None, None


def api_key_from_header(request):
    auth_header = request.headers.get("Authorization", "")[:max_api_key_length]
    match = re.search(token_pattern, auth_header)
    if match:
        api_key = match.group(1)
        return api_key
    return None


def api_key_from_cookie(request):
    return request.cookies.get("api-key", None)


def api_key_from_basic_auth(request):
    authz = request.authorization
    if authz and authz.type == "basic":
        username, password = authz.username, authz.password
        return api_key_from_login(username, password)
    return None


def not_authorized():
    return Response("not authorized", UNAUTHORIZED)
