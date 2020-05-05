from flask import request, Response
import re
from settings import max_api_key_length
from http.client import UNAUTHORIZED
from db import get_user

API_KEY="api key"
COOKIE="cookie"

token_pattern = r'^Token\s+(.+)$'

# TODO investigate more authz methods:
# - API key in URL
# - HTTP basic auth

def authenticated_user(request):
    api_key = api_key_from_header(request)
    if api_key:
        return get_user(api_key), API_KEY
    else:
        api_key = api_key_from_cookie(request)
        if api_key:
            return get_user(api_key), COOKIE
    return None, None

def api_key_from_header(request):
    auth_header = request.headers.get('Authorization', '')[:max_api_key_length]
    match = re.search(token_pattern, auth_header)
    if match is None:
        return None
    else:
        api_key = match.group(1)
        return api_key

def api_key_from_cookie(request):
    return request.cookies.get('api-key', None)


def not_authorized():
    return Response('not authorized', UNAUTHORIZED)
