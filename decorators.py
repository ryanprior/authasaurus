from functools import wraps
from flask import request, Response
from db import get_user_id
from settings import max_api_key_length
import re
from http.client import UNAUTHORIZED

token_pattern = r'^Token\s+(.+)$'

def not_authorized():
    return Response('not authorized', UNAUTHORIZED)

def auth_required(func):
    @wraps(func)
    def check_auth(*args, **kwargs):
        header = request.headers.get('Authorization', '')[:max_api_key_length]
        match = re.search(token_pattern, header)
        if match is None:
            return not_authorized()
        else:
            api_key = match.group(1)
            if get_user_id(api_key):
                return func(*args, **kwargs)
            else:
                return not_authorized()
    return check_auth
