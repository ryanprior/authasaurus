from functools import wraps, partial 
from flask import request, Response
from db import get_user
from settings import max_api_key_length
import re
from http.client import UNAUTHORIZED


token_pattern = r'^Token\s+(.+)$'


def auth_required(func = None, users = None):

    if func is None:
        return partial(auth_required, users = users)    

    @wraps(func)
    def check_auth(*args, **kwargs):
        user = None
        header = request.headers.get('Authorization', '')[:max_api_key_length]
        match = re.search(token_pattern, header)
        if match is None:
            return not_authorized()
        else:
            api_key = match.group(1)
            user = get_user(api_key)
        
        if user is None:
            return not_authorized()
        if users and not user.name in users:
            return not_authorized()
        
        return func(*args, **kwargs)

    return check_auth

def not_authorized():
    return Response('not authorized', UNAUTHORIZED)
