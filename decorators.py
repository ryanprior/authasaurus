from functools import wraps, partial 
from flask import request, Response
from db import get_user
from settings import max_api_key_length
import re
from http.client import UNAUTHORIZED, INTERNAL_SERVER_ERROR


token_pattern = r'^Token\s+(.+)$'


def auth_required(func = None, users = None):

    if func is None:
        return partial(auth_required, users = users)    

    @wraps(func)
    def check_auth(*args, **kwargs):
        user = authenticated_user(request)

        if user is None:
            return not_authorized()
        if users and not user.name in users:
            return not_authorized()
        
        return func(*args, **kwargs)

    return check_auth


def auth_user(func = None, arg = "username"):
    
    if func is None:
        return partial(auth_user, arg = arg)
    
    @wraps(func)
    def check_user(*args, **kwargs):
        username = kwargs.get(arg, None)
        if not username:
            return Response("route configuration fault", INTERNAL_SERVER_ERROR)      
        
        user = authenticated_user(request)

        if user and user.name == username:
            return func(*args, **kwargs)
        
        return not_authorized()
    
    return check_user

        


def authenticated_user(request):
    auth_header = request.headers.get('Authorization', '')[:max_api_key_length]
    match = re.search(token_pattern, auth_header)
    if match is None:
        return None
    else:
        api_key = match.group(1)
        return get_user(api_key)

def not_authorized():
    return Response('not authorized', UNAUTHORIZED)
