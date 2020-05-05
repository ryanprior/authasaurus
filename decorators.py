from functools import wraps, partial
from flask import request, Response
from authz import authenticated_user, not_authorized
from http.client import INTERNAL_SERVER_ERROR

def auth_required(func = None, users = None):

    if func is None:
        return partial(auth_required, users = users)

    @wraps(func)
    def check_auth(*args, **kwargs):
        user, _ = authenticated_user(request)

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

        user, _ = authenticated_user(request)

        if user and user.name == username:
            return func(*args, **kwargs)

        return not_authorized()

    return check_user
