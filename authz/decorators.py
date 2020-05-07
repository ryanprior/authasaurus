from .authz import authenticated_user, not_authorized, api_key_from_basic_auth
from . import settings
from flask import request, Response, redirect
from functools import wraps, partial
from http.client import INTERNAL_SERVER_ERROR


def auth_required(func=None, users=None):

    if func is None:
        return partial(auth_required, users=users)

    @wraps(func)
    def check_auth(*args, **kwargs):
        user, _ = authenticated_user(request)

        if user is None:
            return not_authorized()
        if users and not user.name in users:
            return not_authorized()

        return func(*args, **kwargs)

    return check_auth


def auth_user(func=None, arg="username"):

    if func is None:
        return partial(auth_user, arg=arg)

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


def auth_login(func):
    @wraps(func)
    def check_login(*args, **kwargs):
        api_key = api_key_from_basic_auth(request)
        if api_key is not None:
            return func(*args, api_key=api_key, **kwargs)
        else:
            referrer = request.args.get("referrer") or request.form.get("referrer")
            if referrer is None:
                return not_authorized()
            else:
                return redirect(referrer)

    return check_login
