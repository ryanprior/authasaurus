from .authz import authenticated_user, not_authorized, login_user
from . import settings
from flask import request, Response, redirect
from functools import wraps, partial
from inspect import signature
from http.client import INTERNAL_SERVER_ERROR

def call_with_authz(func, authz, args, kwargs):
    if signature(func).parameters.get('authz', None):
        return func(*args, authz=authz, **kwargs)
    else:
        return func(*args, **kwargs)

def auth_required(func=None, users=None):

    if func is None:
        return partial(auth_required, users=users)

    @wraps(func)
    def check_auth(*args, **kwargs):
        authz = authenticated_user(request)
        user, *_ = authz

        if user is None:
            return not_authorized()
        if users and not user.name in users:
            return not_authorized()

        # could we do something like authz=innocent(authz)
        # where innocent() removes API keys and pw hashes?
        # or should we have an authz_info dataclass
        return call_with_authz(func, authz, args, kwargs)

    return check_auth


def auth_user(func=None, arg="username"):

    if func is None:
        return partial(auth_user, arg=arg)

    @wraps(func)
    def check_user(*args, **kwargs):
        username = kwargs.get(arg, None)
        if not username:
            return Response("route configuration fault", INTERNAL_SERVER_ERROR)

        authz = authenticated_user(request)
        user, *_ = authz

        if user and user.name == username:
            return call_with_authz(func, authz, args, kwargs)

        return not_authorized()

    return check_user


def auth_login(func):
    @wraps(func)
    def check_login(*args, **kwargs):
        authz = login_user(request)
        user, *_ = authz

        if user is not None:
            return call_with_authz(func, authz, args, kwargs)
        else:
            referrer = request.args.get("referrer") or request.form.get("referrer")
            if referrer is None:
                return not_authorized()
            else:
                return redirect(referrer)

    return check_login
