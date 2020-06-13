from flask import request, redirect
from .decorators import auth_login, auth_required
from . import settings
from .db import rotate_api_key, create_api_key
from datetime import datetime, timedelta


@auth_login
def login(authz):
    """If the client provides appropriate credentials, issue them an API key and
    send it to them in a cookie with a rediret.

    If a "redirect" request argument is provided, use that URL; otherwise use
the root.

    """
    url = request.args.get("redirect") or request.form.get("redirect", "/")
    response = redirect(url)
    api_key = create_api_key(authz.user.user_id, 2, datetime.now() + timedelta(days=10))
    response.set_cookie(
        "api-key",
        value=api_key.key,
        max_age=60 * 60 * 24 * 10,  # 10 days
        secure=True,
        httponly=(not settings.allow_javascript_to_read_api_key),
        samesite="Lax",
    )
    return response

@auth_required
def logout(authz):
    url = request.args.get("redirect") or request.form.get("redirect", "/")
    response = redirect(url)
    rotate_api_key(authz.api_key.key)
    return response
