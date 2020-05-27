from flask import request, redirect
from .decorators import auth_login, auth_required
from . import settings
from .db import rotate_api_key, create_api_key
from datetime import datetime, timedelta

@auth_login
def login(authz):
    url = request.args.get("redirect") or request.form.get("redirect", "/")
    response = redirect(url)
    user, _ = authz
    api_key = create_api_key(user.user_id, 2, datetime.now() + timedelta(days=10))
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
    user, _ = authz
    rotate_api_key(user)
    return response

