from flask import request, redirect
from authz.decorators import auth_login
from authz import settings

# @app.route('/login', methods = ['POST'])
@auth_login
def login(api_key):
    url = request.args.get('redirect') or request.form.get('redirect')
    response = redirect(url)
    response.set_cookie("api-key",
                        value=api_key,
                        max_age=60*60*24*10, # 10 days
                        secure=True,
                        httponly=(not settings.allow_javascript_to_read_api_key),
                        samesite="Lax")
    return response
