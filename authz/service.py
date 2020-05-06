from flask import request, redirect
from authz.decorators import auth_login
from authz import settings

# @app.route('/login', methods = ['POST'])
@auth_login
def login(api_key):
    url = request.args.get('redirect') or request.form.get('redirect')
    response = redirect(url)
    response.set_cookie("api-key", api_key)
    return response
