"""Simple Flask web service to test authz flows."""

from logging import basicConfig, NOTSET
from os import environ as env
from flask import Flask
from ..decorators import auth_required, auth_user
from .. import service

app = Flask(__name__)


@app.route("/")
@auth_required
def index():
    """Send ok if authorized as any user."""
    return "ok\n", 200


@app.route("/protected")
@auth_required(users=["admin"])
def protected():
    """Greet admin; reject others."""
    return "hello admin\n", 200


@app.route("/<username>/account")
@auth_user
def account_settings(username):
    """Show a message only to the authorized user whose name matches the USERNAME param."""
    return "set your password", 200


@app.route("/<user>/history")
@auth_user(arg="user")
def user_history(user):
    """Show a message only to the authz user whose name matches the USER param."""
    return "set your password", 200


login = app.route("/login", methods=["POST"])(service.login)
logout = app.route("/logout", methods=["POST"])(service.logout)

basicConfig(filename=f"{env.get('TEST_DATA_DIR', '.')}/wsgi.log", level=NOTSET)
app.run(debug=True)
