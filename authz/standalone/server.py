"""Standalone Authasaurus reverse proxy."""

from flask import Flask, request
from ..decorators import auth_required, auth_user
from .. import service
from ..db import create_user, get_user
from json import dumps as encode

app = Flask(__name__)

def empty(field):
    return (not field) or len(field.strip()) == 0

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    if empty(username):
        return "Request body must include a non empty username.\n", 400
    if get_user(username = username):
        return "Provided username is already registered.\n", 400
    user, password = create_user(username, login = True)
    return encode({
        "username": user.name,
        "password": password
    }), 200

login = app.route("/login", methods=["POST"])(service.login)
logout = app.route("/logout", methods=["POST"])(service.logout)

if __name__ == '__main__':
    address, port = ('127.0.0.1', 8081)
    app.run(debug=True, host=address, port=port)
