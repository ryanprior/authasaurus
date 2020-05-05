from flask import Flask
from decorators import auth_required, auth_user
from os import environ
import db

app = Flask(__name__)

@app.route('/')
@auth_required
def index():
    return "ok\n", 200

@app.route('/protected')
@auth_required(users = ['admin'])
def protected():
    return "hello admin\n", 200

@app.route('/<username>/account')
@auth_user
def account_settings(username):
    return "set your password", 200

@app.route('/<user>/history')
@auth_user(arg = "user")
def user_history(user):
    return "set your password", 200


db.make_db()
db.load_salt()
debug = environ.get("AUTHZ_DEBUG", False)
app.run(debug=debug)
