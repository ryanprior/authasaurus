from flask import Flask
from decorators import auth_required
from os import environ
import db

app = Flask(__name__)

@app.route('/')
@auth_required
def index():
    return "ok\n", 200

db.make_db()
db.load_salt()
debug = environ.get("AUTHZ_DEBUG", False)
app.run(debug=debug)
