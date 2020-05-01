import sqlite3
import uuid
import random
import bcrypt
import settings
from dataclasses import dataclass

@dataclass
class User:
    user_id:int
    name:str
    api_key:str
    password_hash:str


connection = sqlite3.connect('authorization.db')

def create_user(username:str, login:bool, retry = 100):

    user_id = random.randint(1000000000, 9999999999)
    api_key = str(uuid.uuid4())
    password = str(uuid.uuid4()) if login else None
    password_hash = bcrypt.hashpw(password.encode("utf-8"), settings.salt) if login else None

    with connection:
        try:
            connection.execute(
                "INSERT INTO USER (Id, Username, PasswordHash, ApiKey) VALUES (?,?,?,?)", 
                (user_id, username, password_hash, api_key))
            return (User(user_id, username, api_key, password_hash), password)
        except sqlite3.IntegrityError:
            # retry in case violation of unique constraint with user id or api key
            if retry > 0:
                return create_user(username, login, retry = retry-1)
            else:
                raise 


def get_user_id(api_key:str):
    with connection:
        cursor = connection.cursor()
        results = curser.execute("SELECT UserId FROM USER WHERE ApiKey = ? ", (api_key,))
        user_id = cursor.fetchone()
        return user_id


def make_db():
    with connection:
        connection.execute('''            
            CREATE TABLE IF NOT EXISTS USER (
                Id INT NOT NULL PRIMARY KEY, 
                Username TEXT, 
                PasswordHash TEXT, 
                ApiKey TEXT NOT NULL UNIQUE)''')
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS ApiKey_Index ON USER(ApiKey)")



