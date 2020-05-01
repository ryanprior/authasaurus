import db
db.make_db()
user = db.create_user("dullmann", True)
print(user)