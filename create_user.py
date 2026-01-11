from database import SessionLocal
from models import User
from security import hash_password

db = SessionLocal()

users = [
    User(email="admin@example.com", password=hash_password("admin123"), role="admin"),
    User(email="manager@example.com", password=hash_password("manager123"), role="manager"),
    User(email="agent@example.com", password=hash_password("agent123"), role="agent"),
]

db.add_all(users)
db.commit()
db.close()

print("Users created")
