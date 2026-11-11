"""Create the first administrator: python -m scripts.create_admin."""
from getpass import getpass
from sqlalchemy import select
from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models import User

def main() -> None:
    username = input("Admin username (3-64 chars): ").strip()
    if not 3 <= len(username) <= 64:
        raise SystemExit("Username must contain 3-64 characters.")
    password = getpass("Admin password (minimum 12 characters): ")
    confirmation = getpass("Confirm password: ")
    if len(password) < 12 or password != confirmation:
        raise SystemExit("Passwords must match and contain at least 12 characters.")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == username)):
            raise SystemExit("That username already exists.")
        db.add(User(username=username, password_hash=hash_password(password), role="admin", is_active=True))
        db.commit()
        print(f"Administrator '{username}' created.")

if __name__ == "__main__":
    main()
