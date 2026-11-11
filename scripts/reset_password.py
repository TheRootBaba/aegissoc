"""Interactively rotate a local AegisSOC account password.

Run inside the API container: python -m scripts.reset_password
"""
from getpass import getpass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models import User


def reset_password(db: Session, username: str, new_password: str) -> bool:
    """Replace an existing user's password hash; return False if the user is absent."""
    if len(new_password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        return False
    user.password_hash = hash_password(new_password)
    db.commit()
    return True


def main() -> None:
    username = input("Account username: ").strip()
    password = getpass("New password (minimum 12 characters): ")
    confirmation = getpass("Confirm new password: ")
    if len(password) < 12 or password != confirmation:
        raise SystemExit("Passwords must match and contain at least 12 characters.")
    with SessionLocal() as db:
        if not reset_password(db, username, password):
            raise SystemExit("No account exists with that username.")
    print(f"Password updated for '{username}'. Existing access tokens remain valid until they expire.")


if __name__ == "__main__":
    main()
