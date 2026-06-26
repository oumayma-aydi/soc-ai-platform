"""
Script à lancer UNE SEULE FOIS pour créer le premier compte Super Admin.
Usage : python scripts/create_first_admin.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.database import SessionLocal
from app.services.user_service import create_user, get_user_by_username


def main():
    db = SessionLocal()
    try:
        username = input("Nom d'utilisateur du Super Admin : ").strip()
        email = input("Email : ").strip()

        import getpass
        password = getpass.getpass("Mot de passe (min 8 caractères) : ")
        password_confirm = getpass.getpass("Confirmer le mot de passe : ")

        if password != password_confirm:
            print("❌ Les mots de passe ne correspondent pas.")
            return

        if len(password) < 8:
            print("❌ Le mot de passe doit faire au moins 8 caractères.")
            return

        if get_user_by_username(db, username):
            print(f"❌ L'utilisateur '{username}' existe déjà.")
            return

        user = create_user(db, username, email, password, role="admin")
        print(f"✅ Super Admin créé avec succès : {user.id} ({user.username})")

    finally:
        db.close()


if __name__ == "__main__":
    main()
