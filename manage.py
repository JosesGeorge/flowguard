"""
FlowGuard management CLI.

Commands:
  create-admin   Interactively create the first (or additional) admin account.
  list-users     List all user accounts.

Usage:
    .venv/bin/python manage.py create-admin
    .venv/bin/python manage.py list-users
"""
from __future__ import annotations

import getpass
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from werkzeug.security import generate_password_hash
except ImportError:
    print("ERROR: Werkzeug is not installed. Run: .venv/bin/pip install Flask")
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "flowguard.db"

VALID_ROLES = [
    "institution_user",
    "regional_officer",
    "bureau_officer",
    "evc_coordinator",
    "compliance_verifier",
    "auditor",
    "system_admin",
]

VALID_REGIONS = ["Northern", "Southern", "Eastern", "Western", "Central", ""]


def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def create_admin() -> None:
    """Interactively create an admin account."""
    print("=== FlowGuard — Create Administrator Account ===")
    print()

    db = get_db()

    # Ensure users table exists
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "users" not in tables:
        print("ERROR: users table does not exist. Run migrate.py first.")
        print("  .venv/bin/python migrate.py")
        db.close()
        sys.exit(1)

    username = input("Username: ").strip().lower()
    if not username or len(username) < 3:
        print("ERROR: Username must be at least 3 characters.")
        db.close()
        sys.exit(1)

    existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        print(f"ERROR: A user with username '{username}' already exists.")
        db.close()
        sys.exit(1)

    print("Roles: " + ", ".join(VALID_ROLES))
    role = input("Role [system_admin]: ").strip() or "system_admin"
    if role not in VALID_ROLES:
        print(f"ERROR: Invalid role '{role}'. Choose from: {', '.join(VALID_ROLES)}")
        db.close()
        sys.exit(1)

    print("Regions: Northern, Southern, Eastern, Western, Central (leave blank for all)")
    region = input("Region (optional): ").strip() or None

    password = getpass.getpass("Password: ")
    if len(password) < 10:
        print("ERROR: Password must be at least 10 characters.")
        db.close()
        sys.exit(1)

    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("ERROR: Passwords do not match.")
        db.close()
        sys.exit(1)

    password_hash = generate_password_hash(password)
    now = datetime.now(timezone.utc).isoformat()

    db.execute(
        "INSERT INTO users (username, password_hash, role, region, is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (username, password_hash, role, region, now, now),
    )
    db.commit()
    db.close()

    print()
    print(f"✓ Account '{username}' created with role '{role}'.")
    if region:
        print(f"  Region: {region}")
    print("  You can now sign in at the FlowGuard login page.")


def list_users() -> None:
    """List all user accounts."""
    db = get_db()

    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "users" not in tables:
        print("No users table found. Run migrate.py first.")
        db.close()
        return

    users = db.execute(
        "SELECT id, username, role, region, is_active, created_at, last_login FROM users ORDER BY id"
    ).fetchall()
    db.close()

    if not users:
        print("No user accounts found. Run: .venv/bin/python manage.py create-admin")
        return

    print(f"{'ID':<5} {'Username':<25} {'Role':<25} {'Region':<12} {'Active':<8} {'Created':<25} {'Last Login'}")
    print("-" * 120)
    for u in users:
        print(
            f"{u['id']:<5} {u['username']:<25} {u['role']:<25} {(u['region'] or 'All'):<12} "
            f"{'Yes' if u['is_active'] else 'No':<8} {u['created_at'][:19]:<25} {(u['last_login'] or 'Never')[:19]}"
        )


if __name__ == "__main__":
    commands = {"create-admin": create_admin, "list-users": list_users}
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd not in commands:
        print(f"Usage: python manage.py [{' | '.join(commands)}]")
        sys.exit(1)
    commands[cmd]()

