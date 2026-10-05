"""Create (or re-activate) an ADMIN user from the command line.

The password is read interactively (never from argv, which lands in shell
history and process lists) unless ZNIDS_ADMIN_PASSWORD is set for automation.

    python -m app.cli.create_admin --email admin@example.com --name "SOC Admin"
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import select

from app.core.exceptions import ValidationFailedError
from app.core.security import hash_password, validate_password_strength
from app.db.session import session_scope
from app.models.enums import RoleName
from app.models.user import Role, User
from app.schemas.common import validate_email_address
from app.services import audit_service
from app.services.auth_service import normalize_email


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a Z-NIDS administrator")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--role", default=RoleName.ADMIN.value, choices=[r.value for r in RoleName])
    args = parser.parse_args(argv)
    try:
        # Same rule the login API applies, so a created account can always sign in.
        email = normalize_email(validate_email_address(args.email))
    except ValueError as exc:
        print(f"Invalid --email: {exc}", file=sys.stderr)
        return 2

    password = os.environ.get("ZNIDS_ADMIN_PASSWORD")
    if not password:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Repeat password: "):
            print("Passwords do not match.", file=sys.stderr)
            return 2
    try:
        validate_password_strength(password, email=email)
    except ValidationFailedError as exc:
        print(exc.message, file=sys.stderr)
        return 2

    with session_scope() as db:
        role = db.scalar(select(Role).where(Role.name == args.role))
        if role is None:
            print("Roles missing — run `alembic upgrade head` first.", file=sys.stderr)
            return 1
        user = db.scalar(select(User).where(User.email == email))
        created = user is None
        if user is None:
            user = User(email=email, name=args.name, role_id=role.id)
            db.add(user)
        user.name = args.name
        user.role_id = role.id
        user.password_hash = hash_password(password)
        user.is_active = True
        user.failed_login_count = 0
        user.locked_until = None
        user.token_version = (user.token_version or 0) + (0 if created else 1)
        db.flush()
        audit_service.record(db, "USER_CREATED" if created else "USER_RESET_BY_CLI", actor_label="cli",
                             resource_type="user", resource_id=user.id, details={"email": email, "role": args.role})
    print(f"{'Created' if created else 'Updated'} {args.role} user {email}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
