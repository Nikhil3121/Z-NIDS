"""seed reference data: roles, permissions, MITRE ATT&CK techniques

These rows are reference data required for the application to function
(RBAC definitions and the ATT&CK catalogue) — not demo data.

Revision ID: 0002_seed_reference
Revises: 3562df946ecd
Create Date: 2026-09-23
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.integrations.mitre.catalog import ATTACK_URL, TECHNIQUES
from app.models.enums import ROLE_PERMISSIONS, Permission, RoleName

revision: str = "0002_seed_reference"
down_revision: str | None = "3562df946ecd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLE_DESCRIPTIONS = {
    RoleName.ADMIN: "Full administration, including users, sensors and configuration",
    RoleName.SECURITY_MANAGER: "Manages assets and models, approves response actions, reads the audit log",
    RoleName.SECURITY_ANALYST: "Triages alerts, investigates incidents, requests response actions",
    RoleName.VIEWER: "Read-only access to events, detections, alerts, incidents and reports",
}


def upgrade() -> None:
    perms = sa.table("permissions", sa.column("id", sa.Integer), sa.column("code", sa.String),
                     sa.column("description", sa.String))
    roles = sa.table("roles", sa.column("id", sa.Integer), sa.column("name", sa.String),
                     sa.column("description", sa.String))
    role_perms = sa.table("role_permissions", sa.column("role_id", sa.Integer), sa.column("permission_id", sa.Integer))
    techniques = sa.table("mitre_techniques", sa.column("technique_id", sa.String), sa.column("name", sa.String),
                          sa.column("tactic", sa.String), sa.column("description", sa.String),
                          sa.column("url", sa.String))

    perm_ids = {p: i for i, p in enumerate(Permission, start=1)}
    op.bulk_insert(perms, [{"id": i, "code": p.value, "description": p.name.replace("_", " ").title()}
                           for p, i in perm_ids.items()])
    role_ids = {r: i for i, r in enumerate(RoleName, start=1)}
    op.bulk_insert(roles, [{"id": i, "name": r.value, "description": ROLE_DESCRIPTIONS[r]} for r, i in role_ids.items()])
    op.bulk_insert(role_perms, [{"role_id": role_ids[r], "permission_id": perm_ids[p]}
                                for r, granted in ROLE_PERMISSIONS.items() for p in sorted(granted)])
    op.bulk_insert(techniques, [{"technique_id": tid, "name": name, "tactic": tactic, "description": desc,
                                 "url": ATTACK_URL.format(tid.replace(".", "/"))}
                                for tid, (name, tactic, desc) in TECHNIQUES.items()])
    # Explicit ids were used above; move the sequences past them.
    op.execute("SELECT setval(pg_get_serial_sequence('permissions', 'id'), (SELECT max(id) FROM permissions))")
    op.execute("SELECT setval(pg_get_serial_sequence('roles', 'id'), (SELECT max(id) FROM roles))")


def downgrade() -> None:
    op.execute("DELETE FROM mitre_techniques")
    op.execute("DELETE FROM role_permissions")
    op.execute("DELETE FROM roles")
    op.execute("DELETE FROM permissions")
