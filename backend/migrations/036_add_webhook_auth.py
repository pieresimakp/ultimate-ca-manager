"""Migration 036: add webhook authentication columns.

Adds authentication fields to webhook_endpoints table:
- auth_type: one of 'none', 'bearer', 'basic', 'api_key', 'custom'
- _auth_token: encrypted blob for storing secrets (leading underscore follows
  existing UCM pattern for encrypted properties, e.g. SMTPConfig._smtp_oauth_client_secret)
- auth_username: for basic auth username
- auth_header_name: for api_key and custom auth header names

Idempotent and dual-backend (SQLite + PostgreSQL).
Existing rows default to auth_type='none' with other fields NULL.
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True


def _upgrade_sqlite(conn):
    """Upgrade SQLite database."""
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='webhook_endpoints'"
    )
    if not cur.fetchone():
        logger.info("[036] webhook_endpoints table absent, skipping")
        return

    # Get existing columns
    cur = conn.execute("PRAGMA table_info(webhook_endpoints)")
    existing_cols = {row[1] for row in cur.fetchall()}

    # Define columns to add
    columns_to_add = [
        ("auth_type", "VARCHAR(20) NOT NULL DEFAULT 'none'"),
        ("_auth_token", "TEXT"),
        ("auth_username", "VARCHAR(255)"),
        ("auth_header_name", "VARCHAR(100)"),
    ]

    # Add missing columns
    for col_name, col_def in columns_to_add:
        if col_name not in existing_cols:
            conn.execute(f"ALTER TABLE webhook_endpoints ADD COLUMN {col_name} {col_def}")
            logger.info(f"[036] added {col_name} (SQLite)")

    conn.commit()


def _upgrade_pg(conn):
    """Upgrade PostgreSQL database.
    
    The runner already opens a transaction via ``with engine.begin() as conn``
    and passes that Connection here. Calling ``conn.begin()`` (or
    ``engine.begin()`` against an already-bound connection) raises
    "transaction already begun". Use the passed connection directly.
    """
    from sqlalchemy import inspect, text

    insp = inspect(conn)
    if 'webhook_endpoints' not in set(insp.get_table_names()):
        logger.info("[036] webhook_endpoints table absent, skipping")
        return

    # Get existing columns
    existing_cols = {c['name'] for c in insp.get_columns('webhook_endpoints')}

    # Define columns to add
    columns_to_add = [
        ("auth_type", "VARCHAR(20) NOT NULL DEFAULT 'none'"),
        ("_auth_token", "TEXT"),
        ("auth_username", "VARCHAR(255)"),
        ("auth_header_name", "VARCHAR(100)"),
    ]

    # Add missing columns
    for col_name, col_def in columns_to_add:
        if col_name not in existing_cols:
            conn.execute(text(f"ALTER TABLE webhook_endpoints ADD COLUMN {col_name} {col_def}"))
            logger.info(f"[036] added {col_name} (PostgreSQL)")


def upgrade(conn):
    """Main upgrade dispatcher."""
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    """Downgrade dispatcher.
    
    SQLite cannot DROP COLUMN, so we skip.
    PostgreSQL can drop columns.
    """
    if isinstance(conn, sqlite3.Connection):
        logger.info("[036] downgrade skipped on SQLite (no DROP COLUMN)")
    else:
        _downgrade_pg(conn)


def _downgrade_pg(conn):
    """Remove webhook auth columns from PostgreSQL."""
    from sqlalchemy import inspect, text

    insp = inspect(conn)
    if 'webhook_endpoints' not in set(insp.get_table_names()):
        logger.info("[036] webhook_endpoints table absent, skipping downgrade")
        return

    existing_cols = {c['name'] for c in insp.get_columns('webhook_endpoints')}

    columns_to_drop = [
        "auth_type",
        "_auth_token",
        "auth_username",
        "auth_header_name",
    ]

    for col_name in columns_to_drop:
        if col_name in existing_cols:
            conn.execute(text(f"ALTER TABLE webhook_endpoints DROP COLUMN IF EXISTS {col_name}"))
            logger.info(f"[036] dropped {col_name} (PostgreSQL)")
