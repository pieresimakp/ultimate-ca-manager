"""Migration 045: SSO identity by stable identifier (option A).

Authenticate SSO users by an immutable directory id (OIDC ``sub`` / SAML
persistent ``NameID`` / LDAP ``entryUUID``/``objectGUID``) instead of username or
email. Changes:

  * users.sso_external_id   — stores the stable id (bound on first SSO login)
  * users.email             — global UNIQUE replaced by a *partial* unique index
                              that only covers local accounts
                              (UNIQUE(email) WHERE auth_source='local'); an SSO
                              user may now share an email with a local account
  * index (sso_provider_id, sso_external_id) for the primary login lookup
  * pro_sso_providers.ldap_uid_attr — configurable LDAP immutable-id attribute

Email is never an authentication key, so duplicate emails across a local and an
SSO account are harmless (see #136/#138). Dual-backend (SQLite + PostgreSQL).
"""
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

_USERS_COLS = (
    "id, username, email, password_hash, full_name, role, active, mfa_enabled, "
    "created_at, last_login, totp_secret, totp_confirmed, backup_codes, "
    "login_count, failed_logins, locked_until, force_password_change, "
    "password_reset_token, password_reset_expires, custom_role_id, preferences, "
    "auth_source, sso_provider_id"
)


def _upgrade_sqlite(conn):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}

    # Rebuild users without the table-level UNIQUE(email) and with sso_external_id.
    needs_rebuild = (
        'sso_external_id' not in cols
        or conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND tbl_name='users' "
            "AND sql IS NULL AND name LIKE 'sqlite_autoindex_users_%'"
        ).fetchone() is not None
    )
    if needs_rebuild:
        conn.executescript(f"""
            CREATE TABLE _users_new (
                id INTEGER NOT NULL,
                username VARCHAR(80) NOT NULL,
                email VARCHAR(120) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(255),
                role VARCHAR(20) NOT NULL,
                active BOOLEAN,
                mfa_enabled BOOLEAN,
                created_at DATETIME,
                last_login DATETIME,
                totp_secret TEXT,
                totp_confirmed INTEGER DEFAULT 0,
                backup_codes TEXT,
                login_count INTEGER DEFAULT 0,
                failed_logins INTEGER DEFAULT 0,
                locked_until DATETIME,
                force_password_change BOOLEAN DEFAULT 0,
                password_reset_token VARCHAR(128),
                password_reset_expires DATETIME,
                custom_role_id INTEGER REFERENCES pro_custom_roles(id) ON DELETE SET NULL,
                preferences TEXT,
                auth_source VARCHAR(20) NOT NULL DEFAULT 'local',
                sso_provider_id INTEGER,
                sso_external_id VARCHAR(255),
                PRIMARY KEY (id)
            );
            INSERT INTO _users_new ({_USERS_COLS})
                SELECT {_USERS_COLS} FROM users;
            DROP TABLE users;
            ALTER TABLE _users_new RENAME TO users;
            CREATE UNIQUE INDEX ix_users_username ON users (username);
            CREATE UNIQUE INDEX ix_users_email_local ON users (email) WHERE auth_source = 'local';
            CREATE INDEX ix_users_sso_identity ON users (sso_provider_id, sso_external_id);
        """)
        conn.commit()
        logger.info("[045] users rebuilt: sso_external_id + partial email unique (SQLite)")
    else:
        logger.info("[045] users already migrated, skipping (SQLite)")

    pcols = {r[1] for r in conn.execute("PRAGMA table_info(pro_sso_providers)").fetchall()}
    if 'ldap_uid_attr' not in pcols:
        conn.execute("ALTER TABLE pro_sso_providers ADD COLUMN ldap_uid_attr VARCHAR(100)")
        conn.commit()
        logger.info("[045] pro_sso_providers.ldap_uid_attr added (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    insp = inspect(conn)
    tables = set(insp.get_table_names())
    if 'users' not in tables:
        logger.info("[045] users absent, skipping (fresh PG)")
        return

    ucols = {c['name'] for c in insp.get_columns('users')}
    if 'sso_external_id' not in ucols:
        conn.execute(text("ALTER TABLE users ADD COLUMN sso_external_id VARCHAR(255)"))

    # Drop the global unique on email; replace with a partial unique (local only).
    for uc in insp.get_unique_constraints('users'):
        if uc.get('column_names') == ['email'] and uc.get('name'):
            conn.execute(text(f'ALTER TABLE users DROP CONSTRAINT IF EXISTS "{uc["name"]}"'))
    for ix in insp.get_indexes('users'):
        if ix.get('unique') and ix.get('column_names') == ['email'] and ix.get('name') \
                and not ix.get('dialect_options', {}).get('postgresql_where'):
            conn.execute(text(f'DROP INDEX IF EXISTS "{ix["name"]}"'))
    conn.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_local "
        "ON users (email) WHERE auth_source = 'local'"))
    conn.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_users_sso_identity "
        "ON users (sso_provider_id, sso_external_id)"))
    logger.info("[045] users: sso_external_id + partial email unique (PostgreSQL)")

    if 'pro_sso_providers' in tables:
        pcols = {c['name'] for c in insp.get_columns('pro_sso_providers')}
        if 'ldap_uid_attr' not in pcols:
            conn.execute(text("ALTER TABLE pro_sso_providers ADD COLUMN ldap_uid_attr VARCHAR(100)"))
            logger.info("[045] pro_sso_providers.ldap_uid_attr added (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    """No downgrade — would reintroduce the email-uniqueness 500 (#136)."""
    pass
