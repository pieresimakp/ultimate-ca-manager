"""Migration 031: ACME client accounts table.

Replaces 6 SystemConfig keys (acme.client.{staging,production}.account_{key,url}
+ acme.client.{environment,directory_url}) with a relational table where URL is
the source of truth and credentials cannot drift from the directory.

Legacy keys are NOT deleted; they remain for 1 release for rollback safety.
"""
import logging

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS acme_client_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    directory_url VARCHAR(500) NOT NULL UNIQUE,
    label VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    account_url VARCHAR(500),
    account_key TEXT,
    account_key_algorithm VARCHAR(20) NOT NULL DEFAULT 'ES256',
    eab_kid VARCHAR(255),
    eab_hmac_key TEXT,
    is_default BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_acme_client_accounts_default ON acme_client_accounts(is_default);
"""

LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"


def _get_cfg(conn, key, default=None):
    cur = conn.execute("SELECT value FROM system_config WHERE key = ?", (key,))
    row = cur.fetchone()
    return row[0] if row and row[0] is not None else default


def _has_account(conn, directory_url):
    cur = conn.execute("SELECT 1 FROM acme_client_accounts WHERE directory_url = ?", (directory_url,))
    return cur.fetchone() is not None


def _insert_account(conn, directory_url, label, email, account_url, account_key,
                    algorithm, eab_kid, eab_hmac_key, is_default):
    if _has_account(conn, directory_url):
        logger.info(f"  [031] Account for {directory_url} already exists, skipping")
        return
    conn.execute(
        """INSERT INTO acme_client_accounts
           (directory_url, label, email, account_url, account_key, account_key_algorithm,
            eab_kid, eab_hmac_key, is_default)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (directory_url, label, email, account_url, account_key, algorithm,
         eab_kid, eab_hmac_key, 1 if is_default else 0)
    )
    logger.info(f"  [031] Backfilled account: {label} ({directory_url})")


def upgrade(conn):
    conn.executescript(SCHEMA_SQL)
    conn.commit()

    # Backfill from legacy keys
    active_env = _get_cfg(conn, 'acme.client.environment', 'staging')
    email = _get_cfg(conn, 'acme.client.email', 'admin@localhost') or 'admin@localhost'
    algorithm = _get_cfg(conn, 'acme.client.account_key_type', 'ES256') or 'ES256'
    eab_kid = _get_cfg(conn, 'acme.client.eab_kid')
    eab_hmac_key = _get_cfg(conn, 'acme.client.eab_hmac_key')
    custom_dir = _get_cfg(conn, 'acme.client.directory_url')

    for env in ('staging', 'production'):
        account_key = _get_cfg(conn, f'acme.client.{env}.account_key')
        if not account_key:
            continue
        account_url = _get_cfg(conn, f'acme.client.{env}.account_url')
        url = LE_STAGING if env == 'staging' else LE_PRODUCTION
        label = "Let's Encrypt Staging" if env == 'staging' else "Let's Encrypt Production"
        is_def = (env == active_env)
        # Only attach EAB to the active env (legacy schema didn't separate)
        attach_eab = is_def
        _insert_account(
            conn, url, label, email, account_url, account_key, algorithm,
            eab_kid if attach_eab else None,
            eab_hmac_key if attach_eab else None,
            is_def
        )

    # Custom directory: backfill only if non-LE
    if custom_dir and custom_dir not in (LE_STAGING, LE_PRODUCTION):
        # Use whichever account creds exist (active env first)
        account_key = _get_cfg(conn, f'acme.client.{active_env}.account_key')
        account_url = _get_cfg(conn, f'acme.client.{active_env}.account_url')
        if account_key:
            _insert_account(
                conn, custom_dir, f"Custom ({custom_dir[:40]}...)", email,
                account_url, account_key, algorithm, eab_kid, eab_hmac_key, True
            )

    # If we set a custom default, demote LE entries
    if custom_dir and custom_dir not in (LE_STAGING, LE_PRODUCTION):
        conn.execute(
            "UPDATE acme_client_accounts SET is_default = 0 WHERE directory_url != ?",
            (custom_dir,)
        )

    conn.commit()
    logger.info("[031] ACME client accounts migration complete")


def downgrade(conn):
    conn.execute("DROP TABLE IF EXISTS acme_client_accounts")
    conn.commit()