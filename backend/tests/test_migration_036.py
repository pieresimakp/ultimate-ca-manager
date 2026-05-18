"""Tests for migration 036: add webhook authentication columns.

Tests the migration that adds:
- auth_type (VARCHAR(20) DEFAULT 'none')
- _auth_token (TEXT)
- auth_username (VARCHAR(255))
- auth_header_name (VARCHAR(100))

to the webhook_endpoints table.
"""

import pytest
import sqlite3
import tempfile
import os


class TestMigration036SQLite:
    """Test migration 036 on SQLite."""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary SQLite database for testing."""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        yield path
        if os.path.exists(path):
            os.unlink(path)

    def _setup_webhook_endpoints_table(self, conn):
        """Create a minimal webhook_endpoints table without auth columns."""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webhook_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL,
                url VARCHAR(500) NOT NULL,
                secret VARCHAR(255),
                events TEXT DEFAULT '[]',
                ca_filter VARCHAR(100),
                enabled BOOLEAN DEFAULT 1,
                last_success DATETIME,
                last_failure DATETIME,
                failure_count INTEGER DEFAULT 0,
                custom_headers TEXT DEFAULT '{}',
                created_at DATETIME
            )
        """)
        conn.commit()

    def test_036_adds_columns_sqlite(self, temp_db):
        """Test that migration 036 adds all 4 auth columns to webhook_endpoints on SQLite."""
        conn = sqlite3.connect(temp_db)
        try:
            self._setup_webhook_endpoints_table(conn)

            # Import and run the migration
            import importlib.util
            from pathlib import Path
            
            migration_path = Path(__file__).parent.parent / 'migrations' / '036_add_webhook_auth.py'
            spec = importlib.util.spec_from_file_location('migration_036', migration_path)
            migration = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration)
            
            migration.upgrade(conn)

            # Verify columns exist
            cur = conn.execute("PRAGMA table_info(webhook_endpoints)")
            cols = {row[1]: row[2] for row in cur.fetchall()}

            assert 'auth_type' in cols, "auth_type column not added"
            assert '_auth_token' in cols, "_auth_token column not added"
            assert 'auth_username' in cols, "auth_username column not added"
            assert 'auth_header_name' in cols, "auth_header_name column not added"

            # Verify types (SQLite uses TEXT for all, but VARCHAR declarations are stored)
            # Just verify they exist; SQLite doesn't enforce the declared types at storage time
            assert cols['auth_type'] is not None
            assert cols['_auth_token'] is not None
            assert cols['auth_username'] is not None
            assert cols['auth_header_name'] is not None
        finally:
            conn.close()

    def test_036_idempotent_sqlite(self, temp_db):
        """Test that running migration 036 twice is idempotent on SQLite."""
        conn = sqlite3.connect(temp_db)
        try:
            self._setup_webhook_endpoints_table(conn)

            import importlib.util
            from pathlib import Path
            
            migration_path = Path(__file__).parent.parent / 'migrations' / '036_add_webhook_auth.py'
            spec = importlib.util.spec_from_file_location('migration_036', migration_path)
            migration = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration)

            # Run migration first time
            migration.upgrade(conn)

            # Run migration second time - should not raise
            migration.upgrade(conn)

            # Verify columns still exist and database is intact
            cur = conn.execute("PRAGMA table_info(webhook_endpoints)")
            cols = {row[1] for row in cur.fetchall()}

            assert 'auth_type' in cols
            assert '_auth_token' in cols
            assert 'auth_username' in cols
            assert 'auth_header_name' in cols
        finally:
            conn.close()

    def test_036_default_auth_type_for_existing_rows(self, temp_db):
        """Test that existing rows get auth_type='none' after migration."""
        conn = sqlite3.connect(temp_db)
        try:
            self._setup_webhook_endpoints_table(conn)

            # Insert a webhook endpoint BEFORE migration
            conn.execute("""
                INSERT INTO webhook_endpoints (name, url, secret, enabled)
                VALUES (?, ?, ?, ?)
            """, ('test-hook', 'https://example.com/webhook', 'secret123', 1))
            conn.commit()

            # Run migration
            import importlib.util
            from pathlib import Path
            
            migration_path = Path(__file__).parent.parent / 'migrations' / '036_add_webhook_auth.py'
            spec = importlib.util.spec_from_file_location('migration_036', migration_path)
            migration = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration)
            migration.upgrade(conn)

            # Verify the existing row now has auth_type='none'
            cur = conn.execute("SELECT auth_type FROM webhook_endpoints WHERE name = ?", ('test-hook',))
            row = cur.fetchone()
            assert row is not None, "Webhook endpoint not found after migration"
            assert row[0] == 'none', f"Expected auth_type='none', got '{row[0]}'"

            # Verify other auth fields are NULL
            cur = conn.execute(
                "SELECT _auth_token, auth_username, auth_header_name FROM webhook_endpoints WHERE name = ?",
                ('test-hook',)
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] is None, "_auth_token should be NULL"
            assert row[1] is None, "auth_username should be NULL"
            assert row[2] is None, "auth_header_name should be NULL"
        finally:
            conn.close()

    def test_036_downgrade_sqlite_is_noop(self, temp_db):
        """Test that downgrade on SQLite is a no-op and doesn't raise."""
        conn = sqlite3.connect(temp_db)
        try:
            self._setup_webhook_endpoints_table(conn)

            import importlib.util
            from pathlib import Path
            
            migration_path = Path(__file__).parent.parent / 'migrations' / '036_add_webhook_auth.py'
            spec = importlib.util.spec_from_file_location('migration_036', migration_path)
            migration = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration)
            migration.upgrade(conn)

            # Downgrade should not raise
            migration.downgrade(conn)

            # Verify columns still exist (SQLite downgrade is a no-op)
            cur = conn.execute("PRAGMA table_info(webhook_endpoints)")
            cols = {row[1] for row in cur.fetchall()}
            assert 'auth_type' in cols, "Columns were removed on SQLite downgrade"
        finally:
            conn.close()


class TestMigration036PostgreSQL:
    """Test migration 036 on PostgreSQL.
    
    These tests are skipped if no PostgreSQL connection is available.
    """

    @pytest.fixture
    def pg_engine(self):
        """Create a PostgreSQL engine for testing."""
        import os
        from sqlalchemy import create_engine
        
        pg_url = os.environ.get('UCM_TEST_POSTGRES_URL')
        if not pg_url:
            pytest.skip("UCM_TEST_POSTGRES_URL not set")
        
        engine = create_engine(pg_url)
        return engine

    def _setup_webhook_endpoints_table_pg(self, conn):
        """Create a minimal webhook_endpoints table on PostgreSQL without auth columns."""
        from sqlalchemy import text
        
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS webhook_endpoints (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                url VARCHAR(500) NOT NULL,
                secret VARCHAR(255),
                events TEXT DEFAULT '[]',
                ca_filter VARCHAR(100),
                enabled BOOLEAN DEFAULT true,
                last_success TIMESTAMP,
                last_failure TIMESTAMP,
                failure_count INTEGER DEFAULT 0,
                custom_headers TEXT DEFAULT '{}',
                created_at TIMESTAMP
            )
        """))

    def test_036_adds_columns_pg(self, pg_engine):
        """Test that migration 036 adds all 4 auth columns to webhook_endpoints on PostgreSQL."""
        from sqlalchemy import text, inspect
        import importlib.util
        from pathlib import Path
        
        migration_path = Path(__file__).parent.parent / 'migrations' / '036_add_webhook_auth.py'
        spec = importlib.util.spec_from_file_location('migration_036', migration_path)
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        
        with pg_engine.begin() as conn:
            # Clean up any previous test state
            conn.execute(text("DROP TABLE IF EXISTS webhook_endpoints"))
            self._setup_webhook_endpoints_table_pg(conn)
            
            # Run migration
            migration.upgrade(conn)
            
            # Verify columns exist
            insp = inspect(conn)
            cols = {c['name'] for c in insp.get_columns('webhook_endpoints')}
            
            assert 'auth_type' in cols, "auth_type column not added"
            assert '_auth_token' in cols, "_auth_token column not added"
            assert 'auth_username' in cols, "auth_username column not added"
            assert 'auth_header_name' in cols, "auth_header_name column not added"

    def test_036_idempotent_pg(self, pg_engine):
        """Test that running migration 036 twice is idempotent on PostgreSQL."""
        from sqlalchemy import text, inspect
        import importlib.util
        from pathlib import Path
        
        migration_path = Path(__file__).parent.parent / 'migrations' / '036_add_webhook_auth.py'
        spec = importlib.util.spec_from_file_location('migration_036', migration_path)
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        
        with pg_engine.begin() as conn:
            # Clean up any previous test state
            conn.execute(text("DROP TABLE IF EXISTS webhook_endpoints"))
            self._setup_webhook_endpoints_table_pg(conn)
            
            # Run migration first time
            migration.upgrade(conn)
            
            # Run migration second time - should not raise
            migration.upgrade(conn)
            
            # Verify columns still exist
            insp = inspect(conn)
            cols = {c['name'] for c in insp.get_columns('webhook_endpoints')}
            
            assert 'auth_type' in cols
            assert '_auth_token' in cols
            assert 'auth_username' in cols
            assert 'auth_header_name' in cols

    def test_036_default_auth_type_for_existing_rows_pg(self, pg_engine):
        """Test that existing rows get auth_type='none' after migration on PostgreSQL."""
        from sqlalchemy import text, inspect
        import importlib.util
        from pathlib import Path
        
        migration_path = Path(__file__).parent.parent / 'migrations' / '036_add_webhook_auth.py'
        spec = importlib.util.spec_from_file_location('migration_036', migration_path)
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        
        with pg_engine.begin() as conn:
            # Clean up any previous test state
            conn.execute(text("DROP TABLE IF EXISTS webhook_endpoints"))
            self._setup_webhook_endpoints_table_pg(conn)
            
            # Insert a webhook endpoint BEFORE migration
            conn.execute(text("""
                INSERT INTO webhook_endpoints (name, url, secret, enabled)
                VALUES (:name, :url, :secret, :enabled)
            """), {'name': 'test-hook', 'url': 'https://example.com/webhook', 'secret': 'secret123', 'enabled': True})
            
            # Run migration
            migration.upgrade(conn)
            
            # Verify the existing row now has auth_type='none'
            result = conn.execute(text(
                "SELECT auth_type FROM webhook_endpoints WHERE name = :name"
            ), {'name': 'test-hook'}).scalar()
            
            assert result == 'none', f"Expected auth_type='none', got '{result}'"

    def test_036_downgrade_pg(self, pg_engine):
        """Test that downgrade on PostgreSQL removes the auth columns."""
        from sqlalchemy import text, inspect
        import importlib.util
        from pathlib import Path
        
        migration_path = Path(__file__).parent.parent / 'migrations' / '036_add_webhook_auth.py'
        spec = importlib.util.spec_from_file_location('migration_036', migration_path)
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        
        with pg_engine.begin() as conn:
            # Clean up any previous test state
            conn.execute(text("DROP TABLE IF EXISTS webhook_endpoints"))
            self._setup_webhook_endpoints_table_pg(conn)
            
            # Run migration
            migration.upgrade(conn)
            
            # Verify columns exist
            insp = inspect(conn)
            cols = {c['name'] for c in insp.get_columns('webhook_endpoints')}
            assert 'auth_type' in cols
            
            # Downgrade
            migration.downgrade(conn)
            
            # Verify columns are removed
            insp = inspect(conn)
            cols = {c['name'] for c in insp.get_columns('webhook_endpoints')}
            assert 'auth_type' not in cols, "auth_type should be removed on downgrade"
            assert '_auth_token' not in cols, "_auth_token should be removed on downgrade"
            assert 'auth_username' not in cols, "auth_username should be removed on downgrade"
            assert 'auth_header_name' not in cols, "auth_header_name should be removed on downgrade"
