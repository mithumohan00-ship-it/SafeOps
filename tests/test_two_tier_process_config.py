"""
SafeOps - Tests for Two Separate Processes, Distinct Databases, and SaaS Address Configuration
=============================================================================================
Verifies:
1. Collector and SaaS maintain independent database schemas and separate storage files.
2. SaaS address is configurable via config file (config/collector_config.json) and SAAS_URL env var.
3. SaaS address normalization (handles host:port without http:// and trailing slashes).
4. HTML templates dynamically inject the configured SaaS address.
"""

import json
import os
import sqlite3
import unittest
from httpx import ASGITransport, AsyncClient

from tier1_collector.storage import CollectorStorage
from tier2_saas.storage import SaaSStorage
from tier1_collector.buffer_sender import BufferSender
from tier1_collector.adapters import UniversalFeedAdapter


class TestTwoTierProcessAndConfig(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.collector_db = "test_collector_isolated.db"
        self.saas_db = "test_saas_isolated.db"
        for db in [self.collector_db, self.saas_db]:
            if os.path.exists(db):
                os.remove(db)

    def tearDown(self):
        for db in [self.collector_db, self.saas_db]:
            if os.path.exists(db):
                os.remove(db)

    def test_01_separate_databases_and_distinct_schemas(self):
        """Verify Collector and SaaS use completely separate databases with distinct schemas."""
        col_storage = CollectorStorage(self.collector_db)
        saas_storage = SaaSStorage(self.saas_db)

        # Check tables in collector database
        conn_col = sqlite3.connect(self.collector_db)
        col_tables = {r[0] for r in conn_col.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn_col.close()

        # Collector must have raw_telemetry, buffer_queue, egress_audit_log
        self.assertIn("raw_telemetry", col_tables)
        self.assertIn("buffer_queue", col_tables)
        self.assertIn("egress_audit_log", col_tables)
        # Collector must NOT have SaaS tables
        self.assertNotIn("telemetry_events", col_tables)
        self.assertNotIn("collector_heartbeats", col_tables)
        self.assertNotIn("incidents", col_tables)

        # Check tables in SaaS database
        conn_saas = sqlite3.connect(self.saas_db)
        saas_tables = {r[0] for r in conn_saas.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn_saas.close()

        # SaaS must have telemetry_events, collector_heartbeats, state_change_history, incidents, etc.
        self.assertIn("telemetry_events", saas_tables)
        self.assertIn("collector_heartbeats", saas_tables)
        self.assertIn("state_change_history", saas_tables)
        self.assertIn("incidents", saas_tables)
        # SaaS must NOT have Collector local raw tables
        self.assertNotIn("raw_telemetry", saas_tables)
        self.assertNotIn("buffer_queue", saas_tables)

    def test_02_saas_address_config_setting(self):
        """Verify BufferSender correctly loads and normalizes saas_url from config."""
        mock_config = {
            "saas_url": "http://192.168.1.150:8002",
            "heartbeat_interval_seconds": 10,
            "raw_retention_minutes": 60,
            "tenants": {}
        }
        storage = CollectorStorage(self.collector_db)
        adapter = UniversalFeedAdapter(mock_config)

        # 1. From config dictionary
        sender = BufferSender(mock_config, storage, adapter)
        self.assertEqual(sender.saas_url, "http://192.168.1.150:8002")

        # 2. From environment variable override
        os.environ["SAAS_URL"] = "http://second-laptop.lan:8002/"
        try:
            sender_env = BufferSender(mock_config, storage, adapter)
            self.assertEqual(sender_env.saas_url, "http://second-laptop.lan:8002")
        finally:
            del os.environ["SAAS_URL"]

        # 3. Missing http:// scheme is automatically prepended
        os.environ["SAAS_ADDRESS"] = "10.0.0.42:9000"
        try:
            sender_auto_scheme = BufferSender(mock_config, storage, adapter)
            self.assertEqual(sender_auto_scheme.saas_url, "http://10.0.0.42:9000")
        finally:
            del os.environ["SAAS_ADDRESS"]

    async def test_03_html_template_uses_configured_saas_address(self):
        """Verify Collector web pages dynamically link to the configured SaaS address."""
        from tier1_collector.app import app as collector_app
        from tier1_collector.app import BUFFER_SENDER

        transport = ASGITransport(app=collector_app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
            res_egress = await client.get("/egress")
            self.assertEqual(res_egress.status_code, 200)
            # The button link must match BUFFER_SENDER.saas_url
            self.assertIn(f'href="{BUFFER_SENDER.saas_url}"', res_egress.text)

            res_control = await client.get("/control")
            self.assertEqual(res_control.status_code, 200)
            self.assertIn(f'href="{BUFFER_SENDER.saas_url}"', res_control.text)


if __name__ == "__main__":
    unittest.main()
