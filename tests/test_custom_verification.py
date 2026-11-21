"""
SafeOps - Custom System Test Verification Case
==============================================
Validates loading and evaluating custom external system telemetry files:
1. Multi-tenant parsing across Customer A and Customer B
2. Zero-Trust regex redaction on passwords, API keys, and bearer tokens
3. Hostname pseudonymization verification
4. Live upload endpoint and direct system file path streaming
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from starlette.testclient import TestClient
from tier1_collector.app import app as collector_app
from tier1_collector.format_parser import UniversalFormatParser
from tier1_collector.pipeline import CollectorPipeline


class TestCustomVerification(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(collector_app)
        self.parser = UniversalFormatParser()
        self.pipeline = CollectorPipeline()
        self.test_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data_feed", "test_custom_feed.csv"))

    def test_01_verify_custom_feed_file_parsing(self):
        """Verifies that the generated custom CSV feed parses cleanly with all metric fields."""
        self.assertTrue(os.path.exists(self.test_file_path), "Custom test feed file should exist on disk")
        with open(self.test_file_path, "r", encoding="utf-8") as f:
            content = f.read()

        records = self.parser.parse_csv_stream(content)
        self.assertGreaterEqual(len(records), 5, "Should parse at least 5 telemetry events")
        
        # Verify first record fields
        rec0 = records[0]
        self.assertEqual(rec0["tenant_id"], "tenant-a")
        self.assertEqual(rec0["hostname"], "srv-prod-web-01.internal")
        self.assertIn("cpu_usage_pct", rec0["metrics"])
        self.assertEqual(rec0["metrics"]["cpu_usage_pct"], 32.5)

    def test_02_verify_pipeline_redaction_on_custom_feed(self):
        """Verifies that secrets (passwords, tokens, API keys) in the custom test feed are 100% scrubbed."""
        with open(self.test_file_path, "r", encoding="utf-8") as f:
            content = f.read()

        records = self.parser.parse_csv_stream(content)
        for raw_rec in records:
            payloads = self.pipeline.process_raw_record(raw_rec)
            for p in payloads:
                # 1. Source ID must be pseudonymized (cannot contain internal hostnames)
                self.assertNotIn(".internal", p["source_id"])
                self.assertNotIn(".local", p["source_id"])
                self.assertTrue(p["source_id"].startswith("host-"))

                # 2. Raw secrets must NOT leak into egress payload
                context = p.get("short_context", "")
                self.assertNotIn("ProdDbRootPassword999!", context)
                self.assertNotIn("sk_live_sec_8392019482", context)
                self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", context)

    def test_03_verify_live_upload_api(self):
        """Verifies uploading the custom test file through the collector HTTP upload API."""
        with open(self.test_file_path, "rb") as f:
            file_bytes = f.read()

        res = self.client.post(
            "/api/v1/adapter/upload",
            content=file_bytes,
            headers={"Content-Type": "application/octet-stream", "X-Filename": "test_custom_feed.csv"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "uploaded")
        self.assertEqual(data["mode"], "csv")
        self.assertIn("test_custom_feed.csv", data["message"])

    def tearDown(self):
        from tier1_collector.app import ADAPTER
        ADAPTER.feed_file_path = "data_feed/telemetry_input.data"
        ADAPTER.set_mode("simulator")

    def test_04_verify_system_feed_path(self):
        """Verifies pointing the collector directly to the custom system test file path."""
        import tempfile
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".csv") as tmp:
            tmp.write("tenant_id,hostname,metric,value\ntenant-a,srv-temp-99,cpu_usage_pct,42.0\n")
            tmp.flush()
            tmp_path = tmp.name

        try:
            res = self.client.post("/api/v1/adapter/set_feed_path", json={"path": tmp_path})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["status"], "connected")
            self.assertEqual(data["feed_file_path"], tmp_path)
            self.assertEqual(data["mode"], "csv")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
