"""
SafeOps - Collector Local Storage & Retention (Tier 1 Customer Side)
====================================================================
Local SQLite database (`collector_local.db`) providing:
1. Local Raw Storage (retains full raw telemetry for audit & debugging inside the customer boundary only)
2. 1-Hour Automatic Retention Pruner (deletes raw data older than 1 hour)
3. Local Outbound Queue (durable buffer for store-and-forward when SaaS is down)
4. Egress Audit Log (permanent searchable record of exact sanitized JSON emitted to Tier 2)
"""

from contextlib import contextmanager
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple


class CollectorStorage:
    def __init__(self, db_path: str = "collector_local.db"):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            # 1. Raw telemetry table (KEPT LOCALLY ONLY)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS raw_telemetry (
                    raw_id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    hostname TEXT,
                    timestamp_utc TEXT,
                    created_at REAL,
                    raw_json TEXT,
                    secrets_detected INTEGER DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_created_at ON raw_telemetry(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_tenant ON raw_telemetry(tenant_id)")

            # 2. Outbound buffer queue (for resilient store-and-forward)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS buffer_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_id TEXT UNIQUE,
                    raw_id TEXT,
                    tenant_id TEXT,
                    payload_json TEXT,
                    status TEXT DEFAULT 'PENDING',
                    retry_count INTEGER DEFAULT 0,
                    next_retry_at REAL,
                    created_at REAL,
                    sent_at REAL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_buffer_status_retry ON buffer_queue(status, next_retry_at)")

            # 3. Egress Audit Log (exact records that exited Tier 1 to Tier 2 SaaS)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS egress_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_id TEXT UNIQUE,
                    raw_id TEXT,
                    tenant_id TEXT,
                    source_id TEXT,
                    metric TEXT,
                    value REAL,
                    event_time_utc TEXT,
                    sent_to_saas_at TEXT,
                    sanitized_payload_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_egress_time ON egress_audit_log(event_time_utc)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_egress_tenant ON egress_audit_log(tenant_id)")

    def store_raw_event(self, raw_record: Dict[str, Any]) -> str:
        """Stores unredacted raw telemetry in local database with creation timestamp."""
        raw_id = raw_record.get("raw_id")
        tenant_id = raw_record.get("tenant_id")
        hostname = raw_record.get("hostname")
        timestamp_utc = raw_record.get("timestamp_utc")
        created_at = time.time()
        has_secrets = 1 if raw_record.get("ambient_secrets_present") else 0
        raw_json = json.dumps(raw_record)

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO raw_telemetry
                (raw_id, tenant_id, hostname, timestamp_utc, created_at, raw_json, secrets_detected)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (raw_id, tenant_id, hostname, timestamp_utc, created_at, raw_json, has_secrets))
        return raw_id

    def enqueue_payload(self, raw_id: str, payload: Dict[str, Any]):
        """Queues a sanitized, allow-listed payload into the outbound SQLite buffer."""
        payload_id = payload.get("payload_id")
        tenant_id = payload.get("tenant_id")
        now = time.time()
        payload_json = json.dumps(payload)

        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO buffer_queue
                (payload_id, raw_id, tenant_id, payload_json, status, retry_count, next_retry_at, created_at)
                VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?)
            """, (payload_id, raw_id, tenant_id, payload_json, now, now))

    def get_pending_payloads(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves pending payloads ready for transmission."""
        now = time.time()
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT payload_id, raw_id, tenant_id, payload_json, retry_count
                FROM buffer_queue
                WHERE status = 'PENDING' AND next_retry_at <= ?
                ORDER BY created_at ASC
                LIMIT ?
            """, (now, limit)).fetchall()
            return [dict(r) for r in rows]

    def mark_payload_sent(self, payload_id: str, raw_id: str, payload_data: Dict[str, Any]):
        """Marks buffered payload as sent and appends to permanent egress audit log."""
        now_ts = time.time()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts))

        with self._get_connection() as conn:
            # 1. Update buffer status
            conn.execute("""
                UPDATE buffer_queue
                SET status = 'SENT', sent_at = ?
                WHERE payload_id = ?
            """, (now_ts, payload_id))

            # 2. Add to egress audit log
            conn.execute("""
                INSERT OR REPLACE INTO egress_audit_log
                (payload_id, raw_id, tenant_id, source_id, metric, value, event_time_utc, sent_to_saas_at, sanitized_payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                payload_id,
                raw_id,
                payload_data.get("tenant_id"),
                payload_data.get("source_id"),
                payload_data.get("metric"),
                payload_data.get("value"),
                payload_data.get("event_time_utc"),
                now_iso,
                json.dumps(payload_data)
            ))

    def mark_payload_failed(self, payload_id: str, retry_count: int, backoff_seconds: float):
        """Schedules retry with exponential backoff if transmission failed."""
        next_try = time.time() + backoff_seconds
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE buffer_queue
                SET retry_count = ?, next_retry_at = ?, status = 'PENDING'
                WHERE payload_id = ?
            """, (retry_count, next_try, payload_id))

    def prune_expired_raw_records(self, retention_seconds: float = 3600.0) -> int:
        """
        Deletes raw records older than retention period (default 1 hour = 3600s).
        Enforces local data minimization policy.
        """
        cutoff = time.time() - retention_seconds
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM raw_telemetry WHERE created_at < ?", (cutoff,))
            pruned_count = cursor.rowcount
            # Also clean ancient sent entries from buffer queue
            conn.execute("DELETE FROM buffer_queue WHERE status = 'SENT' AND created_at < ?", (cutoff,))
            return pruned_count

    def get_egress_pairs(self, search: str = "", limit: int = 40) -> List[Dict[str, Any]]:
        """
        Fetches paired (Raw Input vs Sanitized Sent JSON) for the Egress Proof Panel.
        Allows searching by payload_id, metric, tenant, or host.
        """
        with self._get_connection() as conn:
            query = """
                SELECT
                    e.payload_id,
                    e.raw_id,
                    e.tenant_id,
                    e.source_id,
                    e.metric,
                    e.value,
                    e.event_time_utc,
                    e.sent_to_saas_at,
                    e.sanitized_payload_json,
                    r.hostname AS raw_hostname,
                    r.raw_json AS raw_full_json,
                    r.secrets_detected
                FROM egress_audit_log e
                LEFT JOIN raw_telemetry r ON e.raw_id = r.raw_id
            """
            params: List[Any] = []
            if search:
                query += """
                    WHERE e.payload_id LIKE ? OR e.metric LIKE ? OR e.source_id LIKE ? OR e.tenant_id LIKE ?
                """
                like_pattern = f"%{search}%"
                params = [like_pattern, like_pattern, like_pattern, like_pattern]

            query += " ORDER BY e.id DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                row_dict = dict(r)
                # Parse JSON strings into Python dicts for template rendering
                try:
                    row_dict["sanitized_dict"] = json.loads(row_dict["sanitized_payload_json"])
                except Exception:
                    row_dict["sanitized_dict"] = {}
                try:
                    row_dict["raw_dict"] = json.loads(row_dict["raw_full_json"]) if row_dict.get("raw_full_json") else {}
                except Exception:
                    row_dict["raw_dict"] = {}
                results.append(row_dict)
            return results

    def get_buffer_stats(self) -> Dict[str, Any]:
        """Returns live statistics of queue and audit logs."""
        with self._get_connection() as conn:
            pending = conn.execute("SELECT COUNT(*) FROM buffer_queue WHERE status = 'PENDING'").fetchone()[0]
            sent = conn.execute("SELECT COUNT(*) FROM egress_audit_log").fetchone()[0]
            raw_stored = conn.execute("SELECT COUNT(*) FROM raw_telemetry").fetchone()[0]
            secrets_intercepted = conn.execute("SELECT COUNT(*) FROM raw_telemetry WHERE secrets_detected = 1").fetchone()[0]
            return {
                "pending_in_buffer": pending,
                "total_sent_to_saas": sent,
                "raw_records_stored": raw_stored,
                "secrets_intercepted_locally": secrets_intercepted
            }

    def get_tenant_buffer_stats(self, tenant_id: str) -> Dict[str, Any]:
        """Returns buffer and sent stats partitioned by tenant."""
        with self._get_connection() as conn:
            pending = conn.execute("SELECT COUNT(*) FROM buffer_queue WHERE tenant_id = ? AND status = 'PENDING'", (tenant_id,)).fetchone()[0]
            sent = conn.execute("SELECT COUNT(*) FROM egress_audit_log WHERE tenant_id = ?", (tenant_id,)).fetchone()[0]
            return {"pending_in_buffer": pending, "total_sent_to_saas": sent}

    def get_tenant_sent_payload_ids(self, tenant_id: str) -> List[str]:
        """Returns list of payload IDs sent by collector for this tenant."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT payload_id FROM egress_audit_log WHERE tenant_id = ? ORDER BY id DESC LIMIT 500", (tenant_id,)).fetchall()
            return [r[0] for r in rows]

    def get_tenant_pending_payload_ids(self, tenant_id: str) -> List[str]:
        """Returns list of pending payload IDs in buffer queue for this tenant."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT payload_id FROM buffer_queue WHERE tenant_id = ? AND status = 'PENDING' LIMIT 500", (tenant_id,)).fetchall()
            return [r[0] for r in rows]

    def requeue_duplicate_payload(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Re-enqueues an already-sent payload with its exact original payload_id to test duplicate rejection."""
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT payload_id, raw_id, tenant_id, sanitized_payload_json
                FROM egress_audit_log
                WHERE tenant_id = ?
                ORDER BY id DESC LIMIT 1
            """, (tenant_id,)).fetchone()
            if row:
                now_ts = time.time()
                conn.execute("""
                    INSERT OR REPLACE INTO buffer_queue
                    (payload_id, raw_id, tenant_id, payload_json, status, retry_count, next_retry_at, created_at)
                    VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?)
                """, (row["payload_id"], row["raw_id"], row["tenant_id"], row["sanitized_payload_json"], now_ts, now_ts))
                return {
                    "payload_id": row["payload_id"],
                    "tenant_id": row["tenant_id"]
                }
            return None

    def requeue_out_of_order_payload(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Enqueues an event with a backdated timestamp (older than latest event_ts for that host) to test out-of-order handling."""
        import datetime, uuid
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT sanitized_payload_json
                FROM egress_audit_log
                WHERE tenant_id = ?
                ORDER BY id DESC LIMIT 1
            """, (tenant_id,)).fetchone()
            if row:
                payload = json.loads(row["sanitized_payload_json"])
                new_payload_id = str(uuid.uuid4())
                payload["payload_id"] = new_payload_id
                # Backdate event_time_utc by 90 seconds
                past_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=90)).isoformat()
                payload["event_time_utc"] = past_time
                now_ts = time.time()
                conn.execute("""
                    INSERT INTO buffer_queue
                    (payload_id, raw_id, tenant_id, payload_json, status, retry_count, next_retry_at, created_at)
                    VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?)
                """, (new_payload_id, "out-of-order-raw", tenant_id, json.dumps(payload), now_ts, now_ts))
                return {
                    "payload_id": new_payload_id,
                    "event_time_utc": past_time,
                    "source_id": payload.get("source_id")
                }
            return None

    def reset_database(self):
        """Clears all raw telemetry, outbound buffer, and egress audit logs."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM buffer_queue")
            conn.execute("DELETE FROM raw_telemetry")
            conn.execute("DELETE FROM egress_audit_log")
