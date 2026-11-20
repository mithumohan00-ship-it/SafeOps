"""
SafeOps - Universal Telemetry Format Parser (Tier 1 Customer Side)
==================================================================
Converts telemetry from unknown external formats into SafeOps standard events:
1. JSON Lines (default): one JSON object per line (nested or flat)
2. CSV: comma-separated values with flexible header aliases
3. Syslog: RFC 5424 or RFC 3164 standard syslog lines with key-value metrics
4. HTTP / API Feed: handles JSON payload, JSON lines, CSV, or Syslog payloads
5. Auto-Detect: sniffs incoming stream structure and selects the correct parser
"""

import csv
import datetime
import io
import json
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

RE_KV_PAIR = re.compile(r'([a-zA-Z0-9_\-]+)\s*[:=]\s*["\']?([^"\'\s,;\]\}]+)["\']?')
RE_SYSLOG_HEADER_RFC5424 = re.compile(r'^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$')
RE_SYSLOG_HEADER_RFC3164 = re.compile(r'^(?:<(\d+)>)?([A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s+(.*)$')


class UniversalFormatParser:
    """Parses and normalizes multi-format telemetry streams into standard SafeOps raw records."""

    _last_csv_header: Optional[str] = None

    def __init__(self):
        self.last_csv_header: Optional[str] = None

    @classmethod
    def detect_format(cls, text: str) -> str:
        """Sniffs incoming text and detects whether it is jsonl, csv, or syslog."""
        clean = text.strip()
        if not clean:
            return "jsonl"
        if clean.startswith("{") or clean.startswith("["):
            return "jsonl"
        if clean.startswith("<") or re.match(r'^[A-Za-z]{3}\s+\d+', clean):
            return "syslog"
        first_line = clean.splitlines()[0]
        if "," in first_line:
            return "csv"
        return "auto"

    def parse_line(self, line: str, forced_format: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Parses a single line of telemetry in the given format."""
        line = line.strip()
        if not line:
            return None

        fmt = (forced_format or self.detect_format(line)).lower()

        if fmt == "jsonl":
            return self.parse_jsonl_line(line)
        elif fmt == "syslog":
            return self.parse_syslog_line(line)
        elif fmt == "csv":
            # Detect header vs data row using exact token matching
            reader = csv.reader(io.StringIO(line))
            try:
                row_tokens = next(reader)
            except Exception:
                row_tokens = [t.strip() for t in line.split(",")]
            clean_tokens = [t.strip().strip('"\'').lower() for t in row_tokens]
            known_headers = {
                "tenant", "tenant_id", "customer", "host", "hostname", "server", "node",
                "metric", "value", "level", "severity", "category", "log", "logs", "raw_logs", "message"
            }
            if sum(1 for t in clean_tokens if t in known_headers) >= 2:
                self.last_csv_header = line
                return None

            csv_block = f"{self.last_csv_header}\n{line}" if self.last_csv_header else f"tenant_id,hostname,metric,value,category,severity,log\n{line}"
            recs = self.parse_csv_stream(csv_block)
            return recs[0] if recs else None
        else:
            recs = self.auto_detect_and_parse(line)
            return recs[0] if recs else None

    @staticmethod
    def normalize_record(
        hostname: str,
        tenant_id: str,
        metrics: Dict[str, Any],
        raw_logs: Optional[List[str]] = None,
        timestamp_utc: Optional[str] = None,
        severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """Ensures all standard metric keys and data types exist."""
        if not timestamp_utc:
            timestamp_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Clean numerical values
        def _get_float(key: str, default: float) -> float:
            val = metrics.get(key)
            if val is None:
                return default
            try:
                # Strip unit strings like %, ms, Mbps if present
                clean_str = str(val).rstrip("%msMbps ")
                return round(float(clean_str), 2)
            except Exception:
                return default

        norm_metrics = {
            "cpu_usage_pct": _get_float("cpu_usage_pct", 35.0),
            "memory_usage_pct": _get_float("memory_usage_pct", 50.0),
            "disk_usage_pct": _get_float("disk_usage_pct", 60.0),
            "bandwidth_mbps": _get_float("bandwidth_mbps", 100.0),
            "latency_ms": _get_float("latency_ms", 25.0),
            "packet_loss_pct": _get_float("packet_loss_pct", 0.0),
            "service_status": int(_get_float("service_status", 1.0)),
        }

        # Check for ambient secrets in raw logs
        raw_logs = raw_logs or []
        has_secrets = any(
            re.search(r'(?i)(password|passwd|api[_-]?key|auth_token|secret)\s*[:=]', log)
            for log in raw_logs
        )

        return {
            "raw_id": str(uuid.uuid4()),
            "tenant_id": tenant_id or "tenant-a",
            "hostname": hostname or "host-generic.internal",
            "timestamp_local": datetime.datetime.now().isoformat(),
            "timestamp_utc": timestamp_utc,
            "source_timezone": "UTC",
            "metrics": norm_metrics,
            "raw_logs": raw_logs,
            "log_lines": raw_logs,
            "severity": severity or "NORMAL",
            "ambient_secrets_present": has_secrets,
            "internal_tags": {
                "ingest_adapter": "universal_parser"
            }
        }

    @classmethod
    def parse_jsonl_line(cls, line: str) -> Optional[Dict[str, Any]]:
        """Parses one JSON line (flat or nested)."""
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        tenant_id = data.get("tenant_id") or data.get("tenant") or "tenant-a"
        hostname = data.get("hostname") or data.get("host") or data.get("source_id") or "srv-unknown.internal"
        ts = data.get("timestamp_utc") or data.get("timestamp") or data.get("time")

        # Extract metrics
        metrics = {}
        if isinstance(data.get("metrics"), dict):
            metrics.update(data["metrics"])

        # Also support flat keys in top-level JSON
        key_map = {
            "cpu": "cpu_usage_pct",
            "cpu_usage": "cpu_usage_pct",
            "cpu_usage_pct": "cpu_usage_pct",
            "mem": "memory_usage_pct",
            "memory": "memory_usage_pct",
            "memory_usage_pct": "memory_usage_pct",
            "memory_used_pct": "memory_usage_pct",
            "disk": "disk_usage_pct",
            "disk_usage_pct": "disk_usage_pct",
            "disk_used_pct": "disk_usage_pct",
            "latency": "latency_ms",
            "latency_ms": "latency_ms",
            "loss": "packet_loss_pct",
            "packet_loss": "packet_loss_pct",
            "packet_loss_pct": "packet_loss_pct",
            "bw": "bandwidth_mbps",
            "bandwidth": "bandwidth_mbps",
            "bandwidth_mbps": "bandwidth_mbps",
            "status": "service_status",
            "service_status": "service_status",
        }

        for src_key, target_key in key_map.items():
            if src_key in data and target_key not in metrics:
                metrics[target_key] = data[src_key]

        # Support generic key-value metric format (e.g. {"metric": "...", "value": ...})
        if "metric" in data and "value" in data:
            m_key = str(data["metric"]).lower()
            canon_key = key_map.get(m_key, m_key)
            metrics[canon_key] = data["value"]

        # Extract logs
        raw_logs = []
        if isinstance(data.get("raw_logs"), list):
            raw_logs.extend([str(x) for x in data["raw_logs"]])
        elif isinstance(data.get("log_lines"), list):
            raw_logs.extend([str(x) for x in data["log_lines"]])
        elif isinstance(data.get("logs"), list):
            raw_logs.extend([str(x) for x in data["logs"]])
        elif data.get("log"):
            raw_logs.append(str(data["log"]))
        elif data.get("message"):
            raw_logs.append(str(data["message"]))
        elif data.get("msg"):
            raw_logs.append(str(data["msg"]))

        sev = data.get("severity") or data.get("level")
        return cls.normalize_record(hostname, tenant_id, metrics, raw_logs, ts, severity=sev)

    @classmethod
    def parse_csv_stream(cls, csv_text: str) -> List[Dict[str, Any]]:
        """Parses CSV content with flexible header names."""
        records: List[Dict[str, Any]] = []
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
        if not reader.fieldnames:
            return records

        # Normalize fieldnames to lowercase
        alias_map = {
            "hostname": ["hostname", "host", "server", "node", "source"],
            "tenant_id": ["tenant_id", "tenant", "customer", "org"],
            "timestamp_utc": ["timestamp_utc", "timestamp", "time", "date", "datetime"],
            "cpu_usage_pct": ["cpu_usage_pct", "cpu", "cpu_pct", "cpu_percent"],
            "memory_usage_pct": ["memory_usage_pct", "memory", "mem", "ram", "mem_pct"],
            "disk_usage_pct": ["disk_usage_pct", "disk_used_pct", "disk", "storage", "disk_pct"],
            "latency_ms": ["latency_ms", "latency", "rtt", "ping"],
            "packet_loss_pct": ["packet_loss_pct", "packet_loss", "loss", "loss_pct"],
            "bandwidth_mbps": ["bandwidth_mbps", "bandwidth", "bw", "throughput"],
            "service_status": ["service_status", "status", "service", "up"],
            "metric": ["metric", "metric_name", "key", "name"],
            "value": ["value", "val", "reading", "metric_value"],
            "severity": ["severity", "level", "prio", "priority"],
            "category": ["category", "cat", "type"],
            "log": ["log", "logs", "raw_log", "raw_logs", "message", "msg"],
        }

        # Build column index resolver
        resolved_cols = {}
        for fn in reader.fieldnames:
            clean_fn = fn.strip().lower()
            for canonical, aliases in alias_map.items():
                if clean_fn in aliases:
                    resolved_cols[canonical] = fn
                    break

        for row in reader:
            hostname = row.get(resolved_cols.get("hostname", ""), "srv-csv.internal")
            tenant_id = row.get(resolved_cols.get("tenant_id", ""), "tenant-a")
            ts = row.get(resolved_cols.get("timestamp_utc", ""))

            metrics = {
                "cpu_usage_pct": row.get(resolved_cols.get("cpu_usage_pct", "")),
                "memory_usage_pct": row.get(resolved_cols.get("memory_usage_pct", "")),
                "disk_usage_pct": row.get(resolved_cols.get("disk_usage_pct", "")),
                "latency_ms": row.get(resolved_cols.get("latency_ms", "")),
                "packet_loss_pct": row.get(resolved_cols.get("packet_loss_pct", "")),
                "bandwidth_mbps": row.get(resolved_cols.get("bandwidth_mbps", "")),
                "service_status": row.get(resolved_cols.get("service_status", "")),
            }

            # If the CSV has generic 'metric' and 'value' columns:
            metric_col = resolved_cols.get("metric")
            val_col = resolved_cols.get("value")
            if metric_col and val_col and row.get(metric_col):
                metric_name = str(row[metric_col]).strip()
                canonical_metric = None
                for canon, aliases in alias_map.items():
                    if metric_name.lower() in aliases:
                        canonical_metric = canon
                        break
                target_key = canonical_metric or metric_name
                metrics[target_key] = row.get(val_col)

            raw_logs = []
            log_val = row.get(resolved_cols.get("log", ""))
            if log_val:
                raw_logs.append(str(log_val))

            sev = row.get(resolved_cols.get("severity", ""))
            record = cls.normalize_record(hostname, tenant_id, metrics, raw_logs, ts, severity=sev)
            records.append(record)

        return records

    @classmethod
    def parse_syslog_line(cls, line: str) -> Optional[Dict[str, Any]]:
        """Parses RFC 5424 or RFC 3164 Syslog messages with key-value metric attributes."""
        line = line.strip()
        if not line:
            return None

        hostname = "srv-syslog.internal"
        tenant_id = "tenant-a"
        timestamp_utc = None
        message_body = line

        # 1. Try RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
        m_5424 = RE_SYSLOG_HEADER_RFC5424.match(line)
        if m_5424:
            timestamp_utc = m_5424.group(3)
            hostname = m_5424.group(4)
            message_body = m_5424.group(8)
        else:
            # 2. Try RFC 3164: <PRI>MMM DD HH:MM:SS HOSTNAME APP: MSG
            m_3164 = RE_SYSLOG_HEADER_RFC3164.match(line)
            if m_3164:
                hostname = m_3164.group(3)
                message_body = m_3164.group(5)

        # 3. Extract key-value pairs from message body
        extracted_kvs = {}
        for match in RE_KV_PAIR.finditer(message_body):
            key = match.group(1).lower()
            val = match.group(2)
            extracted_kvs[key] = val

        if "tenant" in extracted_kvs:
            tenant_id = extracted_kvs["tenant"]
        elif "tenant_id" in extracted_kvs:
            tenant_id = extracted_kvs["tenant_id"]

        if "host" in extracted_kvs:
            hostname = extracted_kvs["host"]
        elif "hostname" in extracted_kvs:
            hostname = extracted_kvs["hostname"]

        metrics = {
            "cpu_usage_pct": extracted_kvs.get("cpu") or extracted_kvs.get("cpu_usage_pct"),
            "memory_usage_pct": extracted_kvs.get("mem") or extracted_kvs.get("memory_usage_pct"),
            "disk_usage_pct": extracted_kvs.get("disk") or extracted_kvs.get("disk_usage_pct"),
            "latency_ms": extracted_kvs.get("lat") or extracted_kvs.get("latency_ms") or extracted_kvs.get("latency"),
            "packet_loss_pct": extracted_kvs.get("loss") or extracted_kvs.get("packet_loss_pct"),
            "bandwidth_mbps": extracted_kvs.get("bw") or extracted_kvs.get("bandwidth_mbps"),
            "service_status": extracted_kvs.get("status") or extracted_kvs.get("service_status"),
        }

        # Check if syslog contains generic 'metric=...' and 'value=...'
        if "metric" in extracted_kvs and "value" in extracted_kvs:
            m_name = extracted_kvs["metric"]
            canon_m = m_name
            if m_name.lower() in ("cpu", "cpu_usage", "cpu_pct"):
                canon_m = "cpu_usage_pct"
            elif m_name.lower() in ("mem", "memory", "ram"):
                canon_m = "memory_usage_pct"
            elif m_name.lower() in ("disk", "storage", "disk_used_pct"):
                canon_m = "disk_usage_pct"
            elif m_name.lower() in ("lat", "latency", "ping"):
                canon_m = "latency_ms"
            elif m_name.lower() in ("loss", "packet_loss"):
                canon_m = "packet_loss_pct"
            elif m_name.lower() in ("bw", "bandwidth"):
                canon_m = "bandwidth_mbps"
            metrics[canon_m] = extracted_kvs["value"]

        # Any message remainder or explicit msg=... is treated as raw log line
        raw_logs = []
        if "msg" in extracted_kvs:
            raw_logs.append(extracted_kvs["msg"])
        elif "message" in extracted_kvs:
            raw_logs.append(extracted_kvs["message"])
        else:
            raw_logs.append(message_body)

        sev = extracted_kvs.get("severity") or extracted_kvs.get("level")
        return cls.normalize_record(hostname, tenant_id, metrics, raw_logs, timestamp_utc, severity=sev)

    @classmethod
    def auto_detect_and_parse(cls, payload_or_line: str) -> List[Dict[str, Any]]:
        """Automatically detects format (JSON Lines, CSV, or Syslog) and parses it."""
        text = payload_or_line.strip()
        if not text:
            return []

        # Check if JSON Lines / JSON
        if text.startswith("{") or text.startswith("["):
            try:
                # Could be a JSON array
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return [cls.parse_jsonl_line(json.dumps(x)) for x in parsed if x]
                elif isinstance(parsed, dict):
                    rec = cls.parse_jsonl_line(text)
                    return [rec] if rec else []
            except Exception:
                # Line-by-line JSONL
                results = []
                for line in text.splitlines():
                    r = cls.parse_jsonl_line(line)
                    if r:
                        results.append(r)
                if results:
                    return results

        # Check if CSV (first line has commas and keywords like cpu/host)
        first_line = text.splitlines()[0] if text else ""
        if "," in first_line and any(kw in first_line.lower() for kw in ("cpu", "host", "tenant", "latency", "status")):
            return cls.parse_csv_stream(text)

        # Check if Syslog (<PRI> or month timestamp)
        if text.startswith("<") or re.match(r'^[A-Za-z]{3}\s+\d+', text):
            results = []
            for line in text.splitlines():
                r = cls.parse_syslog_line(line)
                if r:
                    results.append(r)
            return results

        # Fallback: try parsing line by line as JSONL, then Syslog
        results = []
        for line in text.splitlines():
            r = cls.parse_jsonl_line(line) or cls.parse_syslog_line(line)
            if r:
                results.append(r)
        return results
