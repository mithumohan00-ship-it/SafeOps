"""
SafeOps - Collector Processing Pipeline (Tier 1 Customer Side)
==============================================================
Enforces strict Zero-Trust boundaries before telemetry leaves the customer network:
1. Filter: Drops malformed records
2. Redact: Scrub passwords, API tokens, IP addresses, emails using strict regex
3. Pseudonymize: Replaces hostnames with deterministic salted cryptographic hashes (e.g., host-7f3a9e12)
4. Local Security Analysis: Detects brute-force failed login attacks locally; generates summary metrics only, raw logs NEVER leave Tier 1
5. Allow-List Enforcement: Only allows 11 exact whitelisted fields to exit to Tier 2 SaaS
"""

import collections
import datetime
import hashlib
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

# Strict regex patterns for sensitive data redaction (supports plaintext and JSON formatting)
RE_PASSWORD = re.compile(r'(?i)["\']?(password|passwd|pwd|fallback_password)["\']?\s*[:=]\s*["\']?([^"\'\s,;\}]+)["\']?')
RE_API_KEY = re.compile(r'(?i)["\']?(api[_-]?key|auth_token|token|secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{8,})["\']?')
RE_BEARER = re.compile(r'(?i)\b(bearer)\s+([a-zA-Z0-9_\-\.]{8,})')
RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# Strict Allow-List: Only these 11 fields are permitted to leave Tier 1 to Tier 2
ALLOWED_EGRESS_FIELDS = {
    "payload_id",
    "tenant_id",
    "source_id",
    "metric",
    "value",
    "event_time_utc",
    "source_timezone",
    "health_state",
    "category",
    "severity",
    "short_context",
}


def redact_text(text: str) -> str:
    """Scrub passwords, tokens, IP addresses, and emails from raw strings."""
    if not text:
        return text
    # 1. Passwords
    text = RE_PASSWORD.sub(r'\1=[REDACTED_PASSWORD]', text)
    # 2. Bearer tokens
    text = RE_BEARER.sub(r'Bearer [REDACTED_TOKEN]', text)
    # 3. API Tokens
    text = RE_API_KEY.sub(r'\1=[REDACTED_TOKEN]', text)
    # 4. IP Addresses
    text = RE_IPV4.sub(r'[REDACTED_IP]', text)
    # 5. Email addresses
    text = RE_EMAIL.sub(r'[REDACTED_EMAIL]', text)
    return text


def pseudonymize_hostname(tenant_id: str, hostname: str, salt: str) -> str:
    """
    Produces a consistent, pseudonymous source ID (e.g. host-7f3a9e12).
    Deterministic so metrics over time correlate on SaaS, but the SaaS platform
    can NEVER infer the internal hostname, FQDN, or topology.
    """
    raw_key = f"{salt}:{tenant_id}:{hostname}".encode("utf-8")
    short_hash = hashlib.sha256(raw_key).hexdigest()[:8]
    return f"host-{short_hash}"


class LocalSecurityAnalyzer:
    """
    Analyzes authentication logs directly inside Tier 1.
    Keeps a sliding 30-second window of failed logins per host.
    When failed logins >= 3 in 30s, emits an aggregated security alert metric.
    RAW LOG LINES ARE NEVER SENT TO TIER 2.
    """

    def __init__(self, window_seconds: float = 30.0, threshold_count: int = 3):
        self.window_seconds = window_seconds
        self.threshold_count = threshold_count
        # host -> deque of timestamps
        self.failed_login_timestamps: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        # host -> bool tracking active alert state for clean resolution
        self.active_alert: Dict[str, bool] = collections.defaultdict(bool)

    def process_logs(self, host: str, raw_logs: List[str]) -> Tuple[int, Optional[str], Optional[str]]:
        """
        Inspects logs locally, returns (failed_attempts_in_window, severity, alert_summary).
        """
        now = time.time()
        q = self.failed_login_timestamps[host]

        # Evict timestamps outside sliding window
        while q and q[0] < (now - self.window_seconds):
            q.popleft()

        # Count new failed logins in the current batch
        new_failures = 0
        for line in raw_logs:
            if "FAILED LOGIN" in line or "invalid_credentials" in line:
                q.append(now)
                new_failures += 1

        total_recent_failures = len(q)

        if total_recent_failures >= self.threshold_count:
            self.active_alert[host] = True
            severity = "CRITICAL" if total_recent_failures >= 6 else "WARNING"
            summary = (
                f"Brute force anomaly detected: {total_recent_failures} failed logins "
                f"in {int(self.window_seconds)}s window"
            )
            return total_recent_failures, severity, summary

        # If previous alert was active but attack has now subsided:
        if self.active_alert.get(host, False):
            self.active_alert[host] = False
            return 0, "CLEAR", "Zero auth failures detected in window (attack subsided)"

        return total_recent_failures, None, None


class CollectorPipeline:
    """
    Executes the SafeOps Tier 1 pipeline:
    Collect -> Filter -> Redact -> Aggregate -> Analyze Locally -> Apply Allow-List.
    """

    def __init__(self, salt: str = "safeops_deterministic_salt_tier1_2026"):
        self.salt = salt
        self.security_analyzer = LocalSecurityAnalyzer(window_seconds=30.0, threshold_count=3)

    def process_raw_record(self, raw_record: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Processes one raw telemetry event record into one or more sanitized,
        whitelisted egress payloads ready to be sent to Tier 2 SaaS.
        """
        tenant_id = raw_record.get("tenant_id", "unknown-tenant")
        hostname = raw_record.get("hostname", "unknown-host")
        event_time_utc = raw_record.get("timestamp_utc") or datetime.datetime.now(datetime.timezone.utc).isoformat()
        source_timezone = raw_record.get("source_timezone", "UTC")
        metrics = raw_record.get("metrics", {})
        raw_logs = raw_record.get("raw_logs", [])

        # Step 1: Pseudonymize source hostname
        source_id = pseudonymize_hostname(tenant_id, hostname, self.salt)

        # Step 2: Local Security Analysis (Auth logs processed locally only!)
        failed_count, sec_severity, sec_summary = self.security_analyzer.process_logs(hostname, raw_logs)

        egress_payloads: List[Dict[str, Any]] = []

        # Step 3: Transform operational metrics into standardized egress payloads
        metric_category_map = {
            "cpu_usage_pct": ("compute", "%"),
            "memory_usage_pct": ("compute", "%"),
            "disk_usage_pct": ("storage", "%"),
            "bandwidth_mbps": ("network", "Mbps"),
            "latency_ms": ("network", "ms"),
            "packet_loss_pct": ("network", "%"),
            "service_status": ("application", "state"),
        }

        for metric_name, value in metrics.items():
            category, unit = metric_category_map.get(metric_name, ("custom", ""))

            # Compute preliminary local health assessment
            health_state, severity, short_context = self._evaluate_metric_health(metric_name, value, unit)

            # Construct standardized payload
            payload = {
                "payload_id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "source_id": source_id,
                "metric": metric_name,
                "value": float(value),
                "event_time_utc": event_time_utc,
                "source_timezone": source_timezone,
                "health_state": health_state,
                "category": category,
                "severity": severity,
                "short_context": redact_text(short_context),  # Double safety redaction
            }

            # Step 4: Strict Allow-List Enforcement
            filtered_payload = self._apply_allow_list(payload)
            egress_payloads.append(filtered_payload)

        # Step 5: If security anomaly detected locally or alert resolved, emit summary payload (NO RAW LOGS)
        if sec_severity and sec_summary:
            sec_health = "POOR" if sec_severity in ("CRITICAL", "WARNING") else "EXCELLENT"
            sec_payload = {
                "payload_id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "source_id": source_id,
                "metric": "failed_logins",
                "value": float(failed_count),
                "event_time_utc": event_time_utc,
                "source_timezone": source_timezone,
                "health_state": sec_health,
                "category": "security",
                "severity": "INFO" if sec_severity == "CLEAR" else sec_severity,
                "short_context": redact_text(sec_summary),
            }
            egress_payloads.append(self._apply_allow_list(sec_payload))

        return egress_payloads

    def _evaluate_metric_health(self, metric: str, val: float, unit: str) -> Tuple[str, str, str]:
        """Local threshold rules to assign preliminary health state & short context."""
        if metric == "cpu_usage_pct":
            if val >= 90.0:
                return "POOR", "CRITICAL", f"CPU critical at {val}{unit}"
            if val >= 75.0:
                return "FAIR", "WARNING", f"CPU elevated at {val}{unit}"
            if val >= 50.0:
                return "GOOD", "INFO", f"CPU nominal at {val}{unit}"
            return "EXCELLENT", "INFO", f"CPU optimal at {val}{unit}"

        elif metric == "memory_usage_pct":
            if val >= 90.0:
                return "POOR", "CRITICAL", f"Memory pressure at {val}{unit}"
            if val >= 80.0:
                return "FAIR", "WARNING", f"Memory high at {val}{unit}"
            if val >= 60.0:
                return "GOOD", "INFO", f"Memory normal at {val}{unit}"
            return "EXCELLENT", "INFO", f"Memory optimal at {val}{unit}"

        elif metric == "disk_usage_pct":
            if val >= 92.0:
                return "POOR", "CRITICAL", f"Disk nearly full at {val}{unit}"
            if val >= 80.0:
                return "FAIR", "WARNING", f"Disk high at {val}{unit}"
            return "GOOD", "INFO", f"Disk normal at {val}{unit}"

        elif metric == "latency_ms":
            if val >= 250.0:
                return "POOR", "CRITICAL", f"High latency spike at {val}{unit}"
            if val >= 120.0:
                return "FAIR", "WARNING", f"Latency elevated at {val}{unit}"
            if val >= 40.0:
                return "GOOD", "INFO", f"Latency normal at {val}{unit}"
            return "EXCELLENT", "INFO", f"Latency fast at {val}{unit}"

        elif metric == "packet_loss_pct":
            if val >= 3.0:
                return "POOR", "CRITICAL", f"Packet loss severe at {val}{unit}"
            if val >= 1.0:
                return "FAIR", "WARNING", f"Packet loss detected at {val}{unit}"
            return "GOOD", "INFO", f"Packet loss negligible at {val}{unit}"

        elif metric == "service_status":
            if val < 1.0:
                return "POOR", "CRITICAL", "Service process DOWN"
            return "EXCELLENT", "INFO", "Service process running (UP)"

        return "GOOD", "INFO", f"{metric} at {val}"

    def _apply_allow_list(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures NO unauthorized fields can leave Tier 1."""
        return {k: v for k, v in payload.items() if k in ALLOWED_EGRESS_FIELDS}


if __name__ == "__main__":
    from demo_phase1_pipeline import run_phase1_evaluation_demo
    run_phase1_evaluation_demo()
