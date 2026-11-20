"""
SafeOps - Telemetry Adapters (Tier 1 Customer Side)
===================================================
Provides modular telemetry input adapters:
1. SimulatedTelemetryAdapter (default: Customer A & B, 3 hosts each)
2. FileTelemetryAdapter (reads JSON/CSV stream files)
3. HTTPTelemetryAdapter (accepts external HTTP POST for hackathon test harnesses)
4. SocketTelemetryAdapter (stream listener)
"""

import abc
import datetime
import json
import math
import os
import random
import time
import uuid
from typing import Any, Dict, List, Optional


class BaseTelemetryAdapter(abc.ABC):
    """Abstract base class for telemetry ingestion adapters."""

    @abc.abstractmethod
    def fetch_records(self) -> List[Dict[str, Any]]:
        """Fetch or generate the next batch of raw telemetry events."""
        pass

    @abc.abstractmethod
    def inject_chaos(self, scenario: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Inject an anomaly or failure scenario for testing."""
        pass

    @abc.abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Return adapter health and metadata."""
        pass


class SimulatedTelemetryAdapter(BaseTelemetryAdapter):
    """
    Simulates real-world operational telemetry for 2 tenants, 3 hosts each:
    Tenant A: srv-prod-web-01.internal, srv-prod-app-01.internal, srv-prod-db-01.internal
    Tenant B: corp-payment-01.local, corp-order-01.local, corp-auth-01.local

    Generates metrics every 2 seconds:
    - CPU, Memory, Disk, Bandwidth, Latency, Packet Loss, Service Status, and Auth Logs.
    - Some logs contain realistic fake secrets (passwords, tokens, internal IPs, emails).
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.tenants = config.get("tenants", {})
        self.tick_count = 0
        self.start_time = time.time()

        # Active chaos overrides: dict mapping host -> dict of active overrides
        # e.g., {"srv-prod-web-01.internal": {"cpu_spike": True, "expires": ...}}
        self.chaos_overrides: Dict[str, Dict[str, Any]] = {}
        self.simulated_saas_outage = False
        self.heartbeat_paused = False
        self.duplicate_injection_queue: List[Dict[str, Any]] = []

        # Baseline profiles per host to simulate realistic distinct behaviors
        self.host_baselines = {
            # Tenant A
            "srv-prod-web-01.internal": {"cpu": 32.0, "mem": 48.0, "disk": 55.0, "lat": 22.0, "bw": 120.0},
            "srv-prod-app-01.internal": {"cpu": 45.0, "mem": 62.0, "disk": 60.0, "lat": 30.0, "bw": 85.0},
            "srv-prod-db-01.internal":  {"cpu": 38.0, "mem": 72.0, "disk": 78.0, "lat": 18.0, "bw": 45.0},
            # Tenant B
            "corp-payment-01.local":    {"cpu": 28.0, "mem": 52.0, "disk": 50.0, "lat": 25.0, "bw": 110.0},
            "corp-order-01.local":      {"cpu": 35.0, "mem": 58.0, "disk": 62.0, "lat": 28.0, "bw": 95.0},
            "corp-auth-01.local":       {"cpu": 22.0, "mem": 42.0, "disk": 40.0, "lat": 15.0, "bw": 30.0},
        }

    def inject_chaos(self, scenario: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Inject chaos buttons for live hackathon judge testing."""
        from tier1_collector.pipeline import pseudonymize_hostname
        params = params or {}
        now = time.time()
        duration = params.get("duration", 20.0)  # seconds
        target_tenant = params.get("tenant_id") or params.get("tenant") or "tenant-a"
        target_host = params.get("hostname") or params.get("host")

        # Map each scenario to a fixed, known host if not explicitly specified
        FIXED_HOST_MAP = {
            "cpu_spike": "srv-prod-web-01.internal",
            "latency_rise": "srv-prod-app-01.internal",
            "packet_loss": "srv-prod-app-01.internal",
            "repeated_failed_logins": "srv-prod-db-01.internal",
            "secret_in_log": "srv-prod-web-01.internal",
            "service_down": "srv-prod-web-01.internal",
            "duplicate_events": "srv-prod-web-01.internal"
        }
        if not target_host or target_host == "all":
            target_host = FIXED_HOST_MAP.get(scenario, "srv-prod-web-01.internal")

        salt = self.config.get("pseudonym_salt", "safeops_deterministic_salt_tier1_2026")
        pseudonym = pseudonymize_hostname(target_tenant, target_host, salt)

        if target_host not in self.chaos_overrides:
            self.chaos_overrides[target_host] = {}

        action_msg = f"Injected on {target_host} \u2192 pseudonym {pseudonym}"

        if scenario == "cpu_spike":
            self.chaos_overrides[target_host]["cpu_spike"] = {
                "value": random.uniform(94.0, 99.5),
                "expires": now + duration
            }
            return {
                "status": "injected",
                "scenario": scenario,
                "host": target_host,
                "real_host": target_host,
                "pseudonym": pseudonym,
                "message": action_msg,
                "detail": f"{action_msg} (CPU 95-99%)"
            }

        elif scenario == "latency_rise":
            self.chaos_overrides[target_host]["latency_rise"] = {
                "value": random.uniform(380.0, 520.0),
                "expires": now + duration
            }
            return {
                "status": "injected",
                "scenario": scenario,
                "host": target_host,
                "real_host": target_host,
                "pseudonym": pseudonym,
                "message": action_msg,
                "detail": f"{action_msg} (Latency 380-520ms)"
            }

        elif scenario == "packet_loss":
            self.chaos_overrides[target_host]["packet_loss"] = {
                "value": random.uniform(7.5, 14.0),
                "expires": now + duration
            }
            return {
                "status": "injected",
                "scenario": scenario,
                "host": target_host,
                "real_host": target_host,
                "pseudonym": pseudonym,
                "message": action_msg,
                "detail": f"{action_msg} (Packet loss 7.5-14%)"
            }

        elif scenario == "repeated_failed_logins":
            self.chaos_overrides[target_host]["failed_logins"] = {
                "count": random.randint(6, 12),
                "expires": now + 15.0
            }
            return {
                "status": "injected",
                "scenario": scenario,
                "host": target_host,
                "real_host": target_host,
                "pseudonym": pseudonym,
                "message": action_msg,
                "detail": f"{action_msg} (Repeated failed login burst)"
            }

        elif scenario == "secret_in_log":
            self.chaos_overrides[target_host]["leak_secret"] = {
                "active": True,
                "expires": now + 10.0
            }
            return {
                "status": "injected",
                "scenario": scenario,
                "host": target_host,
                "real_host": target_host,
                "pseudonym": pseudonym,
                "message": action_msg,
                "detail": f"{action_msg} (Credentials & API tokens in raw log)"
            }

        elif scenario == "service_down":
            self.chaos_overrides[target_host]["service_down"] = {
                "active": True,
                "expires": now + duration
            }
            return {
                "status": "injected",
                "scenario": scenario,
                "host": target_host,
                "real_host": target_host,
                "pseudonym": pseudonym,
                "message": action_msg,
                "detail": f"{action_msg} (Service down)"
            }

        elif scenario == "saas_outage":
            self.simulated_saas_outage = not self.simulated_saas_outage
            state_str = "ENABLED (collector will buffer in SQLite)" if self.simulated_saas_outage else "DISABLED (collector will flush buffer)"
            return {"status": "toggled", "scenario": "saas_outage", "is_outage_active": self.simulated_saas_outage, "message": state_str}

        elif scenario == "toggle_heartbeat":
            self.heartbeat_paused = not getattr(self, "heartbeat_paused", False)
            state_str = "PAUSED (Heartbeat stopped - Watch for OFFLINE after 60s)" if self.heartbeat_paused else "RESUMED (Heartbeats active)"
            return {"status": "toggled", "scenario": "toggle_heartbeat", "heartbeat_paused": self.heartbeat_paused, "message": state_str}

        elif scenario == "duplicate_events":
            # Schedule duplicate payload injection on next tick
            self.chaos_overrides[target_host]["inject_duplicate"] = {
                "active": True,
                "expires": now + 10.0
            }
            return {"status": "injected", "scenario": scenario, "host": target_host, "detail": "Duplicate & out-of-order event generation"}

        elif scenario == "clear_chaos":
            self.chaos_overrides.clear()
            self.simulated_saas_outage = False
            return {"status": "cleared", "scenario": "all_normal"}

        return {"status": "error", "message": f"Unknown chaos scenario '{scenario}'"}

    def resolve_pseudonym_to_host(self, tenant_id: str, pseudonym: str) -> Optional[str]:
        """Maps a pseudonymous source ID back to the local host name."""
        from tier1_collector.pipeline import pseudonymize_hostname
        salt = self.config.get("pseudonym_salt", "safeops_deterministic_salt_tier1_2026")
        for tid, tconf in self.tenants.items():
            if tenant_id and tid != tenant_id:
                continue
            for h in tconf.get("hosts", []):
                if pseudonymize_hostname(tid, h, salt) == pseudonym:
                    return h
        return None

    def clear_chaos_for_host(self, hostname: str, action: Optional[str] = None) -> bool:
        """Clears ONLY the matching chaos override on this host (CPU, latency, packet loss, failed logins, service down)."""
        if hostname in self.chaos_overrides:
            action_map = {
                "throttle_process": ["cpu_spike"],
                "scale_cpu_quota": ["cpu_spike"],
                "reroute_uplink": ["latency_rise", "packet_loss"],
                "apply_mfa_firewall": ["failed_logins"],
                "restart_service": ["service_down"]
            }
            target_scenarios = action_map.get(action)
            if target_scenarios:
                for sc in target_scenarios:
                    self.chaos_overrides[hostname].pop(sc, None)
            else:
                self.chaos_overrides[hostname].clear()

            if not self.chaos_overrides[hostname]:
                del self.chaos_overrides[hostname]
            return True
        return False

    def is_saas_outage_active(self) -> bool:
        return self.simulated_saas_outage

    def is_heartbeat_paused(self) -> bool:
        return getattr(self, "heartbeat_paused", False)

    def fetch_records(self) -> List[Dict[str, Any]]:
        """Generates realistic telemetry for every host in every configured tenant."""
        self.tick_count += 1
        now = time.time()
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        records: List[Dict[str, Any]] = []

        # Clean expired chaos overrides
        for host in list(self.chaos_overrides.keys()):
            for sc in list(self.chaos_overrides[host].keys()):
                if self.chaos_overrides[host][sc].get("expires", 0) < now:
                    del self.chaos_overrides[host][sc]
            if not self.chaos_overrides[host]:
                del self.chaos_overrides[host]

        for tenant_id, tenant_info in self.tenants.items():
            hosts = tenant_info.get("hosts", [])
            for hostname in hosts:
                base = self.host_baselines.get(hostname, {"cpu": 35.0, "mem": 50.0, "disk": 60.0, "lat": 25.0, "bw": 100.0})
                overrides = self.chaos_overrides.get(hostname, {})

                # Smooth natural oscillation using sine + random jitter
                sine_wave = math.sin(self.tick_count * 0.15 + hash(hostname) % 10) * 4.0

                # CPU Calculation
                if "cpu_spike" in overrides:
                    cpu = overrides["cpu_spike"]["value"]
                else:
                    cpu = max(5.0, min(92.0, base["cpu"] + sine_wave + random.uniform(-2.5, 2.5)))

                # Memory Calculation
                mem = max(10.0, min(95.0, base["mem"] + (sine_wave * 0.5) + random.uniform(-1.0, 1.0)))
                # If CPU is spiking, memory also experiences slight pressure
                if "cpu_spike" in overrides:
                    mem = min(96.0, mem + 18.0)

                # Disk Calculation (slow gradual growth)
                disk = max(10.0, min(99.0, base["disk"] + random.uniform(-0.1, 0.1)))

                # Latency Calculation
                if "latency_rise" in overrides:
                    latency = overrides["latency_rise"]["value"]
                else:
                    latency = max(5.0, base["lat"] + (sine_wave * 0.8) + random.uniform(-3.0, 3.0))

                # Packet Loss Calculation
                if "packet_loss" in overrides:
                    packet_loss = overrides["packet_loss"]["value"]
                else:
                    packet_loss = max(0.0, min(100.0, random.uniform(0.0, 0.15) if random.random() > 0.3 else 0.0))

                # Bandwidth Calculation
                bw = max(5.0, base["bw"] + (sine_wave * 3.0) + random.uniform(-8.0, 8.0))

                # Service Status (1 = UP, 0 = DOWN)
                if "service_down" in overrides:
                    service_status = 0
                else:
                    service_status = 1

                # Auth Log Lines & Fake Secrets Generation
                auth_lines: List[str] = []
                fake_secrets: List[str] = []

                if "failed_logins" in overrides:
                    # Generate repeated failed login burst
                    fl_count = overrides["failed_logins"]["count"]
                    for i in range(fl_count):
                        bad_pwd = f"attempt_{i}_password=P@ssw0rd{random.randint(100, 999)}!"
                        bad_ip = f"192.168.1.{random.randint(10, 250)}"
                        auth_lines.append(
                            f"FAILED LOGIN: host={hostname} user=root source_ip={bad_ip} {bad_pwd} reason=invalid_credentials"
                        )
                else:
                    # Occasional normal auth activity
                    if random.random() < 0.4:
                        auth_lines.append(f"SUCCESSFUL LOGIN: host={hostname} user=appuser_{tenant_id} method=ssh_pubkey session_id={uuid.uuid4().hex[:8]}")

                # Secret in Log scenario or occasional ambient secret leak
                if "leak_secret" in overrides or random.random() < 0.15:
                    sample_pwd = f"SecretP@ssword{random.randint(1000, 9999)}!"
                    sample_token = f"sk_live_{uuid.uuid4().hex}{uuid.uuid4().hex[:12]}"
                    sample_ip = f"10.0.{random.randint(1, 100)}.{random.randint(2, 254)}"
                    sample_email = f"lead.engineer_{random.randint(1,99)}@{tenant_id}.internal"

                    secret_line = (
                        f"AUDIT_DEBUG: host={hostname} user={sample_email} auth_token={sample_token} "
                        f"bind_ip={sample_ip} fallback_password={sample_pwd} action=sync_cluster_state"
                    )
                    auth_lines.append(secret_line)
                    fake_secrets.append("API Token, Password, Internal IP, Corporate Email")

                # Resolve source timezone from tenant profile (e.g. America/New_York vs Europe/Frankfurt)
                tenant_conf = self.tenants.get(tenant_id, {})
                source_tz = tenant_conf.get("source_timezone", "America/New_York" if tenant_id == "tenant-a" else "Europe/Frankfurt")

                # Build raw event record
                raw_record = {
                    "raw_id": str(uuid.uuid4()),
                    "tenant_id": tenant_id,
                    "hostname": hostname,  # REAL internal hostname
                    "timestamp_local": datetime.datetime.now().isoformat(),
                    "timestamp_utc": utc_now.isoformat(),
                    "source_timezone": source_tz,
                    "metrics": {
                        "cpu_usage_pct": round(cpu, 2),
                        "memory_usage_pct": round(mem, 2),
                        "disk_usage_pct": round(disk, 2),
                        "bandwidth_mbps": round(bw, 2),
                        "latency_ms": round(latency, 2),
                        "packet_loss_pct": round(packet_loss, 2),
                        "service_status": int(service_status),
                    },
                    "raw_logs": auth_lines,
                    "ambient_secrets_present": bool(fake_secrets),
                    "secret_types": fake_secrets,
                    # Internal tags that should NEVER leave the customer boundary
                    "internal_tags": {
                        "rack_unit": f"RU-{random.randint(1, 42)}",
                        "datacenter": "on-prem-vault-alpha",
                        "hypervisor": "esxi-enterprise-internal.corp",
                        "kernel_debug": "vmlinuz-5.15.0-customer-custom"
                    }
                }

                # Duplicate / out-of-order injection test
                if "inject_duplicate" in overrides:
                    # Clone record with duplicate payload ID and delayed timestamp
                    dup_record = dict(raw_record)
                    dup_record["raw_id"] = str(uuid.uuid4())
                    # backdate timestamp by 45 seconds to test out-of-order handling
                    backdated_time = (utc_now - datetime.timedelta(seconds=45)).isoformat()
                    dup_record["timestamp_utc"] = backdated_time
                    dup_record["is_injected_duplicate"] = True
                    self.duplicate_injection_queue.append(dup_record)
                    del overrides["inject_duplicate"]

                records.append(raw_record)

        # Append any queued duplicate events
        if self.duplicate_injection_queue:
            records.extend(self.duplicate_injection_queue)
            self.duplicate_injection_queue.clear()

        return records

    def get_status(self) -> Dict[str, Any]:
        return {
            "adapter_type": "SimulatedTelemetryAdapter",
            "uptime_seconds": round(time.time() - self.start_time, 1),
            "ticks_generated": self.tick_count,
            "active_overrides": self.chaos_overrides,
            "saas_outage_simulated": self.simulated_saas_outage
        }


class ExternalHTTPTelemetryAdapter(BaseTelemetryAdapter):
    """
    HTTP Telemetry Adapter:
    Allows organizers or external agents to push raw telemetry directly via POST.
    """

    def __init__(self):
        self.buffer: List[Dict[str, Any]] = []
        self.received_count = 0

    def push_external_event(self, event: Dict[str, Any]):
        """Called by FastAPI when external harness POSTs data."""
        if "raw_id" not in event:
            event["raw_id"] = str(uuid.uuid4())
        if "timestamp_utc" not in event:
            event["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.buffer.append(event)
        self.received_count += 1

    def fetch_records(self) -> List[Dict[str, Any]]:
        records = list(self.buffer)
        self.buffer.clear()
        return records

    def inject_chaos(self, scenario: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {"status": "noop", "message": "External adapter receives data from outside harness"}

    def get_status(self) -> Dict[str, Any]:
        return {
            "adapter_type": "ExternalHTTPTelemetryAdapter",
            "buffered_records": len(self.buffer),
            "total_received": self.received_count
        }


class FileTelemetryAdapter(BaseTelemetryAdapter):
    """
    File Telemetry Adapter:
    Tails or reads telemetry JSON/NDJSON lines from an organizer's file stream.
    """

    def __init__(self, file_path: str = "telemetry_input.ndjson"):
        self.file_path = file_path
        self.last_position = 0
        self.total_read = 0

    def fetch_records(self) -> List[Dict[str, Any]]:
        import os
        if not os.path.exists(self.file_path):
            return []

        records: List[Dict[str, Any]] = []
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                # If file was truncated/restarted, reset pointer
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size < self.last_position:
                    self.last_position = 0

                f.seek(self.last_position)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "raw_id" not in data:
                            data["raw_id"] = str(uuid.uuid4())
                        if "timestamp_utc" not in data:
                            data["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        records.append(data)
                        self.total_read += 1
                    except json.JSONDecodeError:
                        continue
                self.last_position = f.tell()
        except Exception:
            pass
        return records

    def inject_chaos(self, scenario: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {"status": "noop", "message": f"File adapter reads from {self.file_path}"}

    def get_status(self) -> Dict[str, Any]:
        import os
        return {
            "adapter_type": "FileTelemetryAdapter",
            "file_path": self.file_path,
            "file_exists": os.path.exists(self.file_path),
            "total_records_read": self.total_read
        }


class SocketTelemetryAdapter(BaseTelemetryAdapter):
    """
    Socket Telemetry Adapter:
    Listens on a TCP socket (e.g., 127.0.0.1:9095) for newline-delimited JSON streams.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9095):
        import collections
        import socket
        import threading

        self.host = host
        self.port = port
        self.queue = collections.deque(maxlen=2000)
        self.total_received = 0
        self.running = True
        self.sock = None

        self.thread = threading.Thread(target=self._server_loop, daemon=True)
        self.thread.start()

    def _server_loop(self):
        import socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.sock.settimeout(1.0)
            while self.running:
                try:
                    conn, _ = self.sock.accept()
                except socket.timeout:
                    continue
                except Exception:
                    break

                with conn:
                    conn.settimeout(2.0)
                    buffer = ""
                    while self.running:
                        try:
                            chunk = conn.recv(4096).decode("utf-8")
                            if not chunk:
                                break
                            buffer += chunk
                            while "\n" in buffer:
                                line, buffer = buffer.split("\n", 1)
                                line = line.strip()
                                if line:
                                    try:
                                        item = json.loads(line)
                                        if "raw_id" not in item:
                                            item["raw_id"] = str(uuid.uuid4())
                                        if "timestamp_utc" not in item:
                                            item["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                                        self.queue.append(item)
                                        self.total_received += 1
                                    except Exception:
                                        pass
                        except Exception:
                            break
        except Exception:
            pass
        finally:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass

    def fetch_records(self) -> List[Dict[str, Any]]:
        records = []
        while self.queue:
            try:
                records.append(self.queue.popleft())
            except IndexError:
                break
        return records

    def inject_chaos(self, scenario: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {"status": "noop", "message": f"Socket adapter listening on {self.host}:{self.port}"}

    def get_status(self) -> Dict[str, Any]:
        return {
            "adapter_type": "SocketTelemetryAdapter",
            "host": self.host,
            "port": self.port,
            "buffered_count": len(self.queue),
            "total_received": self.total_received
        }

    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


class UniversalFeedAdapter(BaseTelemetryAdapter):
    """
    Universal Input Feed Adapter:
    Allows switching telemetry input format via a single configuration setting:
    - "simulator" (default): generates simulated JSON lines for Customer A & B
    - "jsonl": reads/tails JSON Lines from a file stream
    - "csv": reads/tails CSV data from a file stream
    - "syslog": reads/tails RFC 5424/3164 Syslog messages from a file stream
    - "http": purely awaits incoming HTTP API pushes on /api/v1/adapter/push
    - "auto": sniffs incoming line/file structure and auto-parses
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None, feed_file_path: Optional[str] = None, default_mode: Optional[str] = None):
        from tier1_collector.format_parser import UniversalFormatParser

        self.config = config or {}
        if default_mode:
            self.format_mode = str(default_mode).lower()
        else:
            self.format_mode = str(self.config.get("input_format", "simulator")).lower()

        if feed_file_path:
            self.feed_file_path = feed_file_path
        else:
            self.feed_file_path = self.config.get("feed_file_path", "data_feed/telemetry_input.data")
        self.file_last_position = 0

        self.parser = UniversalFormatParser
        self.sim_adapter = SimulatedTelemetryAdapter(self.config)
        self.http_buffer: List[Dict[str, Any]] = []

        self.records_by_format: Dict[str, int] = {
            "simulator": 0,
            "jsonl": 0,
            "csv": 0,
            "syslog": 0,
            "http": 0,
            "auto": 0
        }

    def set_mode(self, mode: str):
        """Allows switching the input format on-the-fly via API or UI."""
        clean_mode = mode.lower().strip()
        valid_modes = {"simulator", "jsonl", "csv", "syslog", "http", "auto"}
        if clean_mode in valid_modes:
            self.format_mode = clean_mode
            self.file_last_position = 0  # Reset file pointer on format switch

    def get_mode(self) -> str:
        return self.format_mode

    def push_external_payload(self, raw_input: Any, forced_format: Optional[str] = None):
        """Pushes raw payload from HTTP/API endpoint and parses according to active or forced format."""
        fmt = (forced_format or self.format_mode).lower()

        # If already a list of dicts (standard JSON API push)
        if isinstance(raw_input, list):
            for item in raw_input:
                if isinstance(item, dict):
                    rec = self.parser.parse_jsonl_line(json.dumps(item))
                    if rec:
                        self.http_buffer.append(rec)
                        self.records_by_format["http"] += 1
            return

        if isinstance(raw_input, dict):
            rec = self.parser.parse_jsonl_line(json.dumps(raw_input))
            if rec:
                self.http_buffer.append(rec)
                self.records_by_format["http"] += 1
            return

        # If string / text payload
        text = str(raw_input).strip()
        if not text:
            return

        if fmt == "csv":
            recs = self.parser.parse_csv_stream(text)
            self.http_buffer.extend(recs)
            self.records_by_format["csv"] += len(recs)
        elif fmt == "syslog":
            for line in text.splitlines():
                rec = self.parser.parse_syslog_line(line)
                if rec:
                    self.http_buffer.append(rec)
                    self.records_by_format["syslog"] += 1
        elif fmt == "jsonl":
            for line in text.splitlines():
                rec = self.parser.parse_jsonl_line(line)
                if rec:
                    self.http_buffer.append(rec)
                    self.records_by_format["jsonl"] += 1
        else:
            # Auto-detect format
            recs = self.parser.auto_detect_and_parse(text)
            self.http_buffer.extend(recs)
            self.records_by_format["auto"] += len(recs)

    def fetch_records(self) -> List[Dict[str, Any]]:
        """Pulls telemetry according to current active input format."""
        records: List[Dict[str, Any]] = []

        # 1. Drain HTTP incoming buffer
        if self.http_buffer:
            records.extend(self.http_buffer)
            self.http_buffer.clear()

        # 2. Simulator mode (Default procedural JSON lines generator)
        if self.format_mode == "simulator":
            sim_recs = self.sim_adapter.fetch_records()
            self.records_by_format["simulator"] += len(sim_recs)
            records.extend(sim_recs)
            return records

        # 3. HTTP only mode
        if self.format_mode == "http":
            return records

        # 4. File-based streaming modes (jsonl, csv, syslog, auto)
        if os.path.exists(self.feed_file_path):
            try:
                with open(self.feed_file_path, "r", encoding="utf-8") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    if size < self.file_last_position:
                        self.file_last_position = 0

                    f.seek(self.file_last_position)
                    buffer_lines = []
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        buffer_lines.append(line)
                    self.file_last_position = f.tell()

                if buffer_lines:
                    chunk = "".join(buffer_lines)
                    if self.format_mode == "csv":
                        recs = self.parser.parse_csv_stream(chunk)
                        self.records_by_format["csv"] += len(recs)
                        records.extend(recs)
                    elif self.format_mode == "syslog":
                        for l in buffer_lines:
                            r = self.parser.parse_syslog_line(l)
                            if r:
                                records.append(r)
                                self.records_by_format["syslog"] += 1
                    elif self.format_mode == "jsonl":
                        for l in buffer_lines:
                            r = self.parser.parse_jsonl_line(l)
                            if r:
                                records.append(r)
                                self.records_by_format["jsonl"] += 1
                    else:  # auto
                        recs = self.parser.auto_detect_and_parse(chunk)
                        self.records_by_format["auto"] += len(recs)
                        records.extend(recs)
            except Exception:
                pass

        return records

    def inject_chaos(self, scenario: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Passes chaos injection to simulator or handles global chaos toggles."""
        return self.sim_adapter.inject_chaos(scenario, params)

    def is_saas_outage_active(self) -> bool:
        return self.sim_adapter.is_saas_outage_active()

    def is_heartbeat_paused(self) -> bool:
        return self.sim_adapter.is_heartbeat_paused()

    def resolve_pseudonym_to_host(self, tenant_id: str, pseudonym: str) -> Optional[str]:
        return self.sim_adapter.resolve_pseudonym_to_host(tenant_id, pseudonym)

    def clear_chaos_for_host(self, hostname: str, action: Optional[str] = None) -> bool:
        return self.sim_adapter.clear_chaos_for_host(hostname, action)

    def get_status(self) -> Dict[str, Any]:
        return {
            "adapter_type": "UniversalFeedAdapter",
            "current_format": self.format_mode,
            "feed_file_path": self.feed_file_path,
            "feed_file_exists": os.path.exists(self.feed_file_path),
            "records_ingested_by_format": self.records_by_format,
            "simulator_status": self.sim_adapter.get_status(),
            "saas_outage_simulated": self.sim_adapter.is_saas_outage_active()
        }
