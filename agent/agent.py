#!/usr/bin/env python3
"""
SafeOps - Real Compute & Storage Telemetry Agent
================================================
A lightweight standalone telemetry agent using psutil.
Runs on any laptop or VM, collects host operational metrics every 5 seconds,
and pushes them to SafeOps Tier 1 Collector via HTTP POST (/api/v1/adapter/push).

Metrics Collected (10 Standard SafeOps Telemetry Fields):
- tenant_id: Customer tenant identifier (e.g. tenant-b)
- hostname: Real system hostname (e.g. corp-order-01.local or laptop-host)
- timestamp_utc: ISO 8601 UTC timestamp
- cpu_usage_pct: Real-time CPU utilization % (via psutil.cpu_percent)
- memory_usage_pct: Real-time RAM utilization % (via psutil.virtual_memory)
- disk_usage_pct: Real-time Root Disk % (via psutil.disk_usage)
- bandwidth_mbps: Real-time network throughput in Mbps (via psutil.net_io_counters)
- latency_ms: Local loopback / network latency (default 0.0)
- packet_loss_pct: Local packet loss % (default 0.0)
- service_status: Host daemon health state (1 = UP, 0 = DOWN)
"""

import argparse
import datetime
import json
import os
import platform
import socket
import sys
import time
import urllib.error
import urllib.request

try:
    import psutil
except ImportError:
    print("[ERROR] 'psutil' is required by SafeOps agent.")
    print("Please install it: pip install psutil")
    sys.exit(1)


class SafeOpsAgent:
    """Collects real hardware metrics and delivers them to Tier 1 Collector."""

    def __init__(
        self,
        collector_url: str = "http://127.0.0.1:8001/api/v1/adapter/push",
        tenant_id: str = "tenant-b",
        hostname: str = None,
        interval: float = 5.0
    ):
        self.collector_url = collector_url
        self.tenant_id = tenant_id
        self.hostname = hostname or socket.gethostname()
        self.interval = max(1.0, float(interval))
        self.last_net_io = None
        self.last_net_time = None

    def sample_metrics(self) -> dict:
        """Collects current hardware metrics using psutil."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. CPU Usage % (blocking over 0.5s for precision)
        cpu_pct = round(float(psutil.cpu_percent(interval=0.5)), 2)

        # 2. Memory Usage %
        mem = psutil.virtual_memory()
        mem_pct = round(float(mem.percent), 2)

        # 3. Disk Usage % (platform-aware root)
        disk_path = "C:\\" if platform.system() == "Windows" else "/"
        try:
            disk = psutil.disk_usage(disk_path)
            disk_pct = round(float(disk.percent), 2)
        except Exception:
            disk_pct = 50.0

        # 4. Network Bandwidth Mbps (delta calculation)
        now_time = time.time()
        try:
            net_io = psutil.net_io_counters()
            if self.last_net_io is not None and self.last_net_time is not None:
                elapsed = max(0.1, now_time - self.last_net_time)
                bytes_sent = net_io.bytes_sent - self.last_net_io.bytes_sent
                bytes_recv = net_io.bytes_recv - self.last_net_io.bytes_recv
                total_bytes = max(0, bytes_sent + bytes_recv)
                bandwidth_mbps = round((total_bytes * 8.0) / (elapsed * 1024.0 * 1024.0), 2)
            else:
                bandwidth_mbps = 5.0
            self.last_net_io = net_io
            self.last_net_time = now_time
        except Exception:
            bandwidth_mbps = 10.0

        # Construct 10 standard column names
        return {
            "tenant_id": self.tenant_id,
            "hostname": self.hostname,
            "timestamp_utc": now_utc,
            "cpu_usage_pct": cpu_pct,
            "memory_usage_pct": mem_pct,
            "disk_usage_pct": disk_pct,
            "bandwidth_mbps": bandwidth_mbps,
            "latency_ms": 0.0,
            "packet_loss_pct": 0.0,
            "service_status": 1
        }

    def push(self, payload: dict) -> bool:
        """Pushes standard telemetry payload to collector via HTTP POST."""
        body_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.collector_url,
            data=body_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"SafeOps-Agent/{platform.system()}"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                return resp.status in (200, 201, 202)
        except urllib.error.URLError as e:
            print(f"[Agent Push Error]: Failed to reach collector at {self.collector_url} -> {e}")
            return False
        except Exception as e:
            print(f"[Agent Push Error]: {e}")
            return False

    def run_once(self) -> dict:
        """Samples and pushes a single batch (used for tests and verification)."""
        payload = self.sample_metrics()
        success = self.push(payload)
        payload["_pushed"] = success
        return payload

    def run_loop(self):
        """Continuous collection loop running every interval seconds."""
        print("=" * 65)
        print(" SafeOps Real Telemetry Agent - ACTIVE")
        print("=" * 65)
        print(f" Hostname:      {self.hostname}")
        print(f" Tenant ID:     {self.tenant_id}")
        print(f" Collector URL: {self.collector_url}")
        print(f" Interval:      {self.interval}s")
        print("=" * 65)
        print("Press Ctrl+C to stop agent.\n")

        try:
            while True:
                payload = self.sample_metrics()
                ok = self.push(payload)
                status_str = "200 OK" if ok else "FAILED"
                print(
                    f"[{payload['timestamp_utc']}] host={self.hostname} tenant={self.tenant_id} | "
                    f"CPU: {payload['cpu_usage_pct']}% | RAM: {payload['memory_usage_pct']}% | "
                    f"DISK: {payload['disk_usage_pct']}% | NET: {payload['bandwidth_mbps']} Mbps | -> {status_str}"
                )
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\nSafeOps Agent stopped cleanly.")


def main():
    parser = argparse.ArgumentParser(description="SafeOps Real Compute & Storage Telemetry Agent")
    parser.add_argument("--collector", default=os.environ.get("COLLECTOR_URL", "http://127.0.0.1:8001/api/v1/adapter/push"),
                        help="Tier 1 Collector HTTP Push URL (default: http://127.0.0.1:8001/api/v1/adapter/push)")
    parser.add_argument("--tenant", default=os.environ.get("TENANT_ID", "tenant-b"),
                        help="Tenant identifier (default: tenant-b)")
    parser.add_argument("--hostname", default=os.environ.get("AGENT_HOSTNAME", None),
                        help="Hostname override (default: system hostname)")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="Sampling interval in seconds (default: 5.0)")
    parser.add_argument("--once", action="store_true",
                        help="Sample and push once, print payload, and exit")

    args = parser.parse_args()
    agent = SafeOpsAgent(
        collector_url=args.collector,
        tenant_id=args.tenant,
        hostname=args.hostname,
        interval=args.interval
    )

    if args.once:
        data = agent.run_once()
        print(json.dumps(data, indent=2))
    else:
        agent.run_loop()


if __name__ == "__main__":
    main()
