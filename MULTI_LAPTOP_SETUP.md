# SafeOps: Multi-Laptop & Real Telemetry Setup Guide

This guide explains how to connect a second laptop (or virtual machine) to SafeOps to stream real hardware telemetry, network metrics, web app availability, and syslog messages across a local area network (LAN).

---

## Network Architecture & IP Addresses

| Role | Device | Host / IP | Port | Protocol |
| :--- | :--- | :--- | :--- | :--- |
| **SaaS Cloud Platform (Tier 2)** | Laptop 1 (Host) | `172.17.5.140` | `8002` | HTTPS (TLS with SAN for LAN IP) |
| **Primary Collector (Tier 1)** | Laptop 1 (Host) | `172.17.5.140` | `8001` | HTTP |
| **Syslog UDP Listener** | Laptop 1 (Host) | `172.17.5.140` | `5514` | UDP |
| **Agent / Customer B (Tier 1)** | Laptop 2 | Any LAN IP | Dynamic | Outbound to `8001` or `8002` |

---

## Setup Steps for Laptop 2 (Simple English)

You have two simple ways to run Laptop 2:
- **Option A (Quickest - Standalone Hardware Agent)**: Run the lightweight `agent/agent.py` script on Laptop 2. It samples real CPU, RAM, Disk, and Network IO every 5s and pushes to Laptop 1.
- **Option B (Full Distributed Architecture)**: Run a complete Tier 1 Collector daemon on Laptop 2 with its own SQLite store-and-forward buffer, sending directly to Laptop 1's SaaS over HTTPS.

---

### Option A: Running the Standalone Agent on Laptop 2 (2 Minutes)

1. **Connect both laptops to the same Wi-Fi / Local Network**.
2. **On Laptop 2**, ensure Python 3 is installed and install `psutil`:
   ```bash
   pip install psutil
   ```
3. **Copy `agent/agent.py`** to Laptop 2 (or clone the repository).
4. **Run the agent pointing to Laptop 1**:
   ```bash
   python3 agent/agent.py --collector http://172.17.5.140:8001/api/v1/adapter/push --tenant tenant-b --interval 5.0
   ```
5. **What happens**:
   - The agent reads real hardware metrics from Laptop 2 using `psutil`.
   - It posts standard 10-column payloads to Laptop 1's `/api/v1/adapter/push` endpoint.
   - Laptop 1 redacts any ambient secrets, pseudonymizes the hostname, and buffers it.
   - Laptop 1 delivers it to SaaS. Open **`https://172.17.5.140:8002/dashboard`** on Laptop 1 and switch the tenant dropdown to **Tenant B** to see the real CPU and live telemetry!

---

### Option B: Running a Dedicated Tier 1 Collector on Laptop 2

1. **Copy the SafeOps folder to Laptop 2**.
2. **Copy the Root CA Certificate**:
   Copy `certs/rootCA.pem` from Laptop 1 to Laptop 2 at `certs/rootCA.pem`.
   *(This allows Python and curl on Laptop 2 to verify Laptop 1's HTTPS certificate without warnings).*
3. **Edit `config/collector_config.json` on Laptop 2**:
   ```json
   {
     "collector_version": "1.0.0-hackathon",
     "saas_url": "https://172.17.5.140:8002",
     "ca_bundle_path": "certs/rootCA.pem",
     "heartbeat_interval_seconds": 10,
     "raw_retention_minutes": 60,
     "pseudonym_salt": "safeops_deterministic_salt_tier1_2026",
     "collect_interval_seconds": 2.0,
     "simulator_enabled": false,
     "input_format": "simulator",
     "feed_file_path": "data_feed/telemetry_input.data",
     "db_path": "collector_local.db",
     "default_region": "eu-central-1",
     "tenants": {
       "tenant-b": {
         "name": "Customer B (Healthcare Core)",
         "api_key": "sec_key_tenant_b_443322",
         "data_residency_region": "eu-central-1",
         "jurisdiction": "EU-GDPR",
         "source_timezone": "Europe/Frankfurt",
         "hosts": [
           "corp-payment-01.local",
           "corp-order-01.local",
           "corp-auth-01.local"
         ]
       }
     }
   }
   ```
4. **Test HTTPS connection from Laptop 2**:
   ```bash
   curl --cacert certs/rootCA.pem https://172.17.5.140:8002/api/v1/residency/status
   ```
   *(Returns 200 OK with server region `us-east-1` and active policies).*
5. **Start Collector on Laptop 2**:
   ```bash
   ./start_collector.sh
   # Or: python3 -m uvicorn tier1_collector.app:app --host 0.0.0.0 --port 8001
   ```

---

## How to Demonstrate Live Proof to Judges

### 1. Show Real Hardware CPU Spike (AIOps Incident Detection)
On Laptop 2, run a CPU stress loop to drive utilization up:
```bash
# Start multi-core stress in background
for i in $(seq 1 $(sysctl -n hw.ncpu 2>/dev/null || nproc)); do yes > /dev/null & done

# Watch the agent push 95%+ CPU:
python3 agent/agent.py --tenant tenant-b --hostname corp-order-01.local --once
```
**Dashboard & AIOps Result**:
- Within 2 seconds, the SaaS AIOps engine at `https://172.17.5.140:8002/incidents` detects a **+21σ z-score CPU anomaly** on `host-fcc45d28` (`corp-order-01.local`).
- Flags incident `inc-xxxx` with **CRITICAL** severity, **94% confidence**, and recommended remediation: *"Throttle background job priority (nice +10) or restart runaway worker"*.

To stop the stress loop:
```bash
killall yes
```

### 2. Show Web App Down Detection (Port / Process Outage)
Start a temporary test web server on port 9090:
```bash
python3 -m http.server 9090
```
- WebAppProbe probes `http://127.0.0.1:9090` $\rightarrow$ `service_status = 1` (UP), `health_state = EXCELLENT`.
- Press `Ctrl+C` on the web server to stop it.
- Within 5 seconds, WebAppProbe receives connection refused $\rightarrow$ `service_status = 0` (DOWN), `health_state = POOR`, `severity = CRITICAL`, `short_context = Service process DOWN`.

### 3. Forward External Syslog over UDP Port 5514
Any server or router on the network can send standard Syslog to port 5514:
```bash
echo "<134>1 2026-11-21T12:00:00Z corp-auth-01.local app 1234 - - FAILED LOGIN user=admin password=SecretAdminKey99! invalid_credentials" | nc -u -w1 172.17.5.140 5514
```
- Collector receives UDP on port 5514.
- Zero-Trust Pipeline scrubs `password=SecretAdminKey99!` to `password=[REDACTED_PASSWORD]`.
- Local Security Analyzer evaluates failed logins in sliding 30s window without leaking raw logs.
