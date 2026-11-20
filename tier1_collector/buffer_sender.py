"""
SafeOps - Buffer Sender & Heartbeat Worker (Tier 1 Customer Side)
================================================================
Background worker responsible for:
1. Resilient Outbound Delivery: Flushes SQLite buffer to Tier 2 SaaS over HTTP with API key
2. Outage Handling & Backoff: Backs off exponentially when SaaS is unreachable, keeping all events safe in SQLite
3. Heartbeat: Sends health beacon every 10s (CPU/memory of collector, version, queue size)
4. Local Data Retention Pruner: Deletes raw customer data older than 1 hour
"""

import asyncio
import collections
import json
import logging
import os
import ssl
import time
from typing import Any, Dict

import httpx
import psutil

from tier1_collector.storage import CollectorStorage

logger = logging.getLogger("SafeOpsCollectorSender")


class BufferSender:
    def __init__(self, config: Dict[str, Any], storage: CollectorStorage, adapter: Any):
        self.config = config
        self.storage = storage
        self.adapter = adapter
        # Resolve SaaS URL from environment or configuration
        raw_saas = (
            os.environ.get("SAAS_URL")
            or os.environ.get("SAAS_ADDRESS")
            or os.environ.get("SAFEOPS_SAAS_URL")
            or config.get("saas_url")
            or config.get("saas_address")
            or "http://127.0.0.1:8002"
        )
        if not raw_saas.startswith(("http://", "https://")):
            raw_saas = f"http://{raw_saas}"
        self.saas_url = raw_saas.rstrip("/")
        self.regional_endpoints = config.get("regional_endpoints", {})
        self.default_region = config.get("default_region", "us-east-1")
        self.tenants = config.get("tenants", {})
        self.collector_version = config.get("collector_version", "1.0.0-hackathon")
        self.heartbeat_interval = config.get("heartbeat_interval_seconds", 5.0)
        self.raw_retention_minutes = config.get("raw_retention_minutes", 60)
        self.running = False
        self.last_saas_status = "UNKNOWN"
        self.consecutive_failures = 0
        self.pending_remediation_confirmations = []
        ca_path = self.config.get("ca_bundle_path", "certs/rootCA.pem")
        ca_bundle = os.path.abspath(ca_path) if os.path.exists(ca_path) else (os.path.abspath("certs/cert.pem") if os.path.exists("certs/cert.pem") else True)
        self.http_client: httpx.AsyncClient = httpx.AsyncClient(timeout=4.0, verify=ca_bundle)

    def get_tenant_endpoint(self, tenant_id: str) -> tuple[str, str, str]:
        """Resolves target regional ingest endpoint, data residency region, and jurisdiction."""
        tenant_conf = self.tenants.get(tenant_id, {})
        region = tenant_conf.get("data_residency_region", self.default_region)
        jurisdiction = tenant_conf.get("jurisdiction", "GLOBAL-GENERAL")
        # If a dedicated regional ingest endpoint is configured, route to it
        regional_url = self.regional_endpoints.get(region) or self.saas_url
        if not regional_url.startswith(("http://", "https://")):
            regional_url = f"http://{regional_url}"
        return regional_url.rstrip("/"), region, jurisdiction

    def get_tenant_regional_headers(self, tenant_id: str) -> Dict[str, str]:
        """Builds regional and jurisdiction routing headers for egress requests."""
        tenant_conf = self.tenants.get(tenant_id, {})
        api_key = tenant_conf.get("api_key", "sec_key_default")
        _, region, jurisdiction = self.get_tenant_endpoint(tenant_id)
        return {
            "X-API-Key": api_key,
            "X-Tenant-ID": tenant_id,
            "X-Region-ID": region,
            "X-Jurisdiction": jurisdiction,
            "X-Data-Residency": region,
            "Content-Type": "application/json"
        }

    async def start(self):
        """Starts asynchronous background sender, heartbeat, and retention loops."""
        self.running = True
        asyncio.create_task(self._sender_loop())
        asyncio.create_task(self._heartbeat_loop())
        asyncio.create_task(self._retention_prune_loop())

    async def stop(self):
        self.running = False
        await self.http_client.aclose()

    async def _sender_loop(self):
        """Continuously pulls pending payloads from SQLite buffer and delivers to SaaS."""
        while self.running:
            try:
                # Check if simulated outage is enabled on the adapter
                if self.adapter.is_saas_outage_active():
                    self.last_saas_status = "SIMULATED_OUTAGE"
                    await asyncio.sleep(1.5)
                    continue

                pending_items = self.storage.get_pending_payloads(limit=60)
                if not pending_items:
                    await asyncio.sleep(0.4)
                    continue

                # Group by tenant_id for high-throughput batched delivery
                tenant_groups = collections.defaultdict(list)
                for item in pending_items:
                    tenant_groups[item["tenant_id"]].append(item)

                for tenant_id, items in tenant_groups.items():
                    tenant_conf = self.tenants.get(tenant_id, {})
                    api_key = tenant_conf.get("api_key", "sec_key_default")
                    target_url, target_region, jurisdiction = self.get_tenant_endpoint(tenant_id)

                    headers = {
                        "X-API-Key": api_key,
                        "X-Tenant-ID": tenant_id,
                        "X-Region-ID": target_region,
                        "X-Jurisdiction": jurisdiction,
                        "Content-Type": "application/json"
                    }

                    batch_payloads = [json.loads(i["payload_json"]) for i in items]

                    try:
                        url = f"{target_url}/api/v1/ingest"
                        resp = await self.http_client.post(url, json=batch_payloads, headers=headers)

                        if resp.status_code in (200, 201):
                            for item, p_data in zip(items, batch_payloads):
                                self.storage.mark_payload_sent(item["payload_id"], item["raw_id"], p_data)
                            self.last_saas_status = "ONLINE"
                            self.consecutive_failures = 0
                        else:
                            # SaaS returned 4xx or 5xx
                            self.consecutive_failures += 1
                            self.last_saas_status = f"HTTP_{resp.status_code}"
                            for item in items:
                                retry_count = item["retry_count"]
                                backoff = min(15.0, 1.0 * (1.5 ** retry_count))
                                self.storage.mark_payload_failed(item["payload_id"], retry_count + 1, backoff)
                    except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as err:
                        self.consecutive_failures += 1
                        self.last_saas_status = "UNREACHABLE"
                        for item in items:
                            retry_count = item["retry_count"]
                            backoff = min(15.0, 1.0 * (1.5 ** retry_count))
                            self.storage.mark_payload_failed(item["payload_id"], retry_count + 1, backoff)
                        # Break out of loop early so we don't spam while network is down
                        break

                await asyncio.sleep(0.2)
            except Exception as e:
                logger.error(f"Error in sender loop: {e}")
                await asyncio.sleep(1.0)

    async def _heartbeat_loop(self):
        """Sends collector status beacon to Tier 2 SaaS every 10 seconds."""
        while self.running:
            try:
                # Do not send heartbeat if simulated outage or heartbeat pause is active
                if not self.adapter.is_saas_outage_active() and not getattr(self.adapter, "is_heartbeat_paused", lambda: False)():
                    cpu_use = psutil.cpu_percent(interval=None)
                    mem_use = psutil.virtual_memory().percent
                    stats = self.storage.get_buffer_stats()

                    for tenant_id, tenant_conf in self.tenants.items():
                        api_key = tenant_conf.get("api_key", "sec_key_default")
                        target_url, target_region, jurisdiction = self.get_tenant_endpoint(tenant_id)
                        tenant_stats = self.storage.get_tenant_buffer_stats(tenant_id)
                        heartbeat_payload = {
                            "collector_version": self.collector_version,
                            "tenant_id": tenant_id,
                            "region": target_region,
                            "jurisdiction": jurisdiction,
                            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "cpu_percent": cpu_use,
                            "memory_percent": mem_use,
                            "config_status": "VALID",
                            "pending_buffer_count": tenant_stats.get("pending_in_buffer", 0),
                            "sent_count": tenant_stats.get("total_sent_to_saas", 0),
                            "sent_payload_ids": self.storage.get_tenant_sent_payload_ids(tenant_id),
                            "pending_payload_ids": self.storage.get_tenant_pending_payload_ids(tenant_id),
                            "remediation_confirmations": list(self.pending_remediation_confirmations)
                        }

                        headers = {
                            "X-API-Key": api_key,
                            "X-Tenant-ID": tenant_id,
                            "X-Region-ID": target_region,
                            "X-Jurisdiction": jurisdiction,
                            "Content-Type": "application/json"
                        }

                        try:
                            url = f"{target_url}/api/v1/heartbeat"
                            resp = await self.http_client.post(url, json=heartbeat_payload, headers=headers)
                            if resp.status_code == 200:
                                self.pending_remediation_confirmations.clear()
                                resp_data = resp.json()
                                pending_actions = resp_data.get("pending_approved_actions", [])
                                for act in pending_actions:
                                    p_tenant = act.get("tenant_id") or tenant_id
                                    p_source = act.get("source_id")
                                    p_action = act.get("action")
                                    p_inc = act.get("incident_id")
                                    real_host = self.adapter.resolve_pseudonym_to_host(p_tenant, p_source)
                                    if real_host:
                                        self.adapter.clear_chaos_for_host(real_host, p_action)
                                        confirmed_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                                        self.pending_remediation_confirmations.append({
                                            "incident_id": p_inc,
                                            "tenant_id": p_tenant,
                                            "source_id": p_source,
                                            "action": p_action,
                                            "confirmed_at_utc": confirmed_time
                                        })
                                        logger.info(f"[REMEDIATION] Cleared chaos for {real_host} ({p_source}) after approved fix '{p_action}'")

                                # If confirmations were generated, send immediate follow-up confirmation
                                if self.pending_remediation_confirmations:
                                    conf_payload = dict(heartbeat_payload)
                                    conf_payload["remediation_confirmations"] = list(self.pending_remediation_confirmations)
                                    conf_payload["timestamp_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                                    try:
                                        c_resp = await self.http_client.post(url, json=conf_payload, headers=headers)
                                        if c_resp.status_code == 200:
                                            self.pending_remediation_confirmations.clear()
                                    except Exception:
                                        pass
                        except Exception:
                            # Heartbeat failures are tracked on the SaaS side via 60s timeout
                            pass

                await asyncio.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.error(f"Heartbeat loop error: {e}")
                await asyncio.sleep(self.heartbeat_interval)

    async def _retention_prune_loop(self):
        """Enforces 1-hour raw data retention limit."""
        while self.running:
            try:
                retention_seconds = self.raw_retention_minutes * 60.0
                pruned = self.storage.prune_expired_raw_records(retention_seconds)
                if pruned > 0:
                    logger.info(f"Retention pruner purged {pruned} raw records older than {self.raw_retention_minutes}m")
                await asyncio.sleep(60.0)
            except Exception as e:
                logger.error(f"Retention loop error: {e}")
                await asyncio.sleep(60.0)
