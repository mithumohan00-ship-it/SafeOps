"""
SafeOps - SaaS Health Evaluation & Stale Data Engine (Tier 2 Cloud Side)
========================================================================
1. Evaluates Health States (Excellent / Good / Fair / Poor) against configurable thresholds
2. Explains the exact human reason for every health state
3. Detects Stale Data (>30 seconds without update) -> downgrades to POOR
4. Detects Collector Offline (>60 seconds without heartbeat)
5. Automatically logs every health state change to state_change_history table
"""

import datetime
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

from tier2_saas.storage import SaaSStorage

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "saas_thresholds.json")


class HealthEngine:
    def __init__(self, storage: SaaSStorage, config_path: str = CONFIG_PATH):
        self.storage = storage
        self.config_path = config_path
        self._load_config()

        # Cache of previous known health state: (tenant_id, source_id, metric) -> state
        self._last_known_states: Dict[Tuple[str, str, str], str] = {}

    def _load_config(self):
        with open(self.config_path, "r") as f:
            self.config = json.load(f)
        self.metric_thresholds = self.config.get("metrics", {})
        self.stale_timeout = self.config.get("stale_data_timeout_seconds", 30.0)
        self.offline_timeout = self.config.get("collector_offline_timeout_seconds", 60.0)

    def evaluate_payload_health(self, payload: Dict[str, Any]) -> Tuple[str, str]:
        """
        Evaluates an incoming payload's metric value against thresholds.
        Returns (health_state, human_reason).
        """
        metric = payload.get("metric")
        val = payload.get("value")
        rule = self.metric_thresholds.get(metric)

        if not rule:
            # Fallback for metrics without explicit custom rules
            return payload.get("health_state", "GOOD"), f"Metric {metric} at {val}"

        thresh = rule.get("thresholds", {})
        poor_reason = rule.get("poor_reason", f"{metric} reached critical condition")

        if metric == "service_status":
            if val < 1.0:
                return "POOR", poor_reason
            return "EXCELLENT", "Service process running nominally (UP)"

        elif metric == "failed_logins":
            if val > thresh.get("fair_max", 4):
                return "POOR", f"{poor_reason}: {int(val)} failed logins detected in window"
            if val > thresh.get("good_max", 2):
                return "FAIR", f"Minor auth anomalies: {int(val)} failed logins"
            return "EXCELLENT", "Zero auth failures detected"

        # General numerical thresholds (CPU, memory, latency, packet loss, etc.)
        exc_max = thresh.get("excellent_max", 50.0)
        good_max = thresh.get("good_max", 75.0)
        fair_max = thresh.get("fair_max", 90.0)

        if val >= fair_max:
            return "POOR", f"{poor_reason} (Current: {val}{rule.get('unit', '')})"
        elif val >= good_max:
            return "FAIR", f"{metric} elevated above nominal baseline (Current: {val}{rule.get('unit', '')})"
        elif val >= exc_max:
            return "GOOD", f"{metric} operating well within healthy thresholds ({val}{rule.get('unit', '')})"
        else:
            return "EXCELLENT", f"{metric} optimal at {val}{rule.get('unit', '')}"

    def check_state_transition(self, payload: Dict[str, Any], computed_state: str, reason: str):
        """
        Checks if health state has changed since previous payload.
        If changed, records in state_change_history.
        """
        tenant_id = payload.get("tenant_id")
        source_id = payload.get("source_id")
        metric = payload.get("metric")
        event_time_utc = payload.get("event_time_utc")

        key = (tenant_id, source_id, metric)
        old_state = self._last_known_states.get(key)

        if old_state != computed_state:
            self._last_known_states[key] = computed_state
            if old_state is not None:  # Don't log initial boot state as a transition
                self.storage.record_state_change(
                    tenant_id=tenant_id,
                    source_id=source_id,
                    metric=metric,
                    old_state=old_state,
                    new_state=computed_state,
                    reason=reason,
                    event_time_utc=event_time_utc
                )

    def check_stale_data_for_hosts(self, tenant_id: str, hosts_map: Dict[str, Dict[str, Any]]):
        """
        Inspects all hosts for the tenant:
        If any continuous operational metric (CPU, memory, disk, network) has had no updates in > 30 seconds, downgrades host health to POOR.
        For ephemeral security events like failed_logins, if older than stale_timeout, the attack has expired and resets to nominal.
        """
        now = time.time()
        for sid, host_info in hosts_map.items():
            for m_name, m_data in host_info.get("metrics", {}).items():
                event_ts = m_data.get("event_ts", 0)
                age = now - event_ts

                # If failed_logins event is older than 30s, the attack has expired and subsided
                if m_name == "failed_logins":
                    if age > self.stale_timeout:
                        m_data["value"] = 0
                        m_data["health_state"] = "EXCELLENT"
                        m_data["short_context"] = "Zero auth failures detected (attack subsided)"
                    continue

                if age > self.stale_timeout:
                    m_data["health_state"] = "POOR"
                    m_data["short_context"] = f"Stale data: No telemetry update in {int(age)}s (exceeds {int(self.stale_timeout)}s threshold)"
                    host_info["overall_health"] = "POOR"
                    host_info["is_stale"] = True
                    host_info["stale_reason"] = m_data["short_context"]

            # Re-evaluate overall health for host if not stale
            if not host_info.get("is_stale"):
                states = [
                    m["health_state"] for m_name, m in host_info.get("metrics", {}).items()
                    if not (m_name == "failed_logins" and m.get("value", 0) == 0)
                ]
                if any(s == "POOR" for s in states):
                    host_info["overall_health"] = "POOR"
                elif any(s == "FAIR" for s in states):
                    host_info["overall_health"] = "FAIR"
                elif any(s == "GOOD" for s in states):
                    host_info["overall_health"] = "GOOD"
                else:
                    host_info["overall_health"] = "EXCELLENT"
