"""
SafeOps - SaaS Authentication & Tenant Validation (Tier 2 Cloud Side)
=====================================================================
Validates per-collector API keys and enforces tenant isolation.
Note: Production environments would mandate mutual TLS (mTLS) with client certificates.
"""

from typing import Dict, Optional
from fastapi import Header, HTTPException, Security, status

# Configured API keys per tenant collector
VALID_TENANT_API_KEYS: Dict[str, str] = {
    "tenant-a": "sec_key_tenant_a_998811",
    "tenant-b": "sec_key_tenant_b_443322",
}

# Reverse lookup: api_key -> tenant_id
KEY_TO_TENANT: Dict[str, str] = {v: k for k, v in VALID_TENANT_API_KEYS.items()}


def verify_collector_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID")
) -> str:
    """
    Validates API key from collector request headers.
    Ensures key exists and matches the claimed tenant.
    Returns the authenticated tenant_id.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required 'X-API-Key' authentication header"
        )

    authorized_tenant = KEY_TO_TENANT.get(x_api_key)
    if not authorized_tenant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked collector API key"
        )

    if x_tenant_id and x_tenant_id != authorized_tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key is not authorized for claimed tenant '{x_tenant_id}'"
        )

    return authorized_tenant
