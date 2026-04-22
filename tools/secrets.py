"""
Secret resolution — env vars in dev, Key Vault in Azure.

The rule for the rest of the codebase: NEVER read os.environ for a credential.
Call get_secret(name) instead. This module decides where the value comes from.

Resolution order:
  1. os.environ[name]                                 (always wins — supports dev & CI)
  2. Azure Key Vault                                  (when AZURE_KEYVAULT_URL is set)
  3. return "" (empty string, never None)             (callers handle absence)

Key Vault lookups are memoised in-process. A container restart re-fetches everything,
which is what we want — rotated secrets take effect within one restart.
"""
import os
import logging
from typing import Optional

log = logging.getLogger(__name__)

_AZURE_KEYVAULT_URL = os.environ.get("AZURE_KEYVAULT_URL", "").strip()

_cache: dict[str, str] = {}
_kv_client = None


def _get_kv_client():
    """Lazily initialise the Key Vault client. Only called when AZURE_KEYVAULT_URL is set."""
    global _kv_client
    if _kv_client is not None:
        return _kv_client
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError:
        log.warning("azure-identity / azure-keyvault-secrets not installed — Key Vault disabled.")
        return None

    _kv_client = SecretClient(
        vault_url=_AZURE_KEYVAULT_URL,
        credential=DefaultAzureCredential(),
    )
    return _kv_client


def _fetch_from_keyvault(name: str) -> Optional[str]:
    """Fetch a secret from Key Vault. Returns None if not found or on any error."""
    client = _get_kv_client()
    if client is None:
        return None
    # Key Vault secret names are kebab-case by convention; env names are SNAKE_CASE
    kv_name = name.lower().replace("_", "-")
    try:
        return client.get_secret(kv_name).value
    except Exception as e:
        log.debug("Key Vault lookup failed for %s (%s): %s", name, kv_name, e)
        return None


def get_secret(name: str) -> str:
    """Resolve a secret by logical name. Returns empty string if not found."""
    if name in _cache:
        return _cache[name]

    # 1. Environment wins (dev, CI, local docker-compose)
    env_value = os.environ.get(name, "").strip()
    if env_value:
        _cache[name] = env_value
        return env_value

    # 2. Key Vault (Azure-hosted prod)
    if _AZURE_KEYVAULT_URL:
        kv_value = _fetch_from_keyvault(name)
        if kv_value:
            _cache[name] = kv_value
            return kv_value

    # 3. Not found
    log.warning("Secret %s not found in env or Key Vault — returning empty string", name)
    _cache[name] = ""
    return ""


def clear_cache() -> None:
    """Force re-read of all secrets. Used by admin 'reload config' actions if you add them."""
    _cache.clear()
