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


def get_kv_secret(name: str) -> str:
    """Fetch a secret directly from Key Vault, skipping env fallback.

    Used for customer-scoped secrets (e.g. per-customer Sentinel client secrets) that
    have no env equivalent and live in KV under explicit kebab-case names.
    Returns "" if not found, KV unconfigured, or the SDK is unavailable.
    """
    if not _AZURE_KEYVAULT_URL:
        return ""
    cache_key = f"__kv__{name}"
    if cache_key in _cache:
        return _cache[cache_key]
    value = _fetch_from_keyvault(name) or ""
    _cache[cache_key] = value
    return value


def set_kv_secret(name: str, value: str) -> None:
    """Write a secret to Key Vault under the given name.

    Used by admin handlers when an operator enters a fresh customer credential.
    Raises if KV is not configured or the write fails — callers should handle.
    The in-process cache is invalidated for this name so subsequent reads see the new value.
    """
    if not _AZURE_KEYVAULT_URL:
        raise RuntimeError(
            "AZURE_KEYVAULT_URL is not set — cannot write secret to Key Vault."
        )
    client = _get_kv_client()
    if client is None:
        raise RuntimeError(
            "Key Vault client unavailable (azure-identity / azure-keyvault-secrets not installed)."
        )
    client.set_secret(name, value)
    _cache.pop(f"__kv__{name}", None)
    _cache.pop(name, None)
