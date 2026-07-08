"""
Azure AI model pricing (2026-07-08) — live from the Azure Retail Prices API.

Powers the Stats page "Model Pricing" table. Fetches current per-token prices for
a curated set of Azure OpenAI models directly from Microsoft's public Retail
Prices API (https://prices.azure.com/api/retail/prices — no auth), so the page
stays in sync with the latest published pricing.

Design:
- Prices are LIVE (fetched from the API); the model list + how to locate each
  model's meter is CURATED here (the API's meter names are version-dated and
  inconsistent, so we match on stable tokens rather than exact strings, and
  prefer Global > Data-Zone > Regional deployment pricing).
- Cached in-memory with a TTL (AZURE_PRICING_TTL_HOURS, default 12h). On a fetch
  failure we return the last good snapshot (marked stale) so a transient API
  outage never blanks the page. First-ever failure returns None → the section
  is simply omitted.
- USD, per 1,000,000 tokens (the API returns per-1K; we normalise to per-1M).
- Never raises.
"""
from __future__ import annotations

import logging
import threading
import time

import httpx

logger = logging.getLogger(__name__)

_API = "https://prices.azure.com/api/retail/prices"
_CURRENCY = "USD"

# Products we pull once each and then extract models from.
_PRODUCTS = ["Azure OpenAI", "Azure OpenAI Reasoning", "Azure OpenAI Embedding"]

# Deployment-tier preference (Global cheapest/most common → Data Zone → Regional).
_TIER_TOKENS = [("glbl", "Global"), ("dz", "Data Zone"), ("regnl", "Regional")]

# Tokens that mark a NON-standard variant we never want for the base price.
_EXCLUDE_COMMON = ("cached", "cchd", "batch", "ft ", " ft", "-ft", "audio",
                   "trscb", "tts", "rt-", "realtime", "grdr", "deep research")

# Curated model catalogue. Each: label, product, include-tokens (all must be in
# the meter name), extra excludes, embedding? (input-only), and the deployment
# id-prefix that marks it as "in use" by this platform.
_MODELS = [
    {"label": "gpt-4.1",        "product": "Azure OpenAI",           "inc": ["gpt 4.1"],       "exc": ["mini", "nano"], "embed": False},
    {"label": "gpt-4.1-mini",   "product": "Azure OpenAI",           "inc": ["gpt 4.1 mini"],  "exc": ["nano"],         "embed": False},
    {"label": "gpt-4o",         "product": "Azure OpenAI",           "inc": ["gpt 4o"],        "exc": ["mini", "4.1"],  "embed": False},
    {"label": "gpt-4o-mini",    "product": "Azure OpenAI",           "inc": ["gpt4omini", "txt"], "exc": [],            "embed": False},
    {"label": "o4-mini",        "product": "Azure OpenAI Reasoning", "inc": ["o4-mini"],       "exc": [],               "embed": False},
    {"label": "text-embedding-3-large", "product": "Azure OpenAI Embedding", "inc": ["text embedding 3 large"], "exc": [], "embed": True},
    {"label": "text-embedding-3-small", "product": "Azure OpenAI Embedding", "inc": ["text embedding 3 small"], "exc": [], "embed": True},
]

_TTL_SECONDS = None  # resolved lazily from env
_cache: dict = {"ts": 0.0, "snapshot": None}
_lock = threading.Lock()


def _ttl_seconds() -> float:
    import os
    try:
        return float(os.environ.get("AZURE_PRICING_TTL_HOURS", "12")) * 3600.0
    except (TypeError, ValueError):
        return 12 * 3600.0


def _fetch_product(product: str) -> list[dict]:
    """All USD price items for one product (paged). Returns [] on failure."""
    items: list[dict] = []
    url = _API
    # serviceName is 'Foundry Models' for Azure OpenAI; priceType is unset on
    # these meters, so we filter only on product (currency defaults to USD).
    params = {"$filter": f"serviceName eq 'Foundry Models' and productName eq '{product}'"}
    # Follow NextPageLink up to a sane bound.
    for _ in range(10):
        r = httpx.get(url, params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        items.extend(data.get("Items", []))
        nxt = data.get("NextPageLink")
        if not nxt:
            break
        url, params = nxt, None  # NextPageLink already carries the query
    return items


def _to_per_million(unit_price: float, unit_of_measure: str) -> float | None:
    """Normalise a per-1K or per-1M token price to per-1,000,000 tokens."""
    uom = (unit_of_measure or "").lower()
    if "1m" in uom:
        return round(unit_price, 4)
    if "1k" in uom:
        return round(unit_price * 1000.0, 4)
    return None


def _pick(items: list[dict], spec: dict, want: str | None) -> float | None:
    """Pick the base per-1M price for one model + direction ('inp'/'outp', or
    None for embeddings which have a single undirected token meter).
    Prefers Global > Data Zone > Regional; within a tier takes the lowest price
    (the standard SKU, not a premium variant). Returns None if not found."""
    inc = [t.lower() for t in spec["inc"]]
    exc = [t.lower() for t in spec["exc"]] + list(_EXCLUDE_COMMON)
    for tier_tok, _label in _TIER_TOKENS:
        best = None
        for it in items:
            mn = (it.get("meterName") or "").lower()
            if not all(t in mn for t in inc):
                continue
            if any(t in mn for t in exc):
                continue
            if want and want not in mn:
                continue
            if tier_tok not in mn:
                continue
            per_m = _to_per_million(it.get("unitPrice", 0), it.get("unitOfMeasure", ""))
            if per_m is None:
                continue
            if best is None or per_m < best:
                best = per_m
        if best is not None:
            return best
    return None


def _in_use_labels() -> set[str]:
    """Which catalogue labels this platform actually deploys (chat + embedding)."""
    import os
    labels = set()
    chat = (os.environ.get("AZURE_OPENAI_DEPLOYMENT", "") or os.environ.get("OPENAI_MODEL", "")).strip().lower()
    embed = os.environ.get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "").strip().lower()
    for m in _MODELS:
        lab = m["label"].lower()
        if chat and (chat == lab or chat.startswith(lab)):
            labels.add(m["label"])
        if embed and (embed == lab or lab in embed):
            labels.add(m["label"])
    return labels


def _build_snapshot() -> dict | None:
    by_product: dict[str, list[dict]] = {}
    for p in _PRODUCTS:
        by_product[p] = _fetch_product(p)
    if not any(by_product.values()):
        return None

    in_use = _in_use_labels()
    rows = []
    for m in _MODELS:
        items = by_product.get(m["product"], [])
        inp = _pick(items, m, None if m["embed"] else "inp")
        outp = None if m["embed"] else _pick(items, m, "outp")
        if inp is None and outp is None:
            continue  # couldn't locate this model's meter — omit rather than lie
        rows.append({
            "label": m["label"],
            "input_1m": inp,
            "output_1m": outp,
            "embed": m["embed"],
            "in_use": m["label"] in in_use,
        })
    if not rows:
        return None
    now = time.time()
    return {
        "models": rows,
        "currency": _CURRENCY,
        "unit": "per 1M tokens",
        "deployment": "Global (falls back to Data Zone / Regional)",
        "source": "Azure Retail Prices API",
        "synced_epoch": now,
        # Container runs UTC; SOC team reads SGT (UTC+8).
        "synced_at": time.strftime("%Y-%m-%d %H:%M", time.gmtime(now + 8 * 3600)) + " SGT",
        "stale": False,
    }


def get_model_pricing() -> dict | None:
    """Cached Azure model pricing snapshot, refreshed at most every TTL. Returns
    the last good snapshot (marked stale) if a refresh fails; None if never
    fetched successfully. Never raises."""
    now = time.time()
    with _lock:
        snap = _cache["snapshot"]
        if snap and (now - _cache["ts"]) < _ttl_seconds():
            return snap

    try:
        fresh = _build_snapshot()
    except Exception as e:  # noqa: BLE001 — page must never break on pricing
        logger.warning("azure_pricing: fetch failed (%s): %s", type(e).__name__, e)
        fresh = None

    with _lock:
        if fresh:
            _cache["snapshot"] = fresh
            _cache["ts"] = now
            return fresh
        # Fetch failed — serve last good snapshot, flagged stale.
        if _cache["snapshot"]:
            stale = dict(_cache["snapshot"])
            stale["stale"] = True
            return stale
        return None
