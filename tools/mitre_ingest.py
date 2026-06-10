"""
One-time CLI script: download MITRE ATT&CK Enterprise STIX bundle and produce
a compact index at data/mitre_attack_index.json.

Usage:
    python3 tools/mitre_ingest.py

Run locally whenever MITRE publishes a new ATT&CK version, then commit the
updated index and rebuild the Docker image. The index is baked into the image
and loaded at runtime by tools/mitre_mapper.py.

No new pip dependencies — stdlib only (urllib.request + json).
httpx is used at runtime by the app but is not required here; urllib avoids
any venv-activation requirement when running this script standalone.
"""
import json
import logging
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUTPUT_PATH = Path(__file__).parent.parent / "data" / "mitre_attack_index.json"

# ATT&CK kill-chain name used to identify tactic phase entries.
_KILL_CHAIN_NAME = "mitre-attack"

# Map ATT&CK phase slugs to human-readable tactic names.
_TACTIC_NAMES = {
    "reconnaissance":          "Reconnaissance",
    "resource-development":    "Resource Development",
    "initial-access":          "Initial Access",
    "execution":               "Execution",
    "persistence":             "Persistence",
    "privilege-escalation":    "Privilege Escalation",
    "defense-evasion":         "Defense Evasion",
    "credential-access":       "Credential Access",
    "discovery":               "Discovery",
    "lateral-movement":        "Lateral Movement",
    "collection":              "Collection",
    "command-and-control":     "Command and Control",
    "exfiltration":            "Exfiltration",
    "impact":                  "Impact",
}


def _extract_technique_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            eid = ref.get("external_id", "")
            if eid.startswith("T"):
                return eid
    return None


def _extract_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def _extract_tactic(obj: dict) -> tuple[str, str]:
    """Return (tactic_id, tactic_name) for the first matching phase, or ('', '')."""
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == _KILL_CHAIN_NAME:
            slug = phase.get("phase_name", "")
            return slug, _TACTIC_NAMES.get(slug, slug.replace("-", " ").title())
    return "", ""


def _extract_version(bundle: dict) -> str:
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version", "unknown")
    return "unknown"


def ingest(stix_url: str = STIX_URL, output_path: Path = OUTPUT_PATH) -> None:
    logger.info("Downloading ATT&CK STIX bundle from %s", stix_url)
    logger.info("(This is ~50 MB — may take 30-60s depending on connection)")

    req = urllib.request.Request(stix_url, headers={"User-Agent": "mitre_ingest/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read()

    logger.info("Downloaded %.1f MB", len(raw) / 1_048_576)

    bundle = json.loads(raw)
    version = _extract_version(bundle)
    logger.info("ATT&CK version: %s", version)

    techniques = []
    skipped_revoked = 0
    skipped_no_id = 0

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            skipped_revoked += 1
            continue

        tech_id = _extract_technique_id(obj)
        if not tech_id:
            skipped_no_id += 1
            continue

        tactic_id, tactic_name = _extract_tactic(obj)
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        parent_id = tech_id.split(".")[0] if is_sub and "." in tech_id else None

        desc = obj.get("description", "")
        if len(desc) > 300:
            desc = desc[:297] + "..."

        techniques.append({
            "id":             tech_id,
            "name":           obj.get("name", ""),
            "tactic":         tactic_name,
            "tactic_id":      tactic_id,
            "is_subtechnique": is_sub,
            "parent_id":      parent_id,
            "description":    desc,
            "url":            _extract_url(obj),
        })

    techniques.sort(key=lambda t: t["id"])

    index = {
        "version":   version,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "count":     len(techniques),
        "techniques": techniques,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(index, indent=2, ensure_ascii=False))

    logger.info(
        "Wrote %d techniques to %s (skipped %d revoked, %d no-id)",
        len(techniques), output_path, skipped_revoked, skipped_no_id,
    )


if __name__ == "__main__":
    try:
        ingest()
    except Exception as exc:
        logger.error("Ingest failed: %s", exc)
        sys.exit(1)
