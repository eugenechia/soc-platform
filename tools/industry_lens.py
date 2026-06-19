"""
Industry-aware recommendation lens (2026-06-19).

A small, CURATED, version-controlled map of customer industry → the triage
posture an L2 analyst in that vertical actually cares about. Phase 6
recommendation synthesis blends this lens with the per-ticket evidence so the
"RECOMMENDED ACTION" line reads like it was written by an analyst who knows the
customer's world.

Why curated (not LLM-invented): letting the model freelance on "what does
Finance care about" risks hallucinated compliance obligations and inconsistent
tone. This table is auditable and tunable by SOC leads — edit the facets here,
redeploy, done. The LLM only WEIGHTS the evidence through the lens; it never
sources industry facts from its own memory.

Facets per industry:
  - priorities:          what to treat as high-stakes for this vertical
  - compliance:          regulatory framing to mention when relevant
  - fp_patterns:         benign-by-default patterns common to the vertical
  - escalation_posture:  default lean (escalate-fast vs de-escalate-noise)

`get_industry_lens()` returns a compact text block for the prompt. Unknown /
empty industry → DEFAULT_LENS (safe, vertical-agnostic).
"""
from __future__ import annotations

# Controlled vocabulary. Keys are the stored `industry` values; labels drive the
# admin dropdown. Keep keys stable (they're persisted on the customer record).
INDUSTRY_LABELS: dict[str, str] = {
    "finance":         "Finance / Banking / Insurance",
    "academia":        "Academia / Education / Research",
    "healthcare":      "Healthcare / Life Sciences",
    "government":      "Government / Public Sector",
    "retail":          "Retail / E-commerce",
    "manufacturing":   "Manufacturing / Industrial / OT",
    "technology":      "Technology / IT / SaaS",
    "energy_utilities": "Energy / Utilities",
}

INDUSTRY_LENS: dict[str, dict[str, str]] = {
    "finance": {
        "priorities": "Data exfiltration, account takeover, payment/fraud paths, and access to systems holding cardholder or PII data are top-stakes.",
        "compliance": "PCI-DSS and financial-data regulations apply; treat suspected cardholder-data exposure as escalation-worthy.",
        "fp_patterns": "Scheduled batch transfers, market-data feeds, and known SWIFT/payment-gateway endpoints are routinely benign.",
        "escalation_posture": "Low tolerance for 'monitor and close' on anything touching payment or customer-data systems — escalate when in doubt.",
    },
    "academia": {
        "priorities": "Research-data theft, compromised student/staff credentials, and lateral movement into administrative or grading systems.",
        "compliance": "Student-record privacy (e.g. FERPA-equivalent) applies; research IP may be export-controlled.",
        "fp_patterns": "Open campus networks generate heavy benign scanning, P2P, Tor, and unusual geo logins from international students/visiting researchers.",
        "escalation_posture": "De-escalate recon/scan noise UNLESS it touches a crown-jewel research or administrative asset; then escalate.",
    },
    "healthcare": {
        "priorities": "PHI exposure, ransomware against clinical systems, and access to EMR/medical-device networks.",
        "compliance": "HIPAA-equivalent PHI rules apply; suspected PHI access or exfiltration is escalation-worthy.",
        "fp_patterns": "Medical-device and HL7/DICOM traffic looks anomalous but is often legitimate; legacy OS on clinical gear is expected.",
        "escalation_posture": "Escalate fast on anything touching clinical availability or PHI — patient safety outweighs noise reduction.",
    },
    "government": {
        "priorities": "Nation-state TTPs, access to citizen data, and compromise of public-facing services.",
        "compliance": "Government data-classification and sovereignty rules apply; classified/citizen-data exposure is escalation-worthy.",
        "fp_patterns": "Heavy automated scanning of public services is constant background; sanctioned pen-tests may be in scope.",
        "escalation_posture": "Escalate on credible nation-state indicators or citizen-data access; otherwise contextualise against expected scanning.",
    },
    "retail": {
        "priorities": "POS/payment compromise, e-commerce account takeover, and customer-PII/cardholder-data access.",
        "compliance": "PCI-DSS applies to POS and e-commerce paths; cardholder-data exposure is escalation-worthy.",
        "fp_patterns": "Seasonal traffic spikes, bot/scraper activity, and third-party marketing/CDN callbacks are routinely benign.",
        "escalation_posture": "Escalate on POS or payment-path indicators; de-escalate generic web bot noise unless it hits checkout.",
    },
    "manufacturing": {
        "priorities": "OT/ICS access, production-line availability, and IP/design-data theft; IT→OT pivot is the worst case.",
        "compliance": "Safety-critical OT availability and IP protection drive decisions more than data-privacy regimes.",
        "fp_patterns": "Industrial protocols (Modbus, OPC-UA) and legacy/unpatched OT hosts are expected and not inherently malicious.",
        "escalation_posture": "Escalate hard on any IT→OT lateral movement or production-system impact; safety/availability outweigh noise.",
    },
    "technology": {
        "priorities": "Source-code/secret theft, CI/CD and cloud-control-plane compromise, and supply-chain tampering.",
        "compliance": "Customer-data handling and SOC 2-style obligations apply; secret/source exposure is escalation-worthy.",
        "fp_patterns": "Developer tooling, automated builds, container churn, and broad cloud-API activity are routinely benign.",
        "escalation_posture": "Escalate on CI/CD, secret, or cloud-control-plane indicators; de-escalate routine dev/build noise.",
    },
    "energy_utilities": {
        "priorities": "OT/SCADA access, grid/operational availability, and safety-critical control systems.",
        "compliance": "Critical-infrastructure protection (NERC-CIP-style) and safety regulation apply.",
        "fp_patterns": "SCADA/ICS protocols and long-lived legacy controllers are expected; remote-engineering access may be sanctioned.",
        "escalation_posture": "Escalate hard on any control-system or safety impact; availability and safety dominate.",
    },
}

DEFAULT_LENS: dict[str, str] = {
    "priorities": "Credential theft, lateral movement, data exfiltration, and access to business-critical systems.",
    "compliance": "Apply general data-protection prudence; flag suspected sensitive-data exposure.",
    "fp_patterns": "Known scanners, automated jobs, and documented integrations are routinely benign.",
    "escalation_posture": "Escalate when evidence points to confirmed compromise or critical-asset impact; otherwise contextualise.",
}


# Map free-text / legacy dropdown labels to canonical lens keys. Lets older
# customer records (which stored display strings like "Financial Services")
# and minor wording variants resolve to the right lens. "enterprise" and other
# vague values intentionally map to "" → DEFAULT_LENS.
_INDUSTRY_ALIASES: dict[str, str] = {
    "financial services": "finance", "banking": "finance", "insurance": "finance", "fintech": "finance",
    "information technology": "technology", "it": "technology", "tech": "technology", "saas": "technology", "software": "technology",
    "education": "academia", "university": "academia", "research": "academia", "higher education": "academia",
    "health": "healthcare", "life sciences": "healthcare", "medical": "healthcare", "pharma": "healthcare",
    "public sector": "government", "govt": "government", "federal": "government",
    "e-commerce": "retail", "ecommerce": "retail", "commerce": "retail",
    "industrial": "manufacturing", "ot": "manufacturing", "ics": "manufacturing",
    "energy": "energy_utilities", "utilities": "energy_utilities", "power": "energy_utilities",
}


def normalize_industry(value: str | None) -> str:
    """Resolve an industry value (canonical key, legacy label, or variant) to a
    known lens key, or '' if unrecognised (→ DEFAULT_LENS)."""
    key = (value or "").strip().lower()
    if key in INDUSTRY_LENS:
        return key
    return _INDUSTRY_ALIASES.get(key, "")


def get_industry_lens(industry: str | None) -> str:
    """Return a compact, prompt-ready lens block for the given industry.

    Falls back to the vertical-agnostic DEFAULT_LENS for unknown/empty input,
    so the caller never has to branch on whether an industry was set.
    """
    key = normalize_industry(industry)
    lens = INDUSTRY_LENS.get(key, DEFAULT_LENS)
    label = INDUSTRY_LABELS.get(key, "General / unspecified")
    return (
        f"Industry: {label}\n"
        f"- Priorities: {lens['priorities']}\n"
        f"- Compliance framing: {lens['compliance']}\n"
        f"- Common false positives: {lens['fp_patterns']}\n"
        f"- Default escalation posture: {lens['escalation_posture']}"
    )
