"""Extract advisory rows from uploaded files.

The team receives vulnerability advisories in mixed formats — forwarded
Outlook emails (.msg), raw emails (.eml), vendor PDFs (.pdf), Word docs
(.docx), and plain text. Manually retyping each into the advisories page
is slow and error-prone, so this module provides:

  1. Format-aware text extraction (`extract_text`) that returns a single
     string regardless of input format.
  2. AI-assisted structured extraction (`extract_advisories_with_ai`) that
     turns the raw text into draft rows in the threat_analytics_advisories
     schema — the analyst reviews and edits before saving.

The same LLM client used for report generation is reused here. No
extra credentials, no extra wiring.
"""
import asyncio
import json
import logging
import os
import re
from email import message_from_bytes
from email.policy import default as _email_policy

logger = logging.getLogger(__name__)


# Supported extensions. Keys are lowercase, no leading dot. Values are
# human labels used in error messages.
SUPPORTED_EXTENSIONS = {
    "msg": "Outlook email",
    "eml": "Email (.eml)",
    "pdf": "PDF",
    "docx": "Word document",
    "txt": "Plain text",
    "html": "HTML",
    "htm": "HTML",
    "md": "Markdown",
}


def _extension(filename: str) -> str:
    return (filename or "").rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""


def is_supported(filename: str) -> bool:
    return _extension(filename) in SUPPORTED_EXTENSIONS


# ── Per-format extractors ────────────────────────────────────────────────────


def _extract_msg(data: bytes) -> str:
    """Extract subject + body from an Outlook .msg file. Uses extract-msg,
    which parses the Compound File Binary Format MS Outlook serialises to.

    Attachments are NOT recursed into — most CVE advisories carry the
    relevant info in the body. If a future case shows otherwise we can
    walk msg.attachments and dispatch each by its filename extension.
    """
    import extract_msg
    import tempfile
    # extract-msg only accepts a file path, not bytes. Write to a temp file.
    with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as f:
        f.write(data)
        tmp_path = f.name
    try:
        msg = extract_msg.Message(tmp_path)
        parts = []
        if msg.subject:
            parts.append(f"Subject: {msg.subject}")
        if msg.sender:
            parts.append(f"From: {msg.sender}")
        if msg.date:
            parts.append(f"Date: {msg.date}")
        if msg.body:
            parts.append("")
            parts.append(msg.body)
        return "\n".join(parts)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _extract_eml(data: bytes) -> str:
    """Extract subject + plain-text body from a .eml MIME email."""
    msg = message_from_bytes(data, policy=_email_policy)
    parts = []
    if msg["Subject"]:
        parts.append(f"Subject: {msg['Subject']}")
    if msg["From"]:
        parts.append(f"From: {msg['From']}")
    if msg["Date"]:
        parts.append(f"Date: {msg['Date']}")
    parts.append("")

    # Prefer text/plain; fall back to text/html stripped of tags.
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and not body_text:
                try:
                    body_text = part.get_content()
                except (LookupError, KeyError):
                    body_text = part.get_payload(decode=True).decode("utf-8", errors="ignore")
        if not body_text:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    html = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    body_text = _strip_html(html)
                    break
    else:
        try:
            body_text = msg.get_content()
        except (LookupError, KeyError):
            body_text = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
    parts.append(body_text)
    return "\n".join(parts)


def _strip_html(html: str) -> str:
    """Lightweight HTML → text. Avoids pulling in BeautifulSoup just for this."""
    text = re.sub(r"<style[\s\S]*?</style>", "", html, flags=re.IGNORECASE)
    text = re.sub(r"<script[\s\S]*?</script>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    # Decode common entities; full table not needed for advisory text.
    text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_pdf(data: bytes) -> str:
    from pypdf import PdfReader
    from io import BytesIO
    reader = PdfReader(BytesIO(data))
    pages = []
    for i, page in enumerate(reader.pages):
        try:
            pages.append(page.extract_text() or "")
        except Exception as exc:
            logger.warning("PDF page %d extraction failed: %s", i + 1, exc)
    return "\n".join(pages).strip()


def _extract_docx(data: bytes) -> str:
    from docx import Document
    from io import BytesIO
    doc = Document(BytesIO(data))
    return "\n".join(p.text for p in doc.paragraphs if p.text.strip())


def _extract_text_like(data: bytes, ext: str) -> str:
    text = data.decode("utf-8", errors="ignore")
    if ext in ("html", "htm"):
        return _strip_html(text)
    return text.strip()


def extract_text(data: bytes, filename: str) -> str:
    """Dispatch to the right extractor by filename extension. Returns the
    raw text; caller passes it to the AI extractor."""
    ext = _extension(filename)
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file extension: .{ext}")
    if ext == "msg":
        return _extract_msg(data)
    if ext == "eml":
        return _extract_eml(data)
    if ext == "pdf":
        return _extract_pdf(data)
    if ext == "docx":
        return _extract_docx(data)
    return _extract_text_like(data, ext)


# ── AI structured extraction ─────────────────────────────────────────────────


_AI_SYSTEM_PROMPT = """You are a security analyst extracting cybersecurity vulnerability advisories from raw text (an email, PDF, or document).

Each advisory is typically a CVE identifier paired with a product name, sometimes a vendor name, CVSS score, exploit status, or patch availability. The input may contain multiple advisories or none.

Return a JSON array. Each element is an object with these keys (all strings):
- "threat": canonical advisory title. Strongly prefer the format "CVE-YYYY-NNNNN - Product Name" (e.g. "CVE-2025-54948 - Trend Micro Apex One"). If multiple products are affected by one CVE, name the most prominent or use "CVE-YYYY-NNNNN - Multiple Products". If no CVE ID is present but a clear vulnerability is described, use a descriptive name like "Microsoft Defender Tampering Vulnerability".
- "report_type": "Vulnerability" for CVE-based advisories. Use "Threat Actor" only when the source is clearly about a threat actor group not tied to a specific CVE. Use "Tool" or "Activity Group" only when the source explicitly uses those Defender XDR categories.
- "published": ISO date string (YYYY-MM-DD). Use the publication / advisory date if explicit; otherwise the date of the email or the discovery date. If no date is findable, use an empty string "".
- "hunting_result": always an empty string "" — the analyst fills this in after running the hunt.

Return JUST the JSON array — no prose, no markdown fences, no commentary. If no advisories are found, return [].

Cap output at 25 advisories to avoid runaway. If the source clearly lists more, return the 25 most critical or most recent."""


async def _ai_extract_async(text: str) -> list[dict]:
    from tools.llm_client import make_chat_client
    client, model = make_chat_client()
    # Cap input to ~15k chars (~3500 tokens) so we stay well under context
    # limits for any provider. CVE advisories are short — if the source is
    # huge it's almost certainly a digest of many; truncating still finds
    # the front-most entries.
    truncated = text[:15000]
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _AI_SYSTEM_PROMPT},
            {"role": "user", "content": truncated},
        ],
        max_completion_tokens=4000,
        response_format={"type": "json_object"},  # nudge providers that honour it
    )
    raw = (response.choices[0].message.content or "").strip()
    return _parse_ai_response(raw)


def _parse_ai_response(raw: str) -> list[dict]:
    """Tolerant JSON parser. The model may return a bare array, a wrapped
    object like `{"advisories": [...]}`, or accidentally include a markdown
    fence. Handle each gracefully."""
    if not raw:
        return []
    # Strip markdown fence if present.
    fence = re.match(r"```(?:json)?\s*([\s\S]+?)\s*```", raw)
    if fence:
        raw = fence.group(1).strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # Last-ditch: find the first [...] block by brace matching.
        m = re.search(r"\[[\s\S]*\]", raw)
        if not m:
            logger.warning("AI extraction returned non-JSON: %r", raw[:200])
            return []
        try:
            parsed = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
    if isinstance(parsed, list):
        rows = parsed
    elif isinstance(parsed, dict):
        # Find the first list value in the dict.
        rows = next((v for v in parsed.values() if isinstance(v, list)), [])
    else:
        return []
    # Coerce each row to our canonical schema.
    out: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        threat = (r.get("threat") or "").strip()
        if not threat:
            continue
        out.append({
            "threat": threat,
            "report_type": (r.get("report_type") or "Vulnerability").strip() or "Vulnerability",
            "published": (r.get("published") or "").strip(),
            "hunting_result": (r.get("hunting_result") or "").strip(),
        })
    return out


def extract_advisories_with_ai(text: str) -> list[dict]:
    """Sync wrapper around the async LLM call. Flask routes are sync, so we
    pay the asyncio.run overhead per request — acceptable since this is an
    analyst-initiated one-shot, not a hot path."""
    if not text or not text.strip():
        return []
    try:
        return asyncio.run(_ai_extract_async(text))
    except Exception as exc:
        logger.error("AI advisory extraction failed: %s", exc, exc_info=True)
        return []
