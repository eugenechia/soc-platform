import os
import base64
import logging
from datetime import datetime

import markdown as md_lib
import weasyprint

logger = logging.getLogger(__name__)


def _encode_image(path: str) -> str:
    """Return a base64 data URI for an image file."""
    if not path or not os.path.exists(path):
        return ""
    with open(path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    ext = os.path.splitext(path)[1].lstrip(".").lower()
    mime = {"webp": "image/webp", "png": "image/png", "jpg": "image/jpeg",
            "jpeg": "image/jpeg"}.get(ext, "image/png")
    return f"data:{mime};base64,{b64}"


def _get_report_month(report_date: str) -> str:
    """Extract a readable month-year string from the report date range."""
    # report_date is typically "2026-02-01 to 2026-02-28"
    try:
        parts = report_date.split(" to ")
        if parts:
            dt = datetime.strptime(parts[-1].strip(), "%Y-%m-%d")
            return dt.strftime("%B %Y")
    except Exception:
        pass
    return report_date


_PDF_STYLES = """
  @page {
    margin: 2cm 2cm 2.5cm 2cm;
    @top-left {
      content: "Logicalis GSOC Monthly Report — {report_month}";
      font-size: 8pt;
      color: #888;
      font-family: Arial, sans-serif;
    }
    @bottom-left {
      content: "Confidential";
      font-size: 8pt;
      color: #888;
      font-family: Arial, sans-serif;
    }
    @bottom-right {
      content: counter(page);
      font-size: 8pt;
      color: #888;
      font-family: Arial, sans-serif;
    }
  }

  @page cover {
    margin: 0;
    @top-left { content: none; }
    @bottom-left { content: none; }
    @bottom-right { content: none; }
  }

  body {
    font-family: Arial, 'Helvetica Neue', sans-serif;
    font-size: 11pt;
    line-height: 1.65;
    color: #1a1a2e;
  }

  /* Cover page */
  .cover-page {
    page: cover;
    page-break-after: always;
    text-align: center;
    padding-top: 30%;
    background: #ffffff;
  }
  .cover-logos {
    margin-bottom: 40px;
  }
  .cover-logos img {
    height: 64px;
    margin: 0 16px;
  }
  .cover-title {
    font-size: 14pt;
    color: #666;
    margin-bottom: 8px;
    font-weight: 400;
  }
  .cover-subtitle {
    font-size: 11pt;
    color: #888;
    margin-bottom: 6px;
  }
  .cover-report-title {
    font-size: 22pt;
    font-weight: 700;
    color: #1f6feb;
    margin: 24px 0 12px 0;
  }
  .cover-customer {
    font-size: 18pt;
    color: #1a1a2e;
    margin-bottom: 48px;
  }
  .cover-date {
    font-size: 11pt;
    color: #888;
  }
  .cover-divider {
    width: 80px;
    height: 3px;
    background: #1f6feb;
    margin: 24px auto;
  }

  /* Content styles */
  h1, h2, h3, h4 { color: #1f6feb; margin-top: 1.2em; }
  h2 { font-size: 15pt; border-bottom: 2px solid #1f6feb; padding-bottom: 4px; margin-top: 1.5em; }
  h3 { font-size: 13pt; }
  h4 { font-size: 11pt; }
  p { margin: 0.5em 0; }
  a { color: #1f6feb; text-decoration: none; }
  a:hover { text-decoration: underline; }

  code {
    background: #f0f3fa;
    padding: 2px 5px;
    border-radius: 3px;
    font-size: 9.5pt;
    font-family: 'Courier New', Courier, monospace;
  }
  pre {
    background: #f0f3fa;
    border: 1px solid #dde4f5;
    border-radius: 4px;
    padding: 12px;
    overflow-x: auto;
    font-size: 9pt;
  }
  pre code { background: none; padding: 0; }

  table {
    border-collapse: collapse;
    width: 100%;
    table-layout: fixed;
    margin: 0.8em auto;
    font-size: 8.5pt;
  }
  th, td {
    border: 1px solid #cdd5e8;
    padding: 4px 7px;
    text-align: left;
    vertical-align: top;
    word-break: break-word;
    overflow-wrap: break-word;
    overflow: hidden;
  }
  th {
    background: #1f6feb;
    color: #ffffff;
    font-weight: 600;
  }
  tr:nth-child(even) td { background: #f7f9ff; }

  blockquote {
    border-left: 4px solid #f59e0b;
    background: #fffbeb;
    padding: 12px 16px;
    margin: 1em 0;
    color: #92400e;
    border-radius: 0 4px 4px 0;
  }
  blockquote strong { color: #92400e; }

  ul, ol { padding-left: 1.4em; margin: 0.4em 0; }
  li { margin: 0.2em 0; }
  hr { border: none; border-top: 1px solid #dde4f5; margin: 1.5em 0; }

  .confidentiality {
    margin-top: 48px;
    padding-top: 24px;
    border-top: 2px solid #1f6feb;
    font-size: 9pt;
    color: #666;
  }
"""


def _build_chart_img_tag(png_bytes: bytes) -> str:
    """Create an <img> tag from chart PNG bytes."""
    b64 = base64.b64encode(png_bytes).decode()
    return f'<div style="text-align:center;margin:16px 0;"><img src="data:image/png;base64,{b64}" style="max-width:100%;height:auto;"></div>'


# Map chart names to section heading keywords for injection
_CHART_SECTION_MAP = {
    "monthly_trend": "1.2",
    "severity": "1.3",
    "resolution": "1.4",
    "sentinel_utilization": "1.8",
    "top_alerts": "1.9",
}


def _inject_charts_into_html(html: str, charts: dict) -> str:
    """Insert chart images after matching section headings in the HTML."""
    if not charts:
        return html

    for chart_name, png_bytes in charts.items():
        if not png_bytes:
            continue
        section_id = _CHART_SECTION_MAP.get(chart_name)
        if not section_id:
            continue

        img_tag = _build_chart_img_tag(png_bytes)

        # Find the heading containing the section number and insert chart after it
        # Match heading content that may contain inline HTML (e.g. <a id="...">)
        # but must not span across multiple headings
        import re
        pattern = re.compile(
            rf'(<h([23])[^>]*>(?:(?!</h\2>).)*?{re.escape(section_id)}(?:(?!</h\2>).)*?</h\2>)',
            re.IGNORECASE | re.DOTALL
        )
        match = pattern.search(html)
        if match:
            insert_pos = match.end()
            html = html[:insert_pos] + img_tag + html[insert_pos:]

    return html


def _add_heading_ids(html: str) -> str:
    """Add id attributes to heading tags that don't already have them.

    This ensures TOC anchor links work even if the AI didn't embed <a id> tags.
    """
    import re

    def _slugify(text: str) -> str:
        text = re.sub(r'<[^>]+>', '', text)  # strip HTML tags
        text = text.lower().strip()
        text = re.sub(r'[^\w\s-]', '', text)  # remove punctuation
        text = re.sub(r'[\s]+', '-', text)     # spaces to hyphens
        text = re.sub(r'-+', '-', text)        # collapse multiple hyphens
        return text.strip('-')

    def _replace_heading(match):
        tag = match.group(1)
        attrs = match.group(2)
        content = match.group(3)
        close_tag = match.group(4)
        # Skip if heading already has an id
        if 'id=' in attrs:
            return match.group(0)
        slug = _slugify(content)
        if slug:
            return f'<{tag} id="{slug}"{attrs}>{content}</{close_tag}>'
        return match.group(0)

    html = re.sub(
        r'<(h[1-4])([^>]*)>(.*?)</(h[1-4])>',
        _replace_heading,
        html,
        flags=re.IGNORECASE | re.DOTALL
    )
    return html


def generate_pdf(markdown_content: str, customer_name: str, report_date: str,
                 logo_path: str | None = None, charts: dict | None = None) -> bytes:
    content_html = md_lib.markdown(
        markdown_content,
        extensions=["tables", "fenced_code", "nl2br"],
    )

    # Add id attributes to headings for TOC anchor links
    content_html = _add_heading_ids(content_html)

    # Inject charts into HTML
    if charts:
        content_html = _inject_charts_into_html(content_html, charts)

    # Prepare logos
    default_logo = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "static", "Logo.webp"
    )
    logicalis_logo_uri = _encode_image(default_logo)
    customer_logo_uri = _encode_image(logo_path) if logo_path else ""

    report_month = _get_report_month(report_date)

    # Build cover page logos
    logos_html = ""
    if logicalis_logo_uri:
        logos_html += f'<img src="{logicalis_logo_uri}" alt="Logicalis">'
    if customer_logo_uri:
        logos_html += f'<img src="{customer_logo_uri}" alt="{customer_name}">'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>{_PDF_STYLES.replace("{report_month}", report_month)}</style>
</head>
<body>
  <div class="cover-page">
    <div class="cover-logos">{logos_html}</div>
    <div class="cover-title">Prepared by Logicalis for</div>
    <div class="cover-customer">{customer_name}</div>
    <div class="cover-divider"></div>
    <div class="cover-title">Logicalis Managed Security Services</div>
    <div class="cover-report-title">GSOC Monthly Report &mdash; {report_month}</div>
  </div>
  {content_html}
</body>
</html>"""

    pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    return pdf_bytes
