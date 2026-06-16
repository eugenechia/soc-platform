"""
ADF (Atlassian Document Format) primitive builders.

Each function returns a JSON-serializable dict matching Jira's ADF schema.
``doc(*blocks)`` wraps top-level block nodes into a complete document ready
to be posted as a Jira comment body.

We deliberately accept ``str`` shortcuts everywhere a text node is expected
so call-sites stay terse — e.g. ``paragraph("hello")`` instead of
``paragraph(text("hello"))``.

Used by ``tools/enrichment.py::_build_comment_adf`` (Phase 5c, 2026-06-16)
to render structured triage comments. Stays minimal — adding more node
types here is fine, but be cautious about table cell nesting; Jira Cloud
rejects unexpected node shapes with HTTP 400.
"""
from __future__ import annotations


_PANEL_TYPES = {"info", "note", "warning", "success", "error"}


def text(s: str, *, bold: bool = False, italic: bool = False, code: bool = False) -> dict:
    """Inline text node with optional marks (strong / em / code)."""
    node: dict = {"type": "text", "text": s if s else " "}
    marks = []
    if bold:
        marks.append({"type": "strong"})
    if italic:
        marks.append({"type": "em"})
    if code:
        marks.append({"type": "code"})
    if marks:
        node["marks"] = marks
    return node


def _coerce_inline(node: dict | str) -> dict:
    return text(node) if isinstance(node, str) else node


def _coerce_block(node: dict | str) -> dict:
    if isinstance(node, str):
        return paragraph(node)
    # If already a block (paragraph/heading/table/etc.) pass through.
    if isinstance(node, dict) and node.get("type") in {
        "paragraph", "heading", "table", "panel", "bulletList",
        "orderedList", "rule", "codeBlock",
    }:
        return node
    # Inline text → wrap in paragraph.
    return paragraph(node)


def paragraph(*children: dict | str) -> dict:
    """Paragraph block. Children can be strings or text nodes."""
    nodes = [_coerce_inline(c) for c in children] if children else [text("")]
    return {"type": "paragraph", "content": nodes}


def heading(level: int, *children: dict | str) -> dict:
    nodes = [_coerce_inline(c) for c in children]
    return {"type": "heading", "attrs": {"level": level}, "content": nodes}


def panel(panel_type: str, *blocks: dict | str) -> dict:
    """Panel container. ``panel_type``: info / note / warning / success / error."""
    if panel_type not in _PANEL_TYPES:
        panel_type = "info"
    content = [_coerce_block(b) for b in blocks]
    return {"type": "panel", "attrs": {"panelType": panel_type}, "content": content}


def _table_cell(cell_type: str, content: dict | str | list) -> dict:
    """Build a tableHeader or tableCell. Content can be a string, a single
    block node, or a list of block nodes."""
    if isinstance(content, list):
        blocks = [_coerce_block(b) for b in content]
    else:
        blocks = [_coerce_block(content)]
    return {"type": cell_type, "attrs": {}, "content": blocks}


def table_header_cell(content: dict | str | list) -> dict:
    return _table_cell("tableHeader", content)


def table_cell(content: dict | str | list) -> dict:
    return _table_cell("tableCell", content)


def table_row(*cells: dict) -> dict:
    return {"type": "tableRow", "content": list(cells)}


def table(headers: list[str], rows: list[list[dict | str | list]]) -> dict:
    """Build a table from a header row + body rows.

    ``rows`` is a list of rows; each row is a list of cell contents.
    Each cell content may be a string, a single block node, or a list of
    block nodes (when a cell needs multiple paragraphs).
    """
    rs: list[dict] = []
    if headers:
        rs.append(table_row(*[table_header_cell(h) for h in headers]))
    for row in rows:
        rs.append(table_row(*[table_cell(c) for c in row]))
    return {
        "type": "table",
        "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
        "content": rs,
    }


def bullet_list(*items: dict | str) -> dict:
    list_items = []
    for it in items:
        if isinstance(it, dict) and it.get("type") == "listItem":
            list_items.append(it)
        else:
            list_items.append({"type": "listItem", "content": [_coerce_block(it)]})
    return {"type": "bulletList", "content": list_items}


def rule() -> dict:
    return {"type": "rule"}


def doc(*blocks: dict | str) -> dict:
    """Top-level ADF document. Wraps any number of block nodes."""
    return {
        "type": "doc",
        "version": 1,
        "content": [_coerce_block(b) for b in blocks],
    }
