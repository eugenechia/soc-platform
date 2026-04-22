"""
Export endpoints — PDF, DOCX, XLSX, PPTX.

Both source apps had their own export routes. This merges them:
 - PDF/DOCX: both apps had versions; SOC-Report's is more featureful (Logicalis branding,
   charts embedding, unified TOC), so prefer that implementation.
 - XLSX/PPTX: only from SOC-Report.

Routes are POST /exports/<format> with JSON body { "markdown": "...", "config": {...} }.
The heavy lifting lives in the export/ package; this blueprint is a thin dispatch layer.
"""
import logging
from flask import Blueprint, Response, jsonify, request

from routes.auth import require_login
from export.pdf_export import generate_pdf
from export.docx_export import generate_docx
from export.xlsx_export import generate_xlsx
from export.pptx_export import generate_pptx

log = logging.getLogger(__name__)

exports_bp = Blueprint("exports", __name__)


def _payload() -> tuple[str, dict]:
    data = request.get_json() or {}
    md = (data.get("markdown") or "").strip()
    cfg = data.get("config") or {}
    return md, cfg


@exports_bp.route("/pdf", methods=["POST"])
@require_login
def export_pdf():
    md, cfg = _payload()
    if not md:
        return jsonify({"error": "No content to export."}), 400
    try:
        pdf_bytes = generate_pdf(md, cfg)
    except Exception as e:
        log.exception("PDF export failed")
        return jsonify({"error": f"PDF generation failed: {e}"}), 500
    return Response(
        pdf_bytes, mimetype="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="soc-report.pdf"'},
    )


@exports_bp.route("/docx", methods=["POST"])
@require_login
def export_docx():
    md, cfg = _payload()
    if not md:
        return jsonify({"error": "No content to export."}), 400
    try:
        docx_bytes = generate_docx(md, cfg)
    except Exception as e:
        log.exception("DOCX export failed")
        return jsonify({"error": f"DOCX generation failed: {e}"}), 500
    return Response(
        docx_bytes,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": 'attachment; filename="soc-report.docx"'},
    )


@exports_bp.route("/xlsx", methods=["POST"])
@require_login
def export_xlsx():
    md, cfg = _payload()
    if not md:
        return jsonify({"error": "No content to export."}), 400
    try:
        xlsx_bytes = generate_xlsx(md, cfg)
    except Exception as e:
        log.exception("XLSX export failed")
        return jsonify({"error": f"XLSX generation failed: {e}"}), 500
    return Response(
        xlsx_bytes,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="soc-report.xlsx"'},
    )


@exports_bp.route("/pptx", methods=["POST"])
@require_login
def export_pptx():
    md, cfg = _payload()
    if not md:
        return jsonify({"error": "No content to export."}), 400
    try:
        pptx_bytes = generate_pptx(md, cfg)
    except Exception as e:
        log.exception("PPTX export failed")
        return jsonify({"error": f"PPTX generation failed: {e}"}), 500
    return Response(
        pptx_bytes,
        mimetype="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        headers={"Content-Disposition": 'attachment; filename="soc-report.pptx"'},
    )
