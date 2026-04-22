"""
Export endpoints — PDF, DOCX, XLSX, PPTX.
"""
import os
import logging

from flask import Blueprint, Response, jsonify, request

from routes.auth import require_login
from export.pdf_export import generate_pdf
from export.docx_export import generate_docx
from export.xlsx_export import generate_xlsx
from export.pptx_export import generate_pptx

log = logging.getLogger(__name__)

exports_bp = Blueprint("exports", __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_logo(customer_logo: str) -> str | None:
    if not customer_logo:
        return None
    logo_full = os.path.join(BASE_DIR, customer_logo)
    return logo_full if os.path.exists(logo_full) else None


def _get_charts(job_id: str) -> dict:
    if not job_id:
        return {}
    from routes.reports import jobs, _load_report, _get_charts_bytes
    job = jobs.get(job_id)
    if job:
        return _get_charts_bytes(job)
    saved = _load_report(job_id)
    if saved:
        return _get_charts_bytes(saved)
    return {}


def _get_report_data(job_id: str) -> dict | None:
    if not job_id:
        return None
    from routes.reports import jobs, _load_report
    job = jobs.get(job_id)
    if job and job.get("data"):
        return job["data"]
    saved = _load_report(job_id)
    if saved and saved.get("data"):
        return saved["data"]
    return None


@exports_bp.route("/pdf", methods=["POST"])
@require_login
def export_pdf():
    data = request.json or {}
    markdown_content = data.get("markdown", "").strip()
    customer_name = data.get("customer_name", "Client")
    report_date = data.get("report_date", "")
    customer_logo = data.get("customer_logo", "")
    job_id = data.get("job_id", "")

    if not markdown_content:
        return jsonify({"error": "No content to export."}), 400

    logo_path = _resolve_logo(customer_logo)
    charts = _get_charts(job_id)

    try:
        pdf_bytes = generate_pdf(markdown_content, customer_name, report_date, logo_path, charts)
    except Exception as e:
        log.exception("PDF export failed")
        return jsonify({"error": f"PDF generation failed: {e}"}), 500

    safe_name = customer_name.lower().replace(" ", "-")
    return Response(
        pdf_bytes, mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="soc-report-{safe_name}.pdf"'},
    )


@exports_bp.route("/docx", methods=["POST"])
@require_login
def export_docx():
    data = request.json or {}
    markdown_content = data.get("markdown", "").strip()
    customer_name = data.get("customer_name", "Client")
    report_date = data.get("report_date", "")
    customer_logo = data.get("customer_logo", "")
    job_id = data.get("job_id", "")

    if not markdown_content:
        return jsonify({"error": "No content to export."}), 400

    logo_path = _resolve_logo(customer_logo)
    charts = _get_charts(job_id)

    try:
        docx_bytes = generate_docx(markdown_content, customer_name, report_date, logo_path, charts)
    except Exception as e:
        log.exception("DOCX export failed")
        return jsonify({"error": f"Word export failed: {e}"}), 500

    safe_name = customer_name.lower().replace(" ", "-")
    return Response(
        docx_bytes,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="soc-report-{safe_name}.docx"'},
    )


@exports_bp.route("/xlsx", methods=["POST"])
@require_login
def export_xlsx():
    data = request.json or {}
    job_id = data.get("job_id", "")
    customer_name = data.get("customer_name", "Client")

    report_data = _get_report_data(job_id)
    if not report_data:
        return jsonify({"error": "No data available for export. Generate a report first."}), 400

    try:
        xlsx_bytes = generate_xlsx(report_data)
    except Exception as e:
        log.exception("XLSX export failed")
        return jsonify({"error": f"Excel export failed: {e}"}), 500

    safe_name = customer_name.lower().replace(" ", "-")
    return Response(
        xlsx_bytes,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="soc-report-{safe_name}.xlsx"'},
    )


@exports_bp.route("/pptx", methods=["POST"])
@require_login
def export_pptx():
    data = request.json or {}
    markdown_content = data.get("markdown", "").strip()
    customer_name = data.get("customer_name", "Client")
    report_date = data.get("report_date", "")
    customer_logo = data.get("customer_logo", "")
    job_id = data.get("job_id", "")

    if not markdown_content:
        return jsonify({"error": "No content to export."}), 400

    logo_path = _resolve_logo(customer_logo)
    charts = _get_charts(job_id)

    try:
        pptx_bytes = generate_pptx(markdown_content, customer_name, report_date, logo_path, charts)
    except Exception as e:
        log.exception("PPTX export failed")
        return jsonify({"error": f"PPTX generation failed: {e}"}), 500

    safe_name = customer_name.lower().replace(" ", "-")
    return Response(
        pptx_bytes,
        mimetype="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        headers={"Content-Disposition": f'attachment; filename="soc-report-{safe_name}.pptx"'},
    )
