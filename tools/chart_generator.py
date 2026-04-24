"""Generate matplotlib charts for SOC reports.

Each function returns PNG bytes suitable for embedding in PDF/Word exports.
Charts follow the Logicalis GSOC branding: blue accent (#1F6FEB), clean style.
"""

import logging
from io import BytesIO
from datetime import datetime
from dateutil.relativedelta import relativedelta

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

logger = logging.getLogger(__name__)

# Branding colours
_BLUE = "#1F6FEB"
_DARK = "#1A1A2E"
_GREY = "#64748B"
_BG = "#FAFBFD"

_SEVERITY_COLORS = {
    "Critical Severity": "#DC2626",
    "High Severity": "#F97316",
    "Medium Severity": "#F59E0B",
    "Low Severity": "#3B82F6",
    "Informational": "#8B5CF6",
}

_RESOLUTION_COLORS = {
    "Benign Positive": "#3B82F6",
    "True Positive": "#DC2626",
    "False Positive": "#10B981",
    "Pending": "#F59E0B",
}


def _setup_style(fig, ax):
    """Apply consistent styling."""
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_BG)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#E2E8F0")
    ax.spines["bottom"].set_color("#E2E8F0")
    ax.tick_params(colors=_GREY, labelsize=9)


def _to_bytes(fig) -> bytes:
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def generate_severity_chart(by_severity: dict) -> bytes:
    """Bar chart of incidents by severity level.

    Uses labels: Informational, Low Severity, Medium Severity, High Severity,
    Critical Severity — matching the sample report format.
    """
    # Map raw severity values to display labels
    label_map = {
        "Informational": "Informational",
        "Lowest": "Informational",
        "Low": "Low Severity",
        "Medium": "Medium Severity",
        "High": "High Severity",
        "Critical": "Critical Severity",
        "Highest": "Critical Severity",
    }
    ordered_display = ["Informational", "Low Severity", "Medium Severity",
                       "High Severity", "Critical Severity"]

    # Build data: always show all 5 categories even if count is 0
    display_data = {lbl: 0 for lbl in ordered_display}
    for raw_key, count in by_severity.items():
        mapped = label_map.get(raw_key)
        if mapped:
            display_data[mapped] += count
        elif raw_key in ordered_display:
            display_data[raw_key] += count
        # Skip "Unspecified" or unknown keys

    labels = list(display_data.keys())
    values = list(display_data.values())
    colors = [_SEVERITY_COLORS.get(k, _BLUE) for k in labels]

    fig, ax = plt.subplots(figsize=(7, 3.5))
    _setup_style(fig, ax)
    bars = ax.bar(labels, values, color=colors, width=0.6, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                str(val), ha="center", va="bottom", fontsize=10, fontweight="bold", color=_DARK)
    ax.set_title("Incident Severity", fontsize=13, fontweight="bold", color=_DARK, pad=12)
    ax.set_ylabel("Count", fontsize=10, color=_GREY)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    plt.xticks(fontsize=8)
    fig.subplots_adjust(bottom=0.18)
    return _to_bytes(fig)


def generate_resolution_chart(by_close_justification: dict) -> bytes:
    """Bar chart of incident resolution classification.

    Uses fixed categories: Pending, True Positive, False Positive, Benign Positive
    — matching the sample report's Incident Status chart.
    """
    ordered = ["Pending", "True Positive", "False Positive", "Benign Positive"]
    values = [by_close_justification.get(k, 0) for k in ordered]
    colors = [_RESOLUTION_COLORS[k] for k in ordered]

    fig, ax = plt.subplots(figsize=(7, 3.5))
    _setup_style(fig, ax)
    bars = ax.bar(ordered, values, color=colors, width=0.6, edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                str(val), ha="center", va="bottom", fontsize=10, fontweight="bold", color=_DARK)
    ax.set_title("Incident Resolution", fontsize=13, fontweight="bold", color=_DARK, pad=12)
    ax.set_ylabel("Count", fontsize=10, color=_GREY)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    fig.tight_layout()
    return _to_bytes(fig)


def generate_monthly_trend_chart(monthly_trend: dict, end_date: str = "") -> bytes:
    """Bar chart showing incident escalation counts over the past 12 months.

    Always shows 12 months ending at the report period's end month.
    Months with no data show as 0.
    """
    if not monthly_trend and not end_date:
        return b""

    # Determine the end month
    try:
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    except Exception:
        # Fall back to the latest month in the data
        if monthly_trend:
            latest = max(monthly_trend.keys())
            end_dt = datetime.strptime(latest, "%Y-%m")
        else:
            end_dt = datetime.now()

    # Build 12-month range ending at end_dt's month
    end_month = end_dt.replace(day=1)
    months = []
    for i in range(11, -1, -1):
        m = end_month - relativedelta(months=i)
        months.append(m.strftime("%Y-%m"))

    values = [monthly_trend.get(m, 0) for m in months]
    display_labels = []
    for m in months:
        try:
            dt = datetime.strptime(m, "%Y-%m")
            display_labels.append(dt.strftime("%b\n%Y"))
        except Exception:
            display_labels.append(m)

    fig, ax = plt.subplots(figsize=(10, 4))
    _setup_style(fig, ax)
    bars = ax.bar(display_labels, values, color=_BLUE, width=0.6,
                  edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars, values):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                    str(val), ha="center", va="bottom", fontsize=9,
                    fontweight="bold", color=_DARK)
    ax.set_title("Total Number of Incidents Escalation \u2013 Past 12 Months",
                 fontsize=13, fontweight="bold", color=_DARK, pad=12)
    ax.set_ylabel("Incidents", fontsize=10, color=_GREY)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    fig.tight_layout()
    return _to_bytes(fig)


def generate_top_alerts_chart(top_alerts: dict) -> bytes:
    """Horizontal bar chart of top triggered alerts."""
    if not top_alerts:
        return b""
    sorted_items = sorted(top_alerts.items(), key=lambda x: x[1])
    labels = [k[:50] + ("..." if len(k) > 50 else "") for k, _ in sorted_items]
    values = [v for _, v in sorted_items]

    fig, ax = plt.subplots(figsize=(9, max(3, len(labels) * 0.45 + 1)))
    _setup_style(fig, ax)
    bars = ax.barh(labels, values, color=_BLUE, height=0.6,
                   edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(val), ha="left", va="center", fontsize=9,
                fontweight="bold", color=_DARK)
    ax.set_title("Top Alerts Triggered", fontsize=13, fontweight="bold",
                 color=_DARK, pad=12)
    ax.set_xlabel("Count", fontsize=10, color=_GREY)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    fig.tight_layout()
    return _to_bytes(fig)


def generate_quarterly_chart(monthly_stats: list[dict], quarter_label: str) -> bytes:
    """
    Grouped bar chart showing incidents per month within a quarter.

    monthly_stats: list of dicts, each {month_label, total_incidents, by_severity}
    quarter_label: e.g. "Q2 2026"
    """
    if not monthly_stats:
        fig, ax = plt.subplots(figsize=(8, 3))
        _setup_style(fig, ax)
        ax.text(0.5, 0.5, "No data available", ha="center", va="center",
                transform=ax.transAxes, color=_GREY, fontsize=12)
        ax.set_title(f"Quarterly Incident Trend — {quarter_label}", fontsize=13,
                     fontweight="bold", color=_DARK, pad=12)
        return _to_bytes(fig)

    labels = [m.get("month_label", "") for m in monthly_stats]
    totals = [m.get("total_incidents", 0) for m in monthly_stats]

    fig, ax = plt.subplots(figsize=(8, 4))
    _setup_style(fig, ax)

    bars = ax.bar(labels, totals, color=_BLUE, width=0.5, zorder=3)
    ax.bar_label(bars, padding=4, fontsize=10, color=_DARK, fontweight="bold")
    ax.set_ylim(0, max(totals) * 1.25 + 1 if totals else 10)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.grid(axis="y", linestyle="--", alpha=0.4, zorder=0)
    ax.set_title(f"Quarterly Incident Trend — {quarter_label}", fontsize=13,
                 fontweight="bold", color=_DARK, pad=12)
    ax.set_ylabel("Total Incidents", fontsize=10, color=_GREY)
    fig.tight_layout()
    return _to_bytes(fig)


def generate_sentinel_utilization_chart(daily_breakdown: list, end_date: str = "") -> bytes:
    """Bar chart of monthly GB ingestion for the 3 months ending at end_date."""
    if not daily_breakdown and not end_date:
        return b""

    from dateutil.parser import parse as _dateparse

    monthly_gb: dict[str, float] = {}
    for row in daily_breakdown:
        tg = row.get("TimeGenerated", "")
        gb = float(row.get("TotalGB") or 0)
        if not tg:
            continue
        try:
            dt = _dateparse(tg)
            month_key = dt.strftime("%Y-%m")
            monthly_gb[month_key] = round(monthly_gb.get(month_key, 0) + gb, 2)
        except Exception:
            continue

    try:
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    except Exception:
        if monthly_gb:
            end_dt = datetime.strptime(max(monthly_gb.keys()), "%Y-%m")
        else:
            end_dt = datetime.now()

    end_month = end_dt.replace(day=1)
    months = [
        (end_month - relativedelta(months=i)).strftime("%Y-%m")
        for i in range(2, -1, -1)
    ]

    values = [monthly_gb.get(m, 0) for m in months]
    display_labels = []
    for m in months:
        try:
            display_labels.append(datetime.strptime(m, "%Y-%m").strftime("%b\n%Y"))
        except Exception:
            display_labels.append(m)

    fig, ax = plt.subplots(figsize=(6, 3.5))
    _setup_style(fig, ax)
    bars = ax.bar(display_labels, values, color=_BLUE, width=0.5,
                  edgecolor="white", linewidth=0.5)
    offset = max(values) * 0.02 if max(values) > 0 else 0.1
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + offset,
                f"{val:.2f} GB", ha="center", va="bottom", fontsize=10,
                fontweight="bold", color=_DARK)
    ax.set_title("Monthly Log Ingestion (GB) — Past 3 Months",
                 fontsize=13, fontweight="bold", color=_DARK, pad=12)
    ax.set_ylabel("Ingested (GB)", fontsize=10, color=_GREY)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:.1f}"))
    ax.yaxis.set_major_locator(ticker.MaxNLocator(nbins=5))
    fig.tight_layout()
    return _to_bytes(fig)


def generate_all_charts(stats: dict, end_date: str = "") -> dict:
    """Generate all available charts from stats data.

    Returns a dict of chart_name -> PNG bytes.
    """
    charts = {}

    by_severity = stats.get("by_severity", {})
    if by_severity:
        try:
            charts["severity"] = generate_severity_chart(by_severity)
        except Exception as e:
            logger.error(f"Severity chart failed: {e}")

    by_close = stats.get("by_close_justification", {})
    try:
        charts["resolution"] = generate_resolution_chart(by_close)
    except Exception as e:
        logger.error(f"Resolution chart failed: {e}")

    monthly = stats.get("monthly_trend", {})
    try:
        charts["monthly_trend"] = generate_monthly_trend_chart(monthly, end_date)
    except Exception as e:
        logger.error(f"Monthly trend chart failed: {e}")

    top_alerts = stats.get("top_alerts", {})
    if top_alerts:
        try:
            charts["top_alerts"] = generate_top_alerts_chart(top_alerts)
        except Exception as e:
            logger.error(f"Top alerts chart failed: {e}")

    return charts
