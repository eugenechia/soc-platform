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


def _resolve_utilization_months(daily_breakdown: list, end_date: str = "",
                                monthly_totals: dict | None = None):
    """Pick the 3 chart months ending at ``end_date`` and their GB values.

    Prefers the FROZEN per-month total in ``monthly_totals`` (the current
    month's live total plus prior months captured from their own saved reports)
    over the live ``daily_breakdown`` bucket. This is the fix for a completed
    month silently shrinking between reports: a live trailing-3-month Usage
    query drops days older than Sentinel's 90-day retention, which made a
    finished April fall from 520 GB to ~328 GB once its first ten days aged out.
    ``daily_breakdown`` is used only as a per-month fallback for a month that
    has no frozen value yet (e.g. a newly-onboarded customer). Split out from
    rendering so the frozen-vs-live selection is unit-testable.

    Returns ``(months, values)``.
    """
    from dateutil.parser import parse as _dateparse

    monthly_live: dict[str, float] = {}
    for row in daily_breakdown or []:
        tg = row.get("TimeGenerated", "")
        gb = float(row.get("TotalGB") or 0)
        if not tg:
            continue
        try:
            month_key = _dateparse(tg).strftime("%Y-%m")
            monthly_live[month_key] = round(monthly_live.get(month_key, 0) + gb, 2)
        except Exception:
            continue

    frozen = monthly_totals or {}

    try:
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    except Exception:
        _keys = list(monthly_live.keys()) + list(frozen.keys())
        end_dt = datetime.strptime(max(_keys), "%Y-%m") if _keys else datetime.now()

    end_month = end_dt.replace(day=1)
    months = [
        (end_month - relativedelta(months=i)).strftime("%Y-%m")
        for i in range(2, -1, -1)
    ]

    def _val(m: str) -> float:
        fv = frozen.get(m)
        return round(float(fv), 2) if isinstance(fv, (int, float)) else monthly_live.get(m, 0)

    return months, [_val(m) for m in months]


def generate_sentinel_utilization_chart(daily_breakdown: list, end_date: str = "",
                                        monthly_totals: dict | None = None) -> bytes:
    """Bar chart of monthly GB ingestion for the 3 months ending at end_date.

    Values are chosen by :func:`_resolve_utilization_months` — frozen
    ``monthly_totals`` preferred over the retention-truncated live
    ``daily_breakdown`` so completed months don't change between reports.
    """
    if not daily_breakdown and not end_date and not monthly_totals:
        return b""

    months, values = _resolve_utilization_months(daily_breakdown, end_date, monthly_totals)
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


# Group raw OSPlatform strings into top-level families. The MDE/Heartbeat data
# ships values like "Windows11 10.0", "WindowsServer2022 10.0", "macOS 26.5",
# "Linux 9.7", "iOS 26.5" — too granular for a pie wedge. Order matters: the
# WVD/AVD checks must precede the generic "windows" prefix.
def _family(raw: str) -> str:
    low = (raw or "").strip().lower()
    if low.startswith("windowsserver"):
        return "Windows Server"
    if low.startswith("windows10wvd") or low.startswith("windows11wvd"):
        return "Windows AVD"
    if low.startswith("windows"):
        return "Windows Client"
    if low.startswith("macos"):
        return "macOS"
    if low.startswith("linux"):
        return "Linux"
    if low.startswith("ios"):
        return "iOS"
    if low.startswith("android"):
        return "Android"
    return "Other"


# A real fleet spans 7 families (Windows Client/Server/AVD, macOS, Linux,
# Android, iOS). 8 wedges shows all of them and still guards a pathological
# long tail; the old cap of 6 buried iOS and Windows AVD in "Other".
_MAX_WEDGES = 8


def _group_families(counts: dict) -> list[tuple[str, int]]:
    """Family counts sorted desc, capped to _MAX_WEDGES with the tail lumped
    into "Other". Always preserves the grand total."""
    sorted_fams = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if len(sorted_fams) <= _MAX_WEDGES:
        return sorted_fams
    head, tail = sorted_fams[:_MAX_WEDGES - 1], sorted_fams[_MAX_WEDGES - 1:]
    other_total = sum(c for _, c in tail)
    return head + ([("Other", other_total)] if other_total else [])


def generate_total_assets_chart(os_breakdown: list) -> bytes:
    """Donut chart of monitored assets grouped by OS family.

    Takes the AGGREGATED breakdown ``[{OSPlatform, Count}]`` computed over the
    whole fleet by ``device_breakdown.summarize_devices`` — never a row sample.
    Counting sampled rows here is what made section 1.12 report 200 assets for
    a 965-device fleet. Centre hole shows the total.
    """
    if not os_breakdown:
        return b""

    counts: dict[str, int] = {}
    for row in os_breakdown:
        fam = _family(row.get("OSPlatform") or row.get("os_platform") or "")
        counts[fam] = counts.get(fam, 0) + int(row.get("Count") or 0)

    sorted_fams = _group_families(counts)
    labels = [k for k, _ in sorted_fams]
    values = [v for _, v in sorted_fams]
    total  = sum(values)

    # Reuse the existing palette for visual consistency with other charts.
    # One entry per possible wedge so no two families share a colour.
    palette = [_BLUE, "#10B981", "#F59E0B", "#8B5CF6", "#DC2626",
               "#0891B2", "#EC4899", _GREY]
    colors  = [palette[i % len(palette)] for i in range(len(labels))]

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_BG)
    wedges, _ = ax.pie(values, colors=colors, startangle=90,
                       wedgeprops=dict(width=0.38, edgecolor=_BG, linewidth=2))
    # Centre total
    ax.text(0, 0.08, f"{total:,}", ha="center", va="center",
            fontsize=22, fontweight="bold", color=_DARK)
    ax.text(0, -0.18, "Total Assets", ha="center", va="center",
            fontsize=10, color=_GREY)
    ax.set_title("Total Assets Under Monitoring",
                 fontsize=13, fontweight="bold", color=_DARK, pad=12)
    legend_labels = [f"{lbl} ({cnt})" for lbl, cnt in zip(labels, values)]
    ax.legend(wedges, legend_labels, loc="center left",
              bbox_to_anchor=(1.0, 0.5), frameon=False, fontsize=9)
    fig.tight_layout()
    return _to_bytes(fig)


def generate_sensor_health_chart(health_breakdown: list) -> bytes:
    """Pie chart of HealthStatus distribution across monitored devices.

    Takes the AGGREGATED breakdown ``[{HealthStatus, Count}]`` covering the
    whole fleet. It previously counted rows of a device sample that had been
    truncated after sorting on HealthStatus — which selected only "Active"
    devices and drew a 100%-healthy fleet, hiding the very sensors this
    section exists to surface.

    Renders under section 1.13 "Managed Assets by Sensor Health State".
    """
    if not health_breakdown:
        return b""

    status_colors = {
        "Active":         _BLUE,
        "Inactive":       "#F59E0B",
        "No sensor data": "#DC2626",
        "Impaired":       "#F97316",
        "Unknown":        _GREY,
    }

    counts: dict[str, int] = {}
    for row in health_breakdown:
        raw = (row.get("HealthStatus") or row.get("health_status") or "Unknown").strip()
        # Defender XDR uses "ImpairedCommunication" — fold to "Impaired" for display.
        if raw.lower().startswith("impair"):
            label = "Impaired"
        elif raw.lower() in ("active", "inactive", "unknown"):
            label = raw.capitalize()
        elif "nosensor" in raw.lower().replace(" ", ""):
            # Defender ships "NoSensorData" (no spaces) — match either casing
            # so the raw API string never reaches a customer-facing chart.
            label = "No sensor data"
        else:
            label = raw
        counts[label] = counts.get(label, 0) + int(row.get("Count") or 0)

    # Order: Active first, then everything else, Unknown last.
    def _sort_key(item):
        k = item[0]
        if k == "Active":         return (0, k)
        if k == "Unknown":        return (2, k)
        return (1, k)
    items = sorted(counts.items(), key=_sort_key)

    labels = [k for k, _ in items]
    values = [v for _, v in items]
    colors = [status_colors.get(k, _GREY) for k in labels]
    total  = sum(values)

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_BG)
    wedges, _ = ax.pie(values, colors=colors, startangle=90,
                       wedgeprops=dict(edgecolor=_BG, linewidth=2))
    ax.set_title("Managed Assets by Sensor Health State",
                 fontsize=13, fontweight="bold", color=_DARK, pad=12)
    legend_labels = [
        f"{lbl}  {cnt}  ({cnt/total*100:.1f}%)" if total else lbl
        for lbl, cnt in zip(labels, values)
    ]
    ax.legend(wedges, legend_labels, loc="center left",
              bbox_to_anchor=(1.0, 0.5), frameon=False, fontsize=9)
    fig.tight_layout()
    return _to_bytes(fig)


def generate_vulnerability_severity_chart(by_severity) -> bytes:
    """Horizontal bar chart of vulnerability counts by severity.

    Accepts either a dict {severity: count} or a list of rows like
    [{"VulnerabilitySeverityLevel": "High", "Count": 64890}, ...] — the
    Defender TVM hunt and the Sentinel fallback return slightly different
    shapes so we normalise here.

    Renders under section 1.14 "Vulnerability Details".
    """
    if not by_severity:
        return b""

    # Normalise input → {DisplayLabel: count}
    raw: dict[str, int] = {}
    if isinstance(by_severity, dict):
        for k, v in by_severity.items():
            raw[str(k).strip().capitalize()] = int(v or 0)
    else:
        for row in by_severity:
            if not isinstance(row, dict):
                continue
            k = (row.get("VulnerabilitySeverityLevel")
                 or row.get("severity") or row.get("Severity") or "").strip()
            v = int(row.get("Count") or row.get("count") or 0)
            if k:
                raw[k.capitalize()] = raw.get(k.capitalize(), 0) + v

    ordered = ["Critical", "High", "Medium", "Low", "Informational", "Unspecified"]
    color_map = {
        "Critical":      _SEVERITY_COLORS["Critical Severity"],
        "High":          _SEVERITY_COLORS["High Severity"],
        "Medium":        _SEVERITY_COLORS["Medium Severity"],
        "Low":           _SEVERITY_COLORS["Low Severity"],
        "Informational": _SEVERITY_COLORS["Informational"],
        "Unspecified":   _GREY,
    }

    # Keep only categories present in the data, ordered by severity weight.
    items = [(k, raw[k]) for k in ordered if raw.get(k, 0) > 0]
    if not items:
        return b""

    # Bar chart: top (Critical) at top of plot — reverse for matplotlib barh.
    labels = [k for k, _ in items][::-1]
    values = [v for _, v in items][::-1]
    colors = [color_map.get(k, _GREY) for k in labels]

    fig, ax = plt.subplots(figsize=(7.5, max(2.5, len(labels) * 0.55 + 0.8)))
    _setup_style(fig, ax)
    bars = ax.barh(labels, values, color=colors, height=0.62,
                   edgecolor="white", linewidth=0.5)
    xmax = max(values)
    offset = xmax * 0.012 if xmax else 0.5
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + offset, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", ha="left", va="center", fontsize=10,
                fontweight="bold", color=_DARK)
    ax.set_title("Vulnerability Details by Severity",
                 fontsize=13, fontweight="bold", color=_DARK, pad=12)
    ax.set_xlabel("Vulnerabilities", fontsize=10, color=_GREY)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax.set_xlim(0, xmax * 1.15 if xmax else 1)
    fig.tight_layout()
    return _to_bytes(fig)


def generate_vulnerability_exposed_devices_chart(devices: list) -> bytes:
    """Horizontal bar chart of the top 15 devices by vulnerability count.

    Accepts the Defender TVM hunt shape ({"DeviceName", "VulnCount"}) or
    the Sentinel fallback shape ({"device_name", "count"}).

    Renders under section 1.16 "Monthly Vulnerability Exposed Devices".
    """
    if not devices:
        return b""

    rows: list[tuple[str, int]] = []
    for row in devices:
        if not isinstance(row, dict):
            continue
        name = (row.get("DeviceName") or row.get("device_name") or "").strip()
        cnt  = int(row.get("VulnCount") or row.get("count") or 0)
        if name and cnt:
            rows.append((name, cnt))
    if not rows:
        return b""

    rows.sort(key=lambda kv: kv[1], reverse=True)
    rows = rows[:15]
    # matplotlib barh stacks bottom-up; reverse so highest is on top.
    rows = rows[::-1]

    labels = [(n if len(n) <= 34 else n[:31] + "…") for n, _ in rows]
    values = [v for _, v in rows]

    fig, ax = plt.subplots(figsize=(9, max(3, len(labels) * 0.4 + 1)))
    _setup_style(fig, ax)
    bars = ax.barh(labels, values, color=_BLUE, height=0.62,
                   edgecolor="white", linewidth=0.5)
    xmax = max(values)
    offset = xmax * 0.012 if xmax else 0.5
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + offset, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", ha="left", va="center", fontsize=9,
                fontweight="bold", color=_DARK)
    ax.set_title("Top Vulnerability-Exposed Devices",
                 fontsize=13, fontweight="bold", color=_DARK, pad=12)
    ax.set_xlabel("Vulnerabilities", fontsize=10, color=_GREY)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{int(x):,}"))
    ax.set_xlim(0, xmax * 1.18 if xmax else 1)
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
