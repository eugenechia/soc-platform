"""Render architectural PNGs for soc-platform with Azure-branded icons.

Run from the project root via the project's diagrams venv:

    .venv-diagrams/bin/python docs/architecture/diagrams.py

Produces three PNG files alongside ARCHITECTURE.md:

  * 01_deployment.png   — Azure resources and how they wire together
  * 02_integration.png  — External services the running app talks to
  * 03_internal.png     — Flask blueprints, tools, exporters, and the
                          report-generation data path through them

These are the same three views described in ARCHITECTURE.md. Re-run after
any structural change so executive decks and Confluence artefacts stay in
sync with the Mermaid source-of-truth.
"""
from pathlib import Path

from diagrams import Diagram, Cluster, Edge

# Azure-branded icons
from diagrams.azure.compute import ContainerApps, ContainerRegistries
from diagrams.azure.security import KeyVaults, Sentinel
from diagrams.azure.storage import StorageAccounts, AzureFileshares
from diagrams.azure.analytics import LogAnalyticsWorkspaces
from diagrams.azure.ml import AzureOpenAI
from diagrams.azure.identity import (
    AzureActiveDirectory,
    AppRegistrations,
    ManagedIdentities,
    Groups,
)

# Non-Azure / SaaS / generic
from diagrams.onprem.client import User
from diagrams.onprem.network import Internet
from diagrams.onprem.compute import Server
from diagrams.programming.framework import Flask
from diagrams.programming.language import Python
from diagrams.generic.storage import Storage as GenericStorage
from diagrams.generic.database import SQL as GenericDB
from diagrams.custom import Node


OUT_DIR = Path(__file__).parent
GRAPH_ATTRS = {
    "fontname": "Helvetica",
    "fontsize": "14",
    "bgcolor": "white",
    "pad": "0.4",
    "splines": "spline",
    "rankdir": "TB",
}
NODE_ATTRS = {"fontname": "Helvetica", "fontsize": "11"}
EDGE_ATTRS = {"fontname": "Helvetica", "fontsize": "10", "color": "#475569"}
CLUSTER_ATTRS = {
    "fontname": "Helvetica-Bold",
    "fontsize": "12",
    "bgcolor": "#F8FAFC",
    "pencolor": "#94A3B8",
    "style": "rounded",
    "labeljust": "l",
}


def _gen_node(label: str) -> Node:
    """Plain box node for systems without a brand icon. The Custom node would
    require an image path; Node renders as a box with the given label."""
    return Node(label)


def render_deployment() -> Path:
    """Panel 1 — Azure resources and how they wire together."""
    out = OUT_DIR / "01_deployment"
    with Diagram(
        name="soc-platform — Deployment View",
        filename=str(out),
        outformat="png",
        show=False,
        direction="TB",
        graph_attr={**GRAPH_ATTRS, "rankdir": "TB"},
        node_attr=NODE_ATTRS,
        edge_attr=EDGE_ATTRS,
    ):
        operator = User("Operator\n(GSOC)")

        with Cluster("Entra ID Tenant — logicalisasia",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#FFF7ED"}):
            entra = AzureActiveDirectory("Entra ID")
            app_reg = AppRegistrations("SOC Platform\nApp Registration")
            sec_grp = Groups("Security Group\nGSOC operators")

        with Cluster("Resource Group — rg-soc-platform (southeastasia)",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#EFF6FF"}):
            aca = ContainerApps("Azure Container Apps\nsoc-platform\nmin=max=1 replica")
            acr = ContainerRegistries("ACR\nsocplatformreg")
            mi = ManagedIdentities("Managed Identity\n(get/list/set on KV)")
            kv = KeyVaults("Key Vault\nkv-socplatform")
            sa = StorageAccounts("Storage Account\nsocdataplatform")
            fs = AzureFileshares("File Share\nsoc-platform-data\n(/app/data)")
            law = LogAnalyticsWorkspaces("Log Analytics\nContainerAppConsoleLogs")
            aoai = AzureOpenAI("Azure OpenAI\ngpt-4.1")

        operator >> Edge(label="HTTPS\nEntra-gated", style="bold", color="#0078D4") >> aca
        operator >> Edge(label="OAuth2 PKCE", style="dashed", color="#0078D4") >> entra
        entra >> Edge(style="dashed") >> app_reg
        app_reg >> Edge(label="groupMembershipClaims") >> sec_grp

        aca >> Edge(label="federated MI") >> mi
        mi >> Edge(label="get / list / set") >> kv
        mi >> Edge(label="read / write") >> sa
        sa >> Edge(style="dashed") >> fs
        aca >> Edge(label="stdout / stderr") >> law
        aca >> Edge(label="image pull") >> acr
        aca >> Edge(label="chat.completions", color="#107C10") >> aoai

        kv >> Edge(label="customer-<id>-sentinel-secret\njira-api-token\nsplunk-token\ntavily-api-key",
                   style="dashed", color="#94A3B8") >> aca

    return Path(str(out) + ".png")


def render_integration() -> Path:
    """Panel 2 — Every external service the running app talks to."""
    out = OUT_DIR / "02_integration"
    with Diagram(
        name="soc-platform — System / Integration View",
        filename=str(out),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr={**GRAPH_ATTRS, "rankdir": "LR", "nodesep": "0.6", "ranksep": "1.2"},
        node_attr=NODE_ATTRS,
        edge_attr=EDGE_ATTRS,
    ):
        # Center: the Flask app
        with Cluster("Azure Container Apps",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#EFF6FF"}):
            app = Flask("soc-platform\n(Flask · Python 3.12)")

        # Inbound traffic
        operator = User("Operator")
        webhook = _gen_node("JIRA / Sentinel\nwebhook sender")

        # Identity
        with Cluster("Identity",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#FEF3C7"}):
            entra = AzureActiveDirectory("Entra ID\nMSAL")

        # Per-customer SIEM / ticketing
        with Cluster("Customer Ticketing & SIEM (per-customer)",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#FFF7ED"}):
            jira = _gen_node("JIRA Cloud\nlogicalisasia.atlassian.net\nincidents · SR · CR")
            sentinel = Sentinel("Microsoft Sentinel\n(per-customer\nworkspace + SP)")
            splunk = Server("Splunk on-prem\n10.11.1.181:8089")

        # Threat intelligence
        with Cluster("Threat Intelligence",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#FCE7F3"}):
            socr_rest = _gen_node("SOCRadar REST\nplatform.socradar.com\ncompany + industry")
            socr_mcp = _gen_node("SOCRadar MCP\nmcp.socradar.com\nOAuth2.1 PKCE")
            tavily = Internet("Tavily\nweb search")
            vt = _gen_node("VirusTotal\nIOC")
            abuse = _gen_node("AbuseIPDB\nIOC")

        # AI
        with Cluster("AI Services",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#DCFCE7"}):
            aoai = AzureOpenAI("Azure OpenAI\ngpt-4.1\n(report writer)")
            anthropic = _gen_node("Anthropic\nMessages + MCP-client beta\n(Investigate analyst)")

        # Output / delivery
        with Cluster("Delivery",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#E0F2FE"}):
            smtp = _gen_node("SMTP relay\n:587 TLS\nscheduled email")

        operator >> Edge(label="HTTPS", style="bold") >> app
        webhook >> Edge(label="POST /webhook", style="dashed") >> app
        app >> Edge(label="MSAL\nbefore_request") >> entra

        app >> Edge(label="REST · JQL") >> jira
        app >> Edge(label="client_credentials\n+ KQL") >> sentinel
        app >> Edge(label="REST") >> splunk

        app >> Edge(label="API-Key") >> socr_rest
        app >> Edge(label="MCP / Anthropic") >> socr_mcp
        app >> Edge(label="search query") >> tavily
        app >> Edge(label="enrichment", style="dashed") >> vt
        app >> Edge(label="enrichment", style="dashed") >> abuse

        app >> Edge(label="chat.completions", color="#107C10") >> aoai
        app >> Edge(label="messages.create", color="#D97706") >> anthropic

        app >> Edge(label="multipart attachment\n(scheduled)", style="dashed") >> smtp

    return Path(str(out) + ".png")


def render_internal() -> Path:
    """Panel 3 — Inside the Flask app: blueprints, tools, exporters."""
    out = OUT_DIR / "03_internal"
    with Diagram(
        name="soc-platform — Internal Architecture",
        filename=str(out),
        outformat="png",
        show=False,
        direction="TB",
        graph_attr={**GRAPH_ATTRS, "rankdir": "TB", "nodesep": "0.5", "ranksep": "0.9"},
        node_attr=NODE_ATTRS,
        edge_attr=EDGE_ATTRS,
    ):
        operator = User("Operator")

        with Cluster("app.py — Flask app factory + before_request auth gate",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#EFF6FF"}):

            with Cluster("routes/",
                         graph_attr={**CLUSTER_ATTRS, "bgcolor": "#DBEAFE"}):
                r_auth = Flask("auth.py\nMSAL + Entra")
                r_rep = Flask("reports.py\nGenerate Report")
                r_inv = Flask("investigate.py\nMCP analyst")
                r_adm = Flask("admin.py\ncustomers · history\nschedules")
                r_exp = Flask("exports.py\nfile rendering")
                r_wh = Flask("webhook.py")

            with Cluster("tools/  (deterministic execution)",
                         graph_attr={**CLUSTER_ATTRS, "bgcolor": "#FEF3C7"}):
                t_jira = Python("jira_client\nincidents · SR · CR\nmonthly counts")
                t_ver = Python("⚡ jira_verifier\nindependent 12-month JQL\nFAIL-CLOSED on diff")
                t_sent = Python("sentinel_client\nper-customer KQL")
                t_splk = Python("splunk_client")
                t_socr = Python("socradar_rest")
                t_socm = Python("socradar_mcp")
                t_tav = Python("tavily_client")
                t_cust = Python("customers\nload/save customers.json")
                t_sec = Python("secrets\nenv → KV (cached)")
                t_db = Python("db\nSQLite reports")
                t_sch = Python("scheduler\nAPScheduler")
                t_chrt = Python("chart_generator\nmatplotlib")
                t_enr = Python("enrichment\nVT · AbuseIPDB")

            with Cluster("export/",
                         graph_attr={**CLUSTER_ATTRS, "bgcolor": "#FCE7F3"}):
                e_pdf = Python("pdf_export\nWeasyPrint")
                e_docx = Python("docx_export\npython-docx")
                e_pptx = Python("pptx_export\npython-pptx")
                e_xlsx = Python("xlsx_export\nopenpyxl")

        with Cluster("Storage",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#E5E7EB"}):
            fs_cust = AzureFileshares("/app/data/\ncustomers.json")
            fs_rep = AzureFileshares("/app/data/\nreports/")
            sqlite_db = GenericDB("SQLite\n/tmp/soc_platform.db\n(ephemeral)")
            kv = KeyVaults("Key Vault")

        operator >> r_auth
        operator >> r_rep
        operator >> r_inv
        operator >> r_adm

        # Report generation data path
        r_rep >> Edge(label="parallel fetch\n(threads)", color="#2563EB") >> t_jira
        r_rep >> t_sent
        r_rep >> t_splk
        r_rep >> t_socr
        r_rep >> t_tav
        r_rep >> Edge(label="VERIFY\nbefore export", color="#16A34A", style="bold") >> t_ver
        r_rep >> t_chrt
        r_rep >> t_cust

        # Investigate path
        r_inv >> t_socm
        r_inv >> t_tav

        # Admin
        r_adm >> t_cust
        r_adm >> t_sec

        # Exports
        r_exp >> e_pdf
        r_exp >> e_docx
        r_exp >> e_pptx
        r_exp >> e_xlsx

        # Scheduler triggers report generation
        t_sch >> Edge(label="cron-style trigger", style="dashed") >> r_rep

        # Verifier hits jira independently
        t_ver >> Edge(label="independent JQL", color="#16A34A") >> t_jira

        # Tool dependencies
        t_jira >> t_sec
        t_sent >> t_sec
        t_sent >> t_cust
        t_splk >> t_sec
        t_socr >> t_sec
        t_socm >> t_sec
        t_tav >> t_sec

        # Storage edges
        t_cust >> fs_cust
        t_db >> sqlite_db
        t_sec >> kv

        r_rep >> Edge(label="persist markdown\n+ chart PNGs", style="dashed") >> t_db
        r_rep >> Edge(style="dashed") >> fs_rep

    return Path(str(out) + ".png")


def main() -> None:
    print("Rendering deployment view...")
    p1 = render_deployment()
    print(f"  → {p1.name}")

    print("Rendering integration view...")
    p2 = render_integration()
    print(f"  → {p2.name}")

    print("Rendering internal architecture...")
    p3 = render_internal()
    print(f"  → {p3.name}")

    print("\nAll three panels rendered to:")
    for p in (p1, p2, p3):
        size_kb = p.stat().st_size // 1024 if p.exists() else 0
        print(f"  {p.name:24s}  ({size_kb} KB)")


if __name__ == "__main__":
    main()
