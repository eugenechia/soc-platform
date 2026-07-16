"""Render the production private-tenant architecture PNG.

Run from the project root via the project's diagrams venv:

    .venv-diagrams/bin/python docs/architecture/render_prod_architecture.py

Produces 04_prod_private.png alongside the existing three views. This is the
rendered form of docs/PROD-PRIVATE-TENANT-ARCHITECTURE.md (the Mermaid source
of truth lives in that document). Re-run after any change to the prod design.
"""
from pathlib import Path

from diagrams import Diagram, Cluster, Edge

from diagrams.azure.compute import ContainerApps, ContainerRegistries
from diagrams.azure.security import KeyVaults
from diagrams.azure.storage import AzureFileshares
from diagrams.azure.ml import AzureOpenAI
from diagrams.azure.database import DatabaseForPostgresqlServers
from diagrams.azure.network import (
    ApplicationGateway,
    Firewall,
    PrivateEndpoint,
    ExpressrouteCircuits,
    DNSPrivateZones,
)
from diagrams.onprem.client import User
from diagrams.onprem.vcs import Github
from diagrams.onprem.network import Internet
from diagrams.custom import Node


OUT_DIR = Path(__file__).parent
GRAPH_ATTRS = {
    "fontname": "Helvetica",
    "fontsize": "14",
    "bgcolor": "white",
    "pad": "0.4",
    "splines": "spline",
    "rankdir": "TB",
    "nodesep": "0.55",
    "ranksep": "0.9",
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


def render_prod() -> Path:
    out = OUT_DIR / "04_prod_private"
    with Diagram(
        name="soc-platform — Production Private Tenant",
        filename=str(out),
        outformat="png",
        show=False,
        direction="TB",
        graph_attr=GRAPH_ATTRS,
        node_attr=NODE_ATTRS,
        edge_attr=EDGE_ATTRS,
    ):
        # ------- external parties (declared first → top rank) -------
        jira = Node("Jira Cloud\n*.atlassian.net\nwebhooks + REST")
        analyst = User("SOC Analyst\ncorporate network")

        # ------- dev side (unchanged loop) -------
        with Cluster("DEV / STAGING — current tenant (unchanged)",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#F1F5F9"}):
            dev = User("Eugene\nMac Studio")
            gh = Github("GitHub\nSOC-Platform")
            devacr = ContainerRegistries("dev ACR\nsocplatformreg\nimmutable release tags")
            dev >> Edge(label="push") >> gh
            gh >> Edge(label="az acr build\nvX.Y.Z") >> devacr

        saas = Internet("Allowlisted SaaS\nTavily · VirusTotal · AbuseIPDB ·\nConfluence · SOCRadar ·\nlogin.microsoftonline.com ·\napi.loganalytics.io")

        # ------- prod tenant -------
        with Cluster("PROD TENANT — new Entra tenant, ops-operated",
                     graph_attr={**CLUSTER_ATTRS, "bgcolor": "#FFFBEB", "pencolor": "#D97706"}):

            with Cluster("HUB VNet (ops-provided · self-built in Option A)",
                         graph_attr={**CLUSTER_ATTRS, "bgcolor": "#FEF3C7"}):
                fw = Firewall("Azure Firewall\ndefault-deny egress\nFQDN allowlist\nstatic egress IP")
                er = ExpressrouteCircuits("ExpressRoute / VPN")
                dns = DNSPrivateZones("Private DNS\nprivatelink.* zones")

            with Cluster("SPOKE VNet — soc-platform",
                         graph_attr={**CLUSTER_ATTRS, "bgcolor": "#EFF6FF", "pencolor": "#3060C8"}):
                appgw = ApplicationGateway("App Gateway WAF v2\npublic listener\nPATH-LOCKED /webhook/jira\nNSG: Atlassian IPs only")
                aca = ContainerApps("ACA internal env\nsoc-platform\nworkload profiles /27\nUDR 0/0 → firewall")

                with Cluster("snet-privateendpoints",
                             graph_attr={**CLUSTER_ATTRS, "bgcolor": "#E0F2FE"}):
                    pe = PrivateEndpoint("5 private endpoints")
                    acr = ContainerRegistries("ACR Premium")
                    kv = KeyVaults("Key Vault")
                    pg = DatabaseForPostgresqlServers("Postgres Flex")
                    files = AzureFileshares("Azure Files")
                    aoai = AzureOpenAI("Azure OpenAI\npublicNetworkAccess:\nDisabled")

        # ------- flows -------
        devacr >> Edge(label="az acr import (ops)\ncontrol-plane, per release",
                       color="#D97706", style="bold") >> acr

        jira >> Edge(label="webhook POST\nWAF + IP allowlist + secret",
                     color="#C2410C", style="bold") >> appgw
        appgw >> Edge(label="internal ingress") >> aca

        analyst >> Edge(label="HTTPS · Entra SSO", color="#0078D4", style="bold") >> er
        er >> Edge(label="private DNS →\ninternal FQDN") >> aca

        aca >> Edge(label="0.0.0.0/0", color="#DC2626", style="bold") >> fw
        fw >> Edge(label="allowlisted FQDNs only\neverything else deny+log",
                   color="#DC2626") >> saas
        fw >> Edge(label="Jira REST · Confluence", style="dashed") >> jira

        aca >> Edge(label="private endpoints\nMicrosoft backbone", color="#16A34A") >> pe
        pe - Edge(style="dashed") - acr
        pe - Edge(style="dashed") - kv
        pe - Edge(style="dashed") - pg
        pe - Edge(style="dashed") - files
        pe - Edge(style="dashed") - aoai
        dns >> Edge(style="dotted", label="resolves privatelink.*") >> pe

    return Path(str(out) + ".png")


if __name__ == "__main__":
    p = render_prod()
    print(f"rendered → {p} ({p.stat().st_size // 1024} KB)")
