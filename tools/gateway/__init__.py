"""SIEM ticket gateway — dedup + Jira create/append.

Public surface:
  schema.parse_alert(payload) -> Alert | raises AlertValidationError
  dedup.dedup_key(alert)      -> 16-hex SHA-256 digest
  jira.JiraClient.from_env()  -> client with find/create/append methods

Used by routes.gateway (the /api/ingest blueprint).

Originally a separate Flask app (Office/SOC-System/soc-ticket-gateway/);
merged into soc-platform 2026-05-05 to avoid running two Container Apps for
what is functionally a single SOC product.
"""
