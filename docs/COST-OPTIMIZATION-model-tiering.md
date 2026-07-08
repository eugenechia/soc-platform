# LLM Cost Optimization — Model Tiering

**Date:** 2026-07-08

## Why

Question raised: swap the Triage LLM (`gpt-5.3-chat`) to GPT-5 Mini to cut cost?

### Actual spend (Azure Monitor, `lsg-soc-foundry`, last 30 days)
Current usage ≈ **one active customer** (Logicalis; allowlist = SCDM, LOGICALIS).

| Deployment | Calls | Input | Output | Cost/mo |
|-----------|------:|------:|-------:|--------:|
| gpt-5.3-chat | 341 | 2.90M | 0.12M | $4.83 |
| text-embedding-3-large | 196 | 0.20M | — | $0.03 |
| | | | **Total** | **~$4.86** |

### Projected at ~60 customers, full swing (≈60×)
| | GPT-5 Chat (current) | GPT-5 Mini |
|---|---:|---:|
| Chat cost/mo | ~$290 | ~$58 |
| + embeddings | ~$1.70 | ~$1.70 |
| **Total/mo** | **~$291** (~$3.5K/yr) | **~$60** (~$720/yr) |
| Saving | — | **~$232/mo (~$2.8K/yr)** |

(60× is a central estimate; many of the 60 will be "limited" — no Sentinel/RAG →
they skip cmdline analysis, KQL expansion, and RAG embedding, so cost less per
ticket. Real full-swing spend is plausibly $150–300/mo.)

**Conclusion:** negligible today (~$5/mo); worth optimizing at full scale.

## Prompt caching — investigated, NOT pursued

Azure OpenAI caches an identical prompt prefix **≥1024 tokens**. Findings:
- `cacheReadInputTokens` = **0** over 30 days — caching not active.
- The triage system prompt is **~721 tokens** — below the 1024 threshold — and it's
  the only static/shared part. The remaining ~7,800 tokens/call are dynamic
  per-ticket content (ticket text, IOC results, RAG, history) → inherently
  uncacheable.
- Even after padding system prompts past 1024 tokens, only ~12% of input is
  shared, and caching discounts ~half of that → **~5–6% input savings (~$12/mo at
  60×)**. Not worth the refactor/risk. **Skipped.**

## Model tiering — implemented (opt-in, ships dark)

`tools/llm_client.make_chat_client(tier=...)`:
- `tier="primary"` (default) → `AZURE_OPENAI_DEPLOYMENT` (gpt-5.3-chat). Used for
  every **verdict-critical / security-reasoning** call.
- `tier="cheap"` → `AZURE_OPENAI_DEPLOYMENT_CHEAP` if set, **else falls back to
  primary**. So this changes NOTHING until a cheap deployment is configured.

### Task routing
| Tier | Tasks (files) | Rationale |
|------|---------------|-----------|
| **primary** (gpt-5.3-chat) | L1 triage verdict (`triage.py`), command-line analysis (`cmdline_analysis.py`), IOC insights (`ioc_insights.py`), recommendation (`recommendation.py`), KQL expansion (`kql_expansion.py`), dashboard chat (`dashboard_chat.py`), health ping (`triage_health.py`) | Security decisions — accuracy > cost |
| **cheap** (→ Mini when set) | code decode of unknown codes (`code_explain.py`), advisory extraction (`advisory_extractor.py`), MITRE mapping (`mitre_mapper.py`), report narrative (`routes/reports.py`) | Structured / prose — low risk |

Verdict-critical paths are deliberately kept on the full model.

## Activation runbook (do this only when scaling up)

1. Create a GPT-5 Mini deployment on `lsg-soc-foundry` (it isn't there yet):
   ```
   az cognitiveservices account deployment create -n lsg-soc-foundry -g AI2SC-SOC-AI-Agent \
     --deployment-name gpt-5-mini --model-name gpt-5-mini --model-version <ver> \
     --model-format OpenAI --sku-name GlobalStandard --sku-capacity <tpm>
   ```
2. Point the cheap tier at it:
   ```
   az containerapp update -n soc-platform -g rg-soc-platform \
     --set-env-vars AZURE_OPENAI_DEPLOYMENT_CHEAP=gpt-5-mini
   ```
3. Fire the L1 probe (SCDM-727) + a report/MITRE ticket; confirm the cheap-tier
   tasks still produce sane output. To roll back, just remove the env var.

## Recommended order at scale
1. Model tiering (above) — biggest safe win.
2. Optionally A/B eval gpt-5.3-chat vs GPT-5 Mini on the **verdict path** on real
   historical tickets before considering moving that too. Never assume parity.
3. Input-token reduction (trim RAG/IOC/history payloads) — model-independent lever.
