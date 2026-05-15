"""LLM chat client — env-driven, provider-agnostic.

The platform's report-narrative generator (routes/reports.py) needs an
async chat-completions client. Different deployments back this with
different LLMs:

  * Azure (SOC-Platform on ACA):  Azure OpenAI deployment (gpt-5.2)
  * On-prem (Cisco-OCP):          operator-supplied Ollama or vLLM
                                  (OpenAI-compat REST endpoint)
  * Local dev / CI:               public OpenAI

This module hides those choices behind one factory. The same image works
for every deployment — only the env vars change.

## Detection order (first match wins)

  1. OPENAI_COMPAT_BASE_URL set
        → use AsyncOpenAI with that base_url.
        Use OPENAI_COMPAT_API_KEY if set, else "no-key-needed" (Ollama
        accepts any non-empty token by default).
        Model from OPENAI_COMPAT_MODEL.

  2. AZURE_OPENAI_ENDPOINT set
        → use AsyncAzureOpenAI.
        Key from secret AZURE_OPENAI_API_KEY (env or KV).
        Deployment from AZURE_OPENAI_DEPLOYMENT.
        api_version from AZURE_OPENAI_API_VERSION (default 2024-10-21).

  3. OPENAI_API_KEY set
        → use AsyncOpenAI against public OpenAI.
        Model from OPENAI_MODEL (default gpt-5.2).

If none of the above is set, raises RuntimeError at the first call site
so the failure is loud rather than a silent 401 later.

## Why this shape

The openai SDK's AsyncOpenAI and AsyncAzureOpenAI subclasses share the
same `chat.completions.create(...)` interface. Callers don't have to
care which one they got. Returning `(client, model)` keeps the model
name out of module-level constants — important because two different
provider branches use entirely different model identifiers (an Azure
"deployment name" is unrelated to an Ollama model tag).
"""
import os
import logging

from openai import AsyncAzureOpenAI, AsyncOpenAI

from tools.secrets import get_secret

log = logging.getLogger(__name__)


def make_chat_client() -> tuple[AsyncOpenAI, str]:
    """Return (async_client, default_model_name) for the configured provider.

    The returned client speaks chat.completions.create(...) the same way
    regardless of underlying provider. Caller passes `model=<the_model>`
    where `<the_model>` is the second tuple element.
    """
    # 1. OpenAI-compatible third-party (Ollama, vLLM, anything that exposes /v1/)
    #    OLLAMA_BASE_URL / OLLAMA_DEFAULT_MODEL are accepted as legacy aliases
    #    so existing Cisco-OCP deploys keep working without env changes.
    base_url = (
        os.environ.get("OPENAI_COMPAT_BASE_URL", "").strip()
        or os.environ.get("OLLAMA_BASE_URL", "").strip()
    )
    if base_url:
        api_key = (get_secret("OPENAI_COMPAT_API_KEY") or "no-key-needed")
        model = (
            os.environ.get("OPENAI_COMPAT_MODEL", "").strip()
            or os.environ.get("OLLAMA_DEFAULT_MODEL", "").strip()
            or "qwen2.5:32b"
        )
        log.info("LLM provider: openai-compat at %s, model=%s", base_url, model)
        return AsyncOpenAI(base_url=base_url, api_key=api_key), model

    # 2. Azure OpenAI
    azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
    if azure_endpoint:
        client = AsyncAzureOpenAI(
            azure_endpoint=azure_endpoint,
            api_key=get_secret("AZURE_OPENAI_API_KEY"),
            api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21"),
        )
        model = (
            os.environ.get("AZURE_OPENAI_DEPLOYMENT", "").strip()
            or "gpt-5.2"
        )
        log.info("LLM provider: azure-openai endpoint=%s, deployment=%s",
                 azure_endpoint, model)
        return client, model

    # 3. Public OpenAI (developer / CI fallback)
    api_key = get_secret("OPENAI_API_KEY")
    if api_key:
        model = os.environ.get("OPENAI_MODEL", "").strip() or "gpt-5.2"
        log.info("LLM provider: public openai, model=%s", model)
        return AsyncOpenAI(api_key=api_key), model

    raise RuntimeError(
        "No LLM provider configured. Set ONE of:\n"
        "  - OPENAI_COMPAT_BASE_URL  (for Ollama / vLLM / any OpenAI-compat endpoint)\n"
        "  - AZURE_OPENAI_ENDPOINT   (with AZURE_OPENAI_API_KEY + AZURE_OPENAI_DEPLOYMENT)\n"
        "  - OPENAI_API_KEY          (public OpenAI; dev only)\n"
    )
