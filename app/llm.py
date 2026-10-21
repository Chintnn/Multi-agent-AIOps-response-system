"""Centralized Groq provider boundary with explicit failure semantics."""
from __future__ import annotations

import json
import email.utils
import os
import random
import re
import time
from contextvars import ContextVar
from copy import deepcopy
from typing import TypeVar

from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError

load_dotenv()
T = TypeVar("T", bound=BaseModel)
STRICT_JSON_SCHEMA_MODELS = {
    "openai/gpt-oss-20b", "openai/gpt-oss-120b", "qwen/qwen3.8-27b",
}
_LAST_CALL_METADATA: ContextVar[dict[str, object] | None] = ContextVar(
    "last_structured_call_metadata", default=None)


def clear_last_call_metadata() -> None:
    """Clear context-local call metadata before an agent invocation."""
    _LAST_CALL_METADATA.set(None)


def get_last_call_metadata() -> dict[str, object] | None:
    """Return safe mode/recovery metadata for tracing; never includes prompt text."""
    return _LAST_CALL_METADATA.get()


class ProviderUnavailable(RuntimeError):
    """The configured LLM provider cannot be used for this decision."""

    def __init__(self, message: str, *, category: str = "configuration",
                 status_code: int | None = None, provider_code: str | None = None,
                 retryable: bool = False, operation: str = "chat.completions.create",
                 recovery_attempted: bool = False, response_mode: str | None = None,
                 initial_provider_code: str | None = None,
                 initial_status_code: int | None = None,
                 retry_diagnostics: list[dict[str, object]] | None = None,
                 retry_exhausted: bool = False):
        super().__init__(message)
        self.category = category
        self.status_code = status_code
        self.provider_code = provider_code
        self.retryable = retryable
        self.operation = operation
        self.recovery_attempted = recovery_attempted
        self.response_mode = response_mode
        self.initial_provider_code = initial_provider_code
        self.initial_status_code = initial_status_code
        self.retry_diagnostics = retry_diagnostics or []
        self.retry_exhausted = retry_exhausted


def _safe_provider_message(exc: Exception) -> str | None:
    """Extract only the provider's error message, never request/response metadata."""
    body = getattr(exc, "body", None)
    error = body.get("error") if isinstance(body, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    if not isinstance(message, str):
        return None
    api_key = os.getenv("GROQ_API_KEY")
    if api_key:
        message = message.replace(api_key, "[REDACTED]")
    message = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", message)
    message = re.sub(r"(?i)(api[_ -]?key|authorization|token)\s*[:=]\s*[^\s,;]+",
                     r"\1=[REDACTED]", message)
    message = re.sub(r"\borg_[A-Za-z0-9]+\b", "[ORG]", message)
    message = re.sub(r"https?://\S+", "[URL]", message)
    return " ".join(message.split())[:400]


def provider_config() -> dict[str, object]:
    try:
        timeout = float(os.getenv("GROQ_TIMEOUT_SECONDS", "20"))
        attempts = int(os.getenv("GROQ_RETRY_MAX_ATTEMPTS", "2"))
        wait_budget = float(os.getenv("GROQ_RETRY_WAIT_BUDGET_SECONDS", "25"))
        base_delay = float(os.getenv("GROQ_RETRY_BASE_DELAY_SECONDS", "0.5"))
        completion_tokens = int(os.getenv("GROQ_MAX_COMPLETION_TOKENS", "1000"))
        temperature = float(os.getenv("GROQ_TEMPERATURE", "0"))
        if (timeout <= 0 or not 1 <= attempts <= 3 or not 0 <= wait_budget <= 30
                or not 0 <= base_delay <= 2 or not 256 <= completion_tokens <= 1800
                or not 0 <= temperature <= 2):
            raise ValueError
        return {"model": os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
                "timeout": timeout, "max_retries": 0, "retry_max_attempts": attempts,
                "retry_wait_budget_seconds": wait_budget,
                "retry_base_delay_seconds": base_delay,
                "max_completion_tokens": completion_tokens,
                "temperature": temperature}
    except ValueError as exc:
        raise ProviderUnavailable("LLM provider configuration is invalid") from exc


def _strict_provider_schema(schema: type[BaseModel]) -> dict:
    """Make Pydantic's schema satisfy Groq strict-mode required-field rules."""
    provider_schema = deepcopy(schema.model_json_schema())

    def normalize(node: object) -> None:
        if isinstance(node, dict):
            node.pop("default", None)
            properties = node.get("properties")
            if node.get("type") == "object" or isinstance(properties, dict):
                properties = properties or {}
                node["required"] = list(properties)
                node["additionalProperties"] = False
            for value in node.values():
                normalize(value)
        elif isinstance(node, list):
            for value in node:
                normalize(value)

    normalize(provider_schema)
    return provider_schema


def _provider_error(exc: Exception, *, recovery_attempted: bool,
                    response_mode: str,
                    initial_provider_code: str | None = None,
                    initial_status_code: int | None = None,
                    retry_diagnostics: list[dict[str, object]] | None = None,
                    retry_exhausted: bool = False) -> ProviderUnavailable:
    status_code = getattr(exc, "status_code", None)
    body = getattr(exc, "body", None)
    provider_error = body.get("error") if isinstance(body, dict) else None
    provider_code = provider_error.get("code") if isinstance(provider_error, dict) else None
    transient_status = status_code in {408, 429} or (
        isinstance(status_code, int) and status_code >= 500)
    transient_type = type(exc).__name__ in {"APIConnectionError", "APITimeoutError", "RateLimitError"}
    detail = _safe_provider_message(exc)
    description = f"Groq {type(exc).__name__}"
    if status_code is not None:
        description += f" HTTP {status_code}"
    if provider_code:
        description += f" code={str(provider_code)[:80]}"
    if detail:
        description += f": {detail}"
    return ProviderUnavailable(description, category=type(exc).__name__,
        status_code=status_code if isinstance(status_code, int) else None,
        provider_code=str(provider_code)[:80] if provider_code is not None else None,
        retryable=bool(transient_status or transient_type),
        recovery_attempted=recovery_attempted, response_mode=response_mode,
        initial_provider_code=initial_provider_code,
        initial_status_code=initial_status_code,
        retry_diagnostics=retry_diagnostics, retry_exhausted=retry_exhausted)


def _retry_hint_seconds(exc: Exception) -> float | None:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if not headers:
        return None
    value = headers.get("retry-after") or headers.get("Retry-After")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        try:
            parsed = email.utils.parsedate_to_datetime(str(value))
            return max(0.0, parsed.timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return None


def _create_with_retries(client, request: dict, config: dict[str, object],
                         response_mode: str) -> tuple[object, list[dict[str, object]]]:
    """Retry only transient provider failures, bounded by attempts and total sleep."""
    attempts = int(config["retry_max_attempts"])
    wait_budget = float(config["retry_wait_budget_seconds"])
    base_delay = float(config["retry_base_delay_seconds"])
    waited = 0.0
    diagnostics: list[dict[str, object]] = []
    for attempt in range(1, attempts + 1):
        try:
            response = client.chat.completions.create(**request)
            return response, diagnostics
        except Exception as exc:
            failure = _provider_error(exc, recovery_attempted=False,
                                      response_mode=response_mode)
            if not failure.retryable or attempt >= attempts:
                failure.retry_diagnostics = diagnostics
                failure.retry_exhausted = failure.retryable and attempt >= attempts
                raise failure from None
            hint = _retry_hint_seconds(exc)
            delay = hint if hint is not None else random.uniform(
                0.0, min(2.0, base_delay * (2 ** (attempt - 1))))
            if waited + delay > wait_budget:
                failure.retry_diagnostics = diagnostics
                failure.retry_exhausted = True
                raise failure from None
            diagnostics.append({"attempt": attempt, "status_code": failure.status_code,
                "provider_code": failure.provider_code,
                "delay_seconds": round(delay, 3),
                "delay_source": "retry_after" if hint is not None else "exponential_jitter"})
            time.sleep(delay)
            waited += delay
    raise AssertionError("retry loop exited unexpectedly")


def _request_messages(system_prompt: str, user_prompt: str, schema: type[BaseModel],
                      *, recovery: bool = False) -> list[dict[str, str]]:
    schema_json = schema.model_json_schema()
    field_groups = {schema.__name__: schema_json.get("properties", {})}
    field_groups.update({name: value.get("properties", {})
                         for name, value in schema_json.get("$defs", {}).items()
                         if isinstance(value, dict)})
    fields = "; ".join(f"{name}: {', '.join(properties)}"
                        for name, properties in field_groups.items())
    enum_fields: list[str] = []

    def collect_enums(node: object, path: str) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("enum"), list):
                enum_fields.append(f"{path}.enum={node['enum']}")
            for name, value in node.items():
                collect_enums(value, f"{path}.{name}" if path else name)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                collect_enums(value, f"{path}[{index}]")

    collect_enums(schema_json, schema.__name__)
    instruction = (
        f" Return one object with every field present ({fields}). Use empty arrays when a list has no values, "
        "null only for nullable fields, and only these declared enum values: "
        + ("; ".join(enum_fields) if enum_fields else "none")
        + ". Keep the summary under 60 words, other text fields concise, return at most two hypotheses "
        "and at most five entries in other lists. Do not include prose or extra keys."
    )
    if recovery:
        # JSON mode has no provider-side schema constraint, so give it the schema
        # explicitly and still validate the result locally before using it.
        instruction += " JSON Schema: " + json.dumps(schema_json, separators=(",", ":"))
    return [
        {"role": "system", "content": system_prompt + instruction},
        {"role": "user", "content": user_prompt},
    ]


def _decode_and_validate(content: str | None, schema: type[T], *,
                         recovery_attempted: bool, response_mode: str) -> T:
    if not content:
        raise ProviderUnavailable("Provider returned an empty response", category="empty_response",
            recovery_attempted=recovery_attempted, response_mode=response_mode)
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        raise ProviderUnavailable(f"Provider returned malformed JSON for {schema.__name__}",
            category="malformed_json", recovery_attempted=recovery_attempted,
            response_mode=response_mode) from None
    try:
        return schema.model_validate(payload)
    except ValidationError:
        # Do not include validation input values: incident content can be sensitive.
        raise ProviderUnavailable(f"Provider JSON failed local {schema.__name__} validation",
            category="local_validation", recovery_attempted=recovery_attempted,
            response_mode=response_mode) from None


def invoke_structured(system_prompt: str, user_prompt: str, schema: type[T]) -> T:
    """Request strict structured output, with one changed-format schema-error recovery."""
    clear_last_call_metadata()
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or api_key == "your_key_here":
        raise ProviderUnavailable("GROQ_API_KEY is not configured")
    try:
        from groq import Groq
    except ImportError as exc:
        raise ProviderUnavailable("Groq SDK is not installed") from exc

    config = provider_config()
    # All retry policy lives here. Keeping SDK retries disabled prevents hidden,
    # multiplicative waits and makes worker duration and traces predictable.
    client = Groq(api_key=api_key, timeout=config["timeout"], max_retries=0)
    model = str(config["model"])
    strict_mode = model in STRICT_JSON_SCHEMA_MODELS
    provider_schema = (_strict_provider_schema(schema) if strict_mode
                       else schema.model_json_schema())
    response_mode = "json_schema_strict" if strict_mode else "json_schema_best_effort"
    request = {
        "model": model,
        "temperature": config["temperature"],
        "max_tokens": int(config["max_completion_tokens"]),
        "response_format": {"type": "json_schema", "json_schema": {
            "name": schema.__name__.lower(),
            "strict": strict_mode,
            "schema": provider_schema,
        }},
        "messages": _request_messages(system_prompt, user_prompt, schema),
    }
    recovered = False
    retry_diagnostics: list[dict[str, object]] = []
    try:
        response, retry_diagnostics = _create_with_retries(client, request, config, response_mode)
    except ProviderUnavailable as exc:
        provider_code = exc.provider_code
        initial_status_code = exc.status_code
        # A provider can reject generation against an otherwise valid schema.
        # Try one changed-format request and validate it locally; never repeat
        # the same request or retry other permanent 400 errors.
        can_recover = (exc.status_code == 400 and provider_code == "json_validate_failed")
        if not can_recover:
            _LAST_CALL_METADATA.set({"schema": schema.__name__,
                "response_mode": response_mode, "recovery_attempted": False,
                "provider_code": exc.provider_code, "status_code": exc.status_code,
                "retry_attempts": retry_diagnostics,
                "retry_exhausted": exc.retry_exhausted})
            raise
        recovered = True
        recovery_request = dict(request)
        recovery_request["response_format"] = {"type": "json_object"}
        recovery_request["messages"] = _request_messages(
            system_prompt + " The previous output did not satisfy the schema; follow this schema exactly.",
            user_prompt, schema, recovery=True)
        response_mode = "json_object_recovery"
        try:
            response, recovery_retries = _create_with_retries(
                client, recovery_request, config, response_mode)
            retry_diagnostics.extend(recovery_retries)
        except ProviderUnavailable as failure:
            failure.recovery_attempted = True
            failure.initial_provider_code = str(provider_code)
            failure.initial_status_code = initial_status_code
            _LAST_CALL_METADATA.set({"schema": schema.__name__,
                "response_mode": response_mode, "recovery_attempted": True,
                "provider_code": failure.provider_code, "status_code": failure.status_code,
                "initial_provider_code": failure.initial_provider_code,
                "initial_status_code": failure.initial_status_code,
                "retry_attempts": failure.retry_diagnostics,
                "retry_exhausted": failure.retry_exhausted})
            raise
    content = response.choices[0].message.content
    try:
        result = _decode_and_validate(content, schema, recovery_attempted=recovered,
                                      response_mode=response_mode)
    except ProviderUnavailable as failure:
        _LAST_CALL_METADATA.set({"schema": schema.__name__,
            "response_mode": response_mode, "recovery_attempted": recovered,
            "provider_code": failure.provider_code, "status_code": failure.status_code,
            "category": failure.category,
            "initial_provider_code": "json_validate_failed" if recovered else None,
            "initial_status_code": 400 if recovered else None,
            "retry_attempts": retry_diagnostics,
            "retry_exhausted": False})
        raise
    _LAST_CALL_METADATA.set({"schema": schema.__name__, "response_mode": response_mode,
                             "recovery_attempted": recovered,
                             "retry_attempts": retry_diagnostics,
                             "retry_exhausted": False,
                             "initial_provider_code": "json_validate_failed" if recovered else None,
                             "initial_status_code": 400 if recovered else None})
    return result


def llm_available() -> bool:
    return bool(os.getenv("GROQ_API_KEY")) and os.getenv("GROQ_API_KEY") != "your_key_here"


def ask_llm(system_prompt: str, user_prompt: str, model: str | None = None) -> str | None:
    """Compatibility shim for older callers; new agents use structured output."""
    if model:
        os.environ.setdefault("GROQ_MODEL", model)
    class TextResult(BaseModel):
        text: str
    try:
        return invoke_structured(system_prompt, user_prompt, TextResult).text
    except ProviderUnavailable:
        return None
