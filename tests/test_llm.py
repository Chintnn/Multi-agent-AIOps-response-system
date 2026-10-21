import json
import sys
from types import SimpleNamespace

import pytest
import app.llm as llm_module
from pydantic import ValidationError

from app.llm import ProviderUnavailable, invoke_structured, provider_config
from app.models import (Hypothesis, SpecialistReasoning, TriageAction,
                        TriageDecision, TRIAGE_ACTION_VALUES)


def _decision():
    return TriageDecision(
        assessment="Pool pressure is plausible but not proven.",
        hypotheses=[Hypothesis(statement="Pool exhaustion", rationale="Observed timeouts.",
            supporting_refs=[], contradicting_refs=[], uncertainty="No DB-side metrics.")],
        evidence_gaps=["DB health"], next_agent="metrics",
        investigation_question="Are pool and latency metrics abnormal?",
        expected_information_gain="Measure database pressure.", confidence="moderate",
        decision_rationale="Metrics are the next useful evidence source.",
    )


def _install_fake_groq(monkeypatch, actions, captured=None):
    calls = []
    captured = captured if captured is not None else {}

    class FakeGroq:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs

        @property
        def chat(self):
            def create(**kwargs):
                calls.append(kwargs)
                action = actions.pop(0)
                if isinstance(action, Exception):
                    raise action
                content = action if isinstance(action, str) else json.dumps(action)
                return SimpleNamespace(choices=[SimpleNamespace(
                    message=SimpleNamespace(content=content))])
            return SimpleNamespace(completions=SimpleNamespace(create=create))

    monkeypatch.setitem(sys.modules, "groq", SimpleNamespace(Groq=FakeGroq))
    monkeypatch.setenv("GROQ_API_KEY", "unit-test-secret")
    monkeypatch.setenv("GROQ_MAX_RETRIES", "1")
    return calls, captured


def _assert_closed_strict_objects(node):
    if isinstance(node, dict):
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False
            assert set(node.get("required", [])) == set(node.get("properties", {}))
        assert "default" not in node
        for value in node.values():
            _assert_closed_strict_objects(value)
    elif isinstance(node, list):
        for value in node:
            _assert_closed_strict_objects(value)


def test_valid_structured_response_uses_strict_compatible_schema(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    captured = {}
    calls, _ = _install_fake_groq(monkeypatch, [_decision().model_dump(mode="json")], captured)

    result = invoke_structured("triage", "incident evidence", TriageDecision)

    assert result.next_agent == "metrics"
    assert len(calls) == 1
    response_format = calls[0]["response_format"]
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["strict"] is True
    assert calls[0]["max_tokens"] == 1000
    _assert_closed_strict_objects(response_format["json_schema"]["schema"])
    assert "TriageDecision.$defs.TriageAction.enum=['logs', 'metrics', 'changes', 'remediation', 'more_information', 'escalate']" in calls[0]["messages"][0]["content"]
    assert captured["client_kwargs"]["max_retries"] == 0


def test_canonical_triage_actions_match_pydantic_schema_and_prompt(monkeypatch):
    from app.agents.alert_agent import investigate_alert
    from app.sample_data import sample_incident

    assert tuple(action.value for action in TriageAction) == TRIAGE_ACTION_VALUES
    for action in TriageAction:
        value = _decision().model_dump(mode="python")
        value["next_agent"] = action.value
        assert TriageDecision.model_validate(value).next_agent == action
    with pytest.raises(ValidationError):
        TriageDecision.model_validate({**_decision().model_dump(mode="python"),
                                      "next_agent": "restart_service"})

    captured = {}
    monkeypatch.setattr("app.agents.alert_agent.invoke_structured",
        lambda system, prompt, schema: (captured.update(system=system, schema=schema) or _decision()))
    investigate_alert(sample_incident())
    assert "exactly one of these values" in captured["system"]
    assert ", ".join(TRIAGE_ACTION_VALUES) in captured["system"]
    schema = TriageDecision.model_json_schema()
    action_ref = schema["properties"]["next_agent"]["$ref"].rsplit("/", 1)[-1]
    assert schema["$defs"][action_ref]["enum"] == list(TRIAGE_ACTION_VALUES)


def test_strict_schema_normalizes_optional_and_defaulted_fields(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    calls, _ = _install_fake_groq(monkeypatch, [
        {"summary": "Pool evidence is incomplete.", "hypotheses": [],
         "missing_evidence": [], "follow_up": None, "contradictions": []}
    ])

    invoke_structured("metrics", "values", SpecialistReasoning)

    schema = calls[0]["response_format"]["json_schema"]["schema"]
    assert set(schema["required"]) == set(schema["properties"])
    follow_up = schema["properties"]["follow_up"]
    assert any(option.get("type") == "null" for option in follow_up["anyOf"])
    assert "hypotheses" in schema["required"]


def test_missing_provider_key_is_explicit(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    with pytest.raises(ProviderUnavailable, match="not configured"):
        invoke_structured("planner", "incident", TriageDecision)


def test_malformed_response_is_a_local_parse_failure_without_retry(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    calls, _ = _install_fake_groq(monkeypatch, ["{broken"])

    with pytest.raises(ProviderUnavailable) as caught:
        invoke_structured("planner", "incident", TriageDecision)

    assert caught.value.category == "malformed_json"
    assert caught.value.recovery_attempted is False
    assert len(calls) == 1


def test_local_pydantic_validation_failure_is_distinguished(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    invalid = _decision().model_dump(mode="json")
    invalid["next_agent"] = "not_an_agent"
    calls, _ = _install_fake_groq(monkeypatch, [invalid])

    with pytest.raises(ProviderUnavailable) as caught:
        invoke_structured("planner", "incident", TriageDecision)

    assert caught.value.category == "local_validation"
    assert "not_an_agent" not in str(caught.value)
    assert len(calls) == 1


def test_best_effort_json_generation_error_gets_one_changed_format_recovery(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    class BadRequestError(Exception):
        status_code = 400
        body = {"error": {"code": "json_validate_failed", "message": "Failed to generate JSON"}}

    calls, _ = _install_fake_groq(monkeypatch, [BadRequestError(), _decision().model_dump(mode="json")])
    result = invoke_structured("triage", "incident evidence", TriageDecision)

    assert result.next_agent == "metrics"
    assert len(calls) == 2
    assert calls[0]["response_format"]["type"] == "json_schema"
    assert calls[0]["response_format"]["json_schema"]["strict"] is False
    assert calls[1]["response_format"] == {"type": "json_object"}
    assert "JSON Schema:" in calls[1]["messages"][0]["content"]


def test_recovery_failure_is_bounded_and_recorded(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    class BadRequestError(Exception):
        status_code = 400
        body = {"error": {"code": "json_validate_failed", "message": "Failed to generate JSON"}}

    class InvalidRequestError(Exception):
        status_code = 400
        body = {"error": {"code": "invalid_request", "message": "Request rejected"}}

    calls, _ = _install_fake_groq(monkeypatch, [BadRequestError(), InvalidRequestError()])
    with pytest.raises(ProviderUnavailable) as caught:
        invoke_structured("triage", "incident evidence", TriageDecision)

    assert len(calls) == 2
    assert caught.value.provider_code == "invalid_request"
    assert caught.value.initial_provider_code == "json_validate_failed"
    assert caught.value.initial_status_code == 400
    assert caught.value.recovery_attempted is True
    assert caught.value.response_mode == "json_object_recovery"


def test_permanent_schema_error_is_not_retried(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    class BadRequestError(Exception):
        status_code = 400
        body = {"error": {"code": "invalid_schema", "message": "Schema not supported"}}

    calls, _ = _install_fake_groq(monkeypatch, [BadRequestError()])
    with pytest.raises(ProviderUnavailable) as caught:
        invoke_structured("planner", "incident", TriageDecision)

    assert len(calls) == 1
    assert caught.value.retryable is False
    assert caught.value.recovery_attempted is False


def test_strict_json_generation_error_gets_one_changed_format_recovery(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")

    class BadRequestError(Exception):
        status_code = 400
        body = {"error": {"code": "json_validate_failed", "message": "Generation failed"}}

    from app.llm import get_last_call_metadata
    calls, _ = _install_fake_groq(monkeypatch, [BadRequestError(), _decision().model_dump(mode="json")])
    result = invoke_structured("planner", "incident", TriageDecision)

    assert result.next_agent == "metrics"
    assert len(calls) == 2
    assert calls[0]["response_format"]["json_schema"]["strict"] is True
    assert calls[1]["response_format"] == {"type": "json_object"}
    assert get_last_call_metadata() == {"schema": "TriageDecision",
        "response_mode": "json_object_recovery", "recovery_attempted": True,
        "initial_provider_code": "json_validate_failed", "initial_status_code": 400,
        "retry_attempts": [], "retry_exhausted": False}


def test_recovered_response_with_invalid_action_fails_local_validation_without_more_retries(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")

    class BadRequestError(Exception):
        status_code = 400
        body = {"error": {"code": "json_validate_failed", "message": "Action failed schema check"}}

    invalid = _decision().model_dump(mode="json")
    invalid["next_agent"] = "restart_service"
    calls, _ = _install_fake_groq(monkeypatch, [BadRequestError(), invalid])
    with pytest.raises(ProviderUnavailable) as caught:
        invoke_structured("planner", "incident", TriageDecision)
    assert caught.value.category == "local_validation"
    assert caught.value.recovery_attempted is True
    assert caught.value.response_mode == "json_object_recovery"
    assert len(calls) == 2


def test_retryable_rate_limit_uses_single_bounded_application_policy(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")

    class RateLimitError(Exception):
        status_code = 429
        body = {"error": {"code": "rate_limit_exceeded", "message":
            "Rate limit reached for model org_secret123; try later"}}

    calls, captured = _install_fake_groq(monkeypatch, [RateLimitError(), RateLimitError()])
    sleeps = []
    monkeypatch.setattr("app.llm.time.sleep", sleeps.append)
    with pytest.raises(ProviderUnavailable) as caught:
        invoke_structured("planner", "incident", TriageDecision)

    assert len(calls) == 2
    assert captured["client_kwargs"]["max_retries"] == 0
    assert caught.value.retryable is True
    assert caught.value.retry_exhausted is True
    assert len(caught.value.retry_diagnostics) == 1
    assert "org_secret123" not in str(caught.value)


def test_retry_configuration_is_bounded(monkeypatch):
    monkeypatch.setenv("GROQ_RETRY_MAX_ATTEMPTS", "4")
    with pytest.raises(ProviderUnavailable, match="configuration is invalid"):
        provider_config()


def _http_error(status, code, *, retry_after=None):
    error = type("ProviderError", (Exception,), {})()
    error.status_code = status
    error.body = {"error": {"code": code, "message": "safe test failure"}}
    error.response = SimpleNamespace(headers=(
        {"retry-after": str(retry_after)} if retry_after is not None else {}))
    return error


def test_rate_limit_retry_honors_retry_after_and_recovers(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setenv("GROQ_RETRY_WAIT_BUDGET_SECONDS", "25")
    sleeps = []
    monkeypatch.setattr("app.llm.time.sleep", sleeps.append)
    calls, captured = _install_fake_groq(monkeypatch, [
        _http_error(429, "rate_limit_exceeded", retry_after=21.15), _decision().model_dump(mode="json")])
    result = invoke_structured("planner", "incident", TriageDecision)
    from app.llm import get_last_call_metadata
    assert result.next_agent == "metrics"
    assert sleeps == [21.15]
    assert captured["client_kwargs"]["max_retries"] == 0
    assert get_last_call_metadata()["retry_attempts"] == [{"attempt": 1,
        "status_code": 429, "provider_code": "rate_limit_exceeded",
        "delay_seconds": 21.15, "delay_source": "retry_after"}]
    assert len(calls) == 2


def test_rate_limit_without_hint_uses_bounded_jitter(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setattr("app.llm.random.uniform", lambda low, high: 0.4)
    sleeps = []
    monkeypatch.setattr("app.llm.time.sleep", sleeps.append)
    calls, _ = _install_fake_groq(monkeypatch, [
        _http_error(429, "rate_limit_exceeded"), _decision().model_dump(mode="json")])
    invoke_structured("planner", "incident", TriageDecision)
    assert sleeps == [0.4]
    assert len(calls) == 2


def test_transient_server_error_retries_once(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setattr("app.llm.random.uniform", lambda low, high: 0.1)
    monkeypatch.setattr("app.llm.time.sleep", lambda delay: None)
    calls, _ = _install_fake_groq(monkeypatch, [
        _http_error(503, "server_error"), _decision().model_dump(mode="json")])
    assert invoke_structured("planner", "incident", TriageDecision).next_agent == "metrics"
    assert len(calls) == 2


def test_rate_limit_hint_over_budget_does_not_wait_or_retry(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setenv("GROQ_RETRY_WAIT_BUDGET_SECONDS", "1")
    sleeps = []
    monkeypatch.setattr("app.llm.time.sleep", sleeps.append)
    calls, _ = _install_fake_groq(monkeypatch, [_http_error(429, "rate_limit_exceeded", retry_after=4)])
    with pytest.raises(ProviderUnavailable) as caught:
        invoke_structured("planner", "incident", TriageDecision)
    assert len(calls) == 1 and sleeps == []
    assert caught.value.retry_exhausted is True
