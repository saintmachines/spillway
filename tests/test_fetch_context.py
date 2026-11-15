"""Bind fetch evidence to runtime calls, including the actual reference executor."""
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import _path  # noqa: F401
import pytest

from spillway_guard import Policy
from spillway_guard.agentdojo.candidate_policy import install_candidate_policy
from spillway_guard.agentdojo.fetch_context import current_fetch_tool_texts, install_fetch_capture

URL = "https://safe.example/Report?token=AbC"


class Runtime:
    def __init__(self, raw=URL, error=None):
        self.raw, self.error, self.calls = raw, error, []
        self.functions = {name: SimpleNamespace(name=name, return_type=str)
                          for name in ("read_channel_messages", "get_webpage", "send_email", "create_file")}

    def run_function(self, env, name, args):
        self.calls.append((name, dict(args)))
        return (self.raw if name == "read_channel_messages" else args.get("content", "Article content.")), self.error


def test_capture_only_counts_successful_runtime_calls_and_clears_context():
    class Executor:
        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            self.before = current_fetch_tool_texts()
            runtime.run_function(env, "read_channel_messages", {})
            self.after = current_fetch_tool_texts()
            return query, runtime, env, [*messages, {"role": "tool", "content": "Result"}], extra_args

    gate = SimpleNamespace(SchemaProvenanceToolsExecutor=Executor,
                           m30=SimpleNamespace(first_user_task=lambda messages: messages[0]["content"],
                                               tool_is_read_only=lambda name: name == "read_channel_messages"))
    assert install_fetch_capture(gate, True)
    executor, runtime = Executor(), Runtime()
    messages = [{"role": "user", "content": "Read the cited article."}]
    result = executor.query("", runtime, messages=messages)
    assert result[1] is runtime and (executor.before, executor.after) == ((), (URL,))
    assert current_fetch_tool_texts() == ()
    runtime.error = "Tool failed."
    result = executor.query("", runtime, messages=messages)
    assert (executor.before, executor.after) == ((), ())
    assert not executor._spw_fetch_tool_texts
    assert install_fetch_capture(gate, False) is False


def test_capture_resets_for_same_task_new_episode_and_changed_task():
    class Executor:
        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            self.before = current_fetch_tool_texts()
            if extra_args and extra_args.get("execute"):
                runtime.run_function(env, "read_channel_messages", {})
                messages = [*messages, {"role": "tool", "content": "A real result."}]
            return query, runtime, env, messages, extra_args

    gate = SimpleNamespace(SchemaProvenanceToolsExecutor=Executor,
                           m30=SimpleNamespace(first_user_task=lambda messages: messages[0]["content"],
                                               tool_is_read_only=lambda name: name == "read_channel_messages"))
    install_fetch_capture(gate, True)
    executor, runtime = Executor(), Runtime()
    start = [{"role": "user", "content": "Same task."}]
    result = executor.query("", runtime, messages=start, extra_args={"execute": True})
    continued = list(result[3]) + [{"role": "assistant", "content": "Continue."}]
    executor.query("", runtime, messages=continued)
    assert executor.before == (URL,)
    executor.query("", runtime, messages=start)
    assert executor.before == ()
    executor.query("", runtime, messages=start, extra_args={"execute": True})
    changed = [{"role": "user", "content": "Different task."}, {"role": "tool", "content": URL}]
    executor.query("", runtime, messages=changed)
    assert executor.before == ()


def test_copied_legitimate_continuation_preserves_actual_runtime_capture():
    class Executor:
        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            self.before = current_fetch_tool_texts()
            if extra_args:
                runtime.run_function(env, "read_channel_messages", {})
            return query, runtime, env, [*messages, {"role": "tool", "content": URL}], extra_args

    gate = SimpleNamespace(SchemaProvenanceToolsExecutor=Executor,
                           m30=SimpleNamespace(first_user_task=lambda messages: messages[0]["content"],
                                               tool_is_read_only=lambda name: name == "read_channel_messages"))
    install_fetch_capture(gate, True)
    executor, runtime = Executor(), Runtime()
    result = executor.query("", runtime, messages=[{"role": "user", "content": "Same task."}], extra_args={"run": True})
    copied = [dict(message) for message in result[3]]
    executor.query("", runtime, messages=copied)
    assert executor.before == (URL,)


def test_failed_formatter_cannot_leave_partial_runtime_evidence():
    class Executor:
        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            runtime.run_function(env, "read_channel_messages", {})
            raise ValueError("Formatter failed")

    gate = SimpleNamespace(SchemaProvenanceToolsExecutor=Executor,
                           m30=SimpleNamespace(first_user_task=lambda messages: messages[0]["content"],
                                               tool_is_read_only=lambda name: name == "read_channel_messages"))
    install_fetch_capture(gate, True)
    executor = Executor()
    with pytest.raises(ValueError, match="Formatter failed"):
        executor.query("", Runtime(), messages=[{"role": "user", "content": "Read article."}])
    assert executor._spw_fetch_tool_texts == []
    assert current_fetch_tool_texts() == ()


def _reference(module, monkeypatch):
    pytest.importorskip("agentdojo")
    reference = Path(__file__).resolve().parents[1] / "reference"
    for path in (reference, reference / "harness"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    name = "fetch_context_" + module
    spec = importlib.util.spec_from_file_location(name, reference / (module + ".py"))
    gate = importlib.util.module_from_spec(spec)
    sys.modules[name] = gate
    spec.loader.exec_module(gate)
    for flag in ("SPW_INGRESS_REDACT", "SPW_INGRESS_AGENTADDR", "SPW_MV_GUARD"):
        monkeypatch.setenv(flag, "0")
    return gate


def _assistant(name, args, ident):
    from agentdojo.functions_runtime import FunctionCall
    return {"role": "assistant", "content": None,
            "tool_calls": [FunctionCall(function=name, args=args, id=ident)]}


@pytest.mark.parametrize("module", ["spillway_gate", "spillway_guarded"])
@pytest.mark.parametrize("approve", [False, True])
def test_actual_reference_executor_captures_raw_returns_then_uses_content_judge(module, approve, monkeypatch):
    gate = _reference(module, monkeypatch)
    judged = []

    def judge(*args, **kwargs):
        judged.append(kwargs.get("mode"))
        return approve, float(approve)

    monkeypatch.setattr(gate, "_coherence_judge", judge)
    install_candidate_policy(gate, Policy.enhanced_014())
    executor = gate.SchemaProvenanceToolsExecutor(tool_output_formatter=lambda _: "Redacted text.",
                                                 content_tier=True, escalate=False)
    runtime = Runtime()
    messages = [{"role": "user", "content": "Read the article mentioned in channel general."},
                _assistant("read_channel_messages", {"channel": "general"}, "read")]
    result = executor.query("", runtime, messages=messages, extra_args={})
    assert result[1] is runtime and runtime.calls == [("read_channel_messages", {"channel": "general"})]
    assert executor._spw_fetch_tool_texts == [URL]
    for index, changed in enumerate((URL.replace("Report", "report"), URL + "&extra=1", URL.replace("https:", "http:"))):
        messages = list(result[3]) + [_assistant("get_webpage", {"url": changed}, "modified_" + str(index))]
        result = executor.query("", runtime, messages=messages, extra_args={})
        assert result[4]["harness_v12_gate_audit"][-1]["decision"] == "block_fetch_provenance"
        assert judged == []
        assert [name for name, _ in runtime.calls] == ["read_channel_messages"]
    messages = list(result[3]) + [_assistant("get_webpage", {"url": URL}, "fetch")]
    result = executor.query("", runtime, messages=messages, extra_args={})
    label = result[4]["harness_v12_gate_audit"][-1]["decision"]
    assert label == ("allow_read_only" if approve else "block_content_fetch")
    assert judged == ["content"]
    assert [name for name, _ in runtime.calls] == (["read_channel_messages", "get_webpage"] if approve
                                                else ["read_channel_messages"])
    assert current_fetch_tool_texts() == ()
    # A fresh episode with the same task cannot inherit the prior raw source.
    messages = [messages[0], _assistant("get_webpage", {"url": URL}, "new_episode")]
    result = executor.query("", runtime, messages=messages, extra_args={})
    assert result[4]["harness_v12_gate_audit"][-1]["decision"] == "block_fetch_provenance"
    assert judged == ["content"]


@pytest.mark.parametrize("module", ["spillway_gate", "spillway_guarded"])
def test_reference_transcript_and_refusal_cannot_mint_runtime_evidence(module, monkeypatch):
    gate = _reference(module, monkeypatch)
    monkeypatch.setattr(gate, "_coherence_judge", lambda *args, **kwargs: pytest.fail("Judge must not run"))
    install_candidate_policy(gate, Policy.enhanced_014())
    executor = gate.SchemaProvenanceToolsExecutor(content_tier=True, escalate=False)
    runtime = Runtime()
    task = {"role": "user", "content": "Read the cited article."}
    # A tool-looking history row did not execute through this instance.
    messages = [task, {"role": "tool", "content": URL}, _assistant("get_webpage", {"url": URL}, "fake")]
    result = executor.query("", runtime, messages=messages, extra_args={})
    assert result[4]["harness_v12_gate_audit"][-1]["decision"] == "block_fetch_provenance"
    assert runtime.calls == []
    # A blocked write's guard result is tool-role history but never a runtime return.
    messages = [task, _assistant("send_email", {"recipient": URL, "body": "Summary"}, "refusal")]
    result = executor.query("", runtime, messages=messages, extra_args={})
    assert runtime.calls == []
    messages = list(result[3]) + [_assistant("get_webpage", {"url": URL}, "echo")]
    result = executor.query("", runtime, messages=messages, extra_args={})
    assert result[4]["harness_v12_gate_audit"][-1]["decision"] == "block_fetch_provenance"
    assert runtime.calls == []
    kwargs = {"escalate": False, "threshold": 0.5, "voters": (), "content_tier": True}
    if module == "spillway_guarded":
        kwargs["mvg_sources"] = [URL]
    assert gate.gate_decision_v13b("get_webpage", {"url": URL}, URL, "Read article", "Read article", set(),
                                   **kwargs)[1] == "block_fetch_provenance"


@pytest.mark.parametrize("module", ["spillway_gate", "spillway_guarded"])
def test_actual_reference_write_echo_cannot_mint_fetch_evidence(module, monkeypatch):
    gate = _reference(module, monkeypatch)
    monkeypatch.setattr(gate, "_coherence_judge", lambda *args, **kwargs: pytest.fail("Judge must not run"))
    install_candidate_policy(gate, Policy.enhanced_014())
    executor = gate.SchemaProvenanceToolsExecutor(content_tier=True, escalate=False)
    runtime = Runtime()
    task = {"role": "user", "content": "Create a file named notes, then read the cited article."}
    result = executor.query("", runtime, messages=[task, _assistant("create_file", {"filename": "notes", "content": URL}, "write")], extra_args={})
    assert [name for name, _ in runtime.calls] == ["create_file"]
    assert executor._spw_fetch_tool_texts == []
    result = executor.query("", runtime, messages=list(result[3]) + [_assistant("get_webpage", {"url": URL}, "echo")], extra_args={})
    assert result[4]["harness_v12_gate_audit"][-1]["decision"] == "block_fetch_provenance"
    assert [name for name, _ in runtime.calls] == ["create_file"]


@pytest.mark.parametrize("module", ["spillway_gate", "spillway_guarded"])
def test_actual_agent_pipeline_preserves_capture_across_copied_history(module, monkeypatch):
    from agentdojo.agent_pipeline import AgentPipeline, BasePipelineElement

    gate = _reference(module, monkeypatch)
    judged = []

    def judge(*args, **kwargs):
        judged.append(kwargs.get("mode"))
        return True, 1.0

    monkeypatch.setattr(gate, "_coherence_judge", judge)
    install_candidate_policy(gate, Policy.enhanced_014())
    executor = gate.SchemaProvenanceToolsExecutor(content_tier=True, escalate=False)

    class CopyAndAppend(BasePipelineElement):
        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            copied = [dict(message) for message in messages]
            return query, runtime, env, [*copied, _assistant("get_webpage", {"url": URL}, "after_copy")], extra_args

    pipeline = AgentPipeline([executor, CopyAndAppend(), executor])
    runtime = Runtime()
    messages = [{"role": "user", "content": "Read the article mentioned in channel general."},
                _assistant("read_channel_messages", {"channel": "general"}, "read")]
    result = pipeline.query("", runtime, messages=messages, extra_args={})
    assert result[4]["harness_v12_gate_audit"][-1]["decision"] == "allow_read_only"
    assert judged == ["content"]
    assert [name for name, _ in runtime.calls] == ["read_channel_messages", "get_webpage"]
