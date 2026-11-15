"""Episode-local fetch evidence captured from actual runtime executions.

Tool-role transcripts and mvg_sources include pasted or guard-generated text in
some hosts. They cannot establish origin. Capture successful raw runtime returns
instead, only for read-only calls, without modifying the shared runtime or
reading provenance from data.
"""
from contextvars import ContextVar
from functools import wraps

from ..fetch_boundary import raw_tool_texts

_CURRENT = ContextVar("spillway_executed_fetch_texts", default=None)


def current_fetch_tool_texts():
    state = _CURRENT.get()
    return tuple(state) if state is not None else ()


class _FetchRuntimeProxy:
    def __init__(self, runtime, texts, read_only):
        self._runtime, self._texts, self._read_only = runtime, texts, read_only

    def __getattr__(self, name):
        return getattr(self._runtime, name)

    def run_function(self, env, name, args, *extra, **kwargs):
        result = self._runtime.run_function(env, name, args, *extra, **kwargs)
        if isinstance(result, (tuple, list)) and len(result) == 2:
            raw, error = result
            if not error and self._read_only(name):
                self._texts.extend(raw_tool_texts(raw))
        return result


def install_fetch_capture(gate, enabled):
    cls = getattr(gate, "SchemaProvenanceToolsExecutor", None)
    if cls is None:
        return False
    original = getattr(cls.query, "_spw_fetch_original_query", cls.query)
    if not enabled:
        if hasattr(cls.query, "_spw_fetch_original_query"):
            cls.query = original
        return False
    generation = object()

    @wraps(original)
    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        task = gate.m30.first_user_task(messages) if messages else None
        texts = getattr(self, "_spw_fetch_tool_texts", None)
        if (texts is None or getattr(self, "_spw_fetch_generation", None) is not generation
                or task != getattr(self, "_spw_fetch_task", None)
                or not any(message.get("role") == "tool" for message in messages or ())):
            texts = []
            self._spw_fetch_tool_texts, self._spw_fetch_task = texts, task
            self._spw_fetch_generation = generation
        # Match the reference executor's episode lifecycle. Pipeline elements
        # may copy message dictionaries; transcript object identity is not an
        # execution/session boundary. A fresh instance has no captured evidence.
        proxy = _FetchRuntimeProxy(runtime, texts, gate.m30.tool_is_read_only) if runtime is not None else None
        token = _CURRENT.set(texts)
        before = len(texts)
        try:
            result = original(self, query, proxy if proxy is not None else runtime, env, messages, extra_args)
        except Exception:
            del texts[before:]
            raise
        finally:
            _CURRENT.reset(token)
        if proxy is not None and isinstance(result, tuple) and len(result) >= 2 and result[1] is proxy:
            result = (result[0], runtime, *result[2:])
        return result

    query._spw_fetch_original_query = original
    cls.query = query
    return True
