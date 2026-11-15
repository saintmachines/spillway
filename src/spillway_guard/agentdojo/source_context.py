"""Task-local exact source evidence, independent from the R5 sensitive index."""
from contextlib import contextmanager
from contextvars import ContextVar

_CURRENT_SOURCE = ContextVar("spillway_named_source_state", default=None)


def current_named_source_state():
    return _CURRENT_SOURCE.get()


@contextmanager
def named_source_context(state):
    token = _CURRENT_SOURCE.set(state)
    try:
        yield
    finally:
        _CURRENT_SOURCE.reset(token)


def install_named_source_capture(gate, enabled, contracts=None):
    from .sensitive_context import install_source_capture
    return install_source_capture(gate, enabled, contracts)
