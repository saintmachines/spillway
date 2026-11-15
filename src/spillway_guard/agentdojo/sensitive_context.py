"""One composable executor capture for sensitive values and exact source reads.

R5 reads the original raw formatter. Source provenance intercepts actual
runtime.run_function(name,args)->(raw,error) calls without aligning text deltas.
Neither modifies the shared runtime object or trusts metadata inside raw data.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from types import SimpleNamespace

from ..sensitive import SensitiveIndex
from ..short_lineage import CreatedObjectReceipts, CreationContracts, created_resource_context
from ..source_known import NamedSourceIndex, SourceContracts
from .source_context import named_source_context

_CURRENT = ContextVar("spillway_sensitive_source_state", default=None)


def current_sensitive_state():
    return _CURRENT.get()


@contextmanager
def sensitive_source_context(state):
    token = _CURRENT.set(state)
    try:
        yield
    finally:
        _CURRENT.reset(token)


class _SourceRuntimeProxy:
    def __init__(self, runtime, state, task, contracts, roles, *, created=None, identities=None):
        self._runtime, self._state, self._task = runtime, state, task
        self._contracts, self._roles = contracts, roles
        self._created, self._identities = created, identities

    def __getattr__(self, name):
        return getattr(self._runtime, name)

    def run_function(self, env, name, args, *extra, **kwargs):
        actual_args = dict(args or {})
        try:
            result = self._runtime.run_function(env, name, args, *extra, **kwargs)
        except Exception:
            if self._created is not None:
                self._created.discard(name, actual_args)
            raise
        if isinstance(result, (tuple, list)) and len(result) == 2:
            raw, error = result
            if self._created is not None:
                if error or self._identities is None:
                    self._created.discard(name, actual_args)
                else:
                    self._created.observe(name, actual_args, raw, self._identities())
            if not error and self._state is not None and self._roles.tool_is_read_only(name):
                try:
                    proof = self._contracts.proof(name, actual_args, raw,
                                                  context={"runtime": self._runtime, "env": env})
                    self._state.observe(name, actual_args, raw, self._task, proof=proof, lexicon=self._roles)
                except Exception as exc:
                    # A failed attestor/capture grants no evidence. Do not replace
                    # the executed tool result or print untrusted exception data.
                    if len(self._state.unavailable) < 16:
                        self._state.unavailable.append(type(exc).__name__)
        elif self._created is not None:
            self._created.discard(name, actual_args)
        return result


def _configure(gate, kind, enabled, contracts=None, creation_contracts=None):
    if contracts is not None and not isinstance(contracts, SourceContracts):
        raise TypeError("source_contracts must be SourceContracts, never fields from a document")
    if creation_contracts is not None and not isinstance(creation_contracts, CreationContracts):
        raise TypeError("creation_contracts must be app-owned CreationContracts")
    cls = getattr(gate, "SchemaProvenanceToolsExecutor", None)
    if cls is None:
        return False
    config = getattr(cls, "_spw_raw_capture_config", None)
    if config is None:
        if not enabled:
            return False
        config = {"sensitive": False, "source": False, "resource": False, "contracts": SourceContracts(),
                  "creation_contracts": CreationContracts()}
        original_init, original_query = cls.__init__, cls.query
        roles = SimpleNamespace(tool_is_read_only=lambda name: gate.m30.tool_is_read_only(name),
                                is_fetch_arg=lambda key: gate._is_fetch_arg(key))

        def current_config():
            return getattr(cls, "_spw_raw_capture_config", {})

        def initialize(self):
            if not hasattr(self, "_spw_sensitive_state"):
                self._spw_sensitive_state = SensitiveIndex(complete=True)
            if not hasattr(self, "_spw_named_source_state"):
                self._spw_named_source_state = NamedSourceIndex()
            if not hasattr(self, "_spw_capture_task"):
                self._spw_capture_task = None
            if not hasattr(self, "_spw_created_resources"):
                self._spw_created_resources = CreatedObjectReceipts()
            self._spw_created_resources.configure(current_config().get("creation_contracts"))

        @wraps(original_init)
        def init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            initialize(self)
            formatter = self.output_formatter

            def capture(raw):
                if current_config().get("sensitive"):
                    self._spw_sensitive_state.observe(raw, source="reference.raw_output_formatter")
                return formatter(raw)
            self.output_formatter = capture

        @wraps(original_query)
        def query(self, *args, **kwargs):
            initialize(self)
            messages = kwargs.get("messages", args[3] if len(args) > 3 else ())
            task = gate.m30.first_user_task(messages) if messages else None
            tools = any(message.get("role") == "tool" for message in messages)
            cfg = current_config()
            if not tools or task != self._spw_capture_task:
                self._spw_sensitive_state.reset(complete=True)
                self._spw_named_source_state.reset()
                self._spw_created_resources.reset()
                self._spw_capture_task = task
            if cfg.get("sensitive") and tools and not self._spw_sensitive_state.observations:
                self._spw_sensitive_state.fail("tool history was not observed through the raw formatter")
            runtime = kwargs.get("runtime", args[1] if len(args) > 1 else None)
            proxy = None
            call_args, call_kwargs = args, dict(kwargs)
            if (cfg.get("source") or cfg.get("resource")) and runtime is not None:
                proxy = _SourceRuntimeProxy(runtime, self._spw_named_source_state if cfg.get("source") else None, task,
                                             cfg.get("contracts", SourceContracts()), roles,
                                             created=self._spw_created_resources if cfg.get("resource") else None,
                                             identities=lambda: getattr(self, "_identity_set", set()))
                if "runtime" in call_kwargs:
                    call_kwargs["runtime"] = proxy
                else:
                    call_args = tuple(proxy if i == 1 else value for i, value in enumerate(args))
            with created_resource_context(self._spw_created_resources if cfg.get("resource") else None,
                                          lambda: getattr(self, "_identity_set", set())):
                with sensitive_source_context(self._spw_sensitive_state if cfg.get("sensitive") else None):
                    with named_source_context(self._spw_named_source_state if cfg.get("source") else None):
                        result = original_query(self, *call_args, **call_kwargs)
            if proxy is not None and isinstance(result, tuple) and len(result) >= 2 and result[1] is proxy:
                result = (result[0], runtime, *result[2:])
            return result

        cls._spw_raw_capture_original_methods = (original_init, original_query)
        cls._spw_raw_capture_config = config
        cls.__init__, cls.query = init, query
    config[kind] = bool(enabled)
    if contracts is not None:
        config["contracts"] = contracts
    if creation_contracts is not None:
        config["creation_contracts"] = creation_contracts
    if not (config["sensitive"] or config["source"] or config.get("resource")):
        cls.__init__, cls.query = cls._spw_raw_capture_original_methods
        del cls._spw_raw_capture_original_methods
        del cls._spw_raw_capture_config
    return bool(enabled)


def install_resource_capture(gate, enabled, contracts=None):
    contracts = CreationContracts() if contracts is None else contracts
    return _configure(gate, "resource", enabled, creation_contracts=contracts)


def install_sensitive_capture(gate, enabled):
    return _configure(gate, "sensitive", enabled)


def install_source_capture(gate, enabled, contracts=None):
    return _configure(gate, "source", enabled, contracts)
