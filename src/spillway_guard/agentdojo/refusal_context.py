"""Episode-local refusal provenance at the real AgentDojo executor boundary."""
import json
from contextvars import ContextVar
from functools import wraps

from ..refusals import HOW_TO_PROCEED, without_own_refusals

_CURRENT = ContextVar('spillway_own_refusal_state', default=None)


def install_refusal_capture(gate, enabled):
    cls = getattr(gate, 'SchemaProvenanceToolsExecutor', None)
    if cls is None:
        return
    original = getattr(cls.query, '_spw_refusal_original_query', cls.query)
    if not enabled:
        if hasattr(cls.query, '_spw_refusal_original_query'):
            cls.query = original
        entailed = getattr(gate, '_query_entailed', None)
        if entailed is not None and hasattr(entailed, '_spw_refusal_original_entailed'):
            gate._query_entailed = entailed._spw_refusal_original_entailed
        return

    @wraps(original)
    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        state = getattr(self, '_spw_own_refusals', None)
        if state is None or not any(m.get('role') == 'tool' for m in messages or ()):
            state = {'refusals': []}
            self._spw_own_refusals = state
        token = _CURRENT.set(state)
        try:
            return original(self, query, runtime, env, messages, extra_args)
        finally:
            _CURRENT.reset(token)

    query._spw_refusal_original_query = original
    cls.query = query
    entailed = getattr(gate, '_query_entailed', None)
    if entailed is not None:
        original_entailed = getattr(entailed, '_spw_refusal_original_entailed', entailed)

        @wraps(original_entailed)
        def query_entailed(args, tainted, trusted):
            state = _CURRENT.get()
            if state is not None:
                tainted = without_own_refusals(tainted, state['refusals'])
            return original_entailed(args, tainted, trusted)

        query_entailed._spw_refusal_original_entailed = original_entailed
        gate._query_entailed = query_entailed


def prepare_decision(tainted, kw, *, enabled):
    state = _CURRENT.get()
    if state is None or not enabled:
        return tainted, kw
    tainted = without_own_refusals(tainted, state['refusals'])
    kw = dict(kw)
    if kw.get('mvg_sources') is not None:
        kw['mvg_sources'] = [without_own_refusals(v, state['refusals']) for v in kw['mvg_sources']]
    return tainted, kw


def refusal_message(executor, tool_call, reason, score, generic):
    payload = {'status': 'blocked_by_spillway', 'reason': reason, 'how_to_proceed': HOW_TO_PROCEED,
               'tool': tool_call.function, 'score': score}
    state = getattr(executor, '_spw_own_refusals', None)
    # A tool argument being optional does not mean the user's task can omit it.
    # Never generate a reduced concrete call from schema optionality alone.
    text = '<SPILLWAY> ' + json.dumps(payload)
    # AgentDojo sends error instead of content to the model. Carry the same
    # actionable refusal in both, then exclude both exact texts from evidence.
    error = 'SPILLWAY refused the call: ' + str(reason) + '. ' + HOW_TO_PROCEED
    if state is not None:
        state['refusals'].extend((text, error))
    return payload, text, error
