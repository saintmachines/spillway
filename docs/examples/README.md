# Connect a local tool app

Run the examples from a current repository checkout:

```bash
git clone https://github.com/saintmachines/spillway.git
cd spillway
python -m pip install spillway-guard
python docs/examples/local_app_demo.py --report app-check.json
python docs/examples/collection_demo.py --report collection-check.json
```

The examples start a temporary HTTP server on `127.0.0.1`, run fixed proposed
calls against synthetic messages and notes, and close the server. They use the
installed 0.1.0 library, Pydantic and the standard library, with no model or
external account. Example files come from the checkout, outside the wheel and
source distribution.

## Register the tool's contract

`boundary.py` supplies `ToolSpec`, `ToolBoundary` and `BoundaryStopped`.
The runnable collection example declares its tools this way:

```python
from boundary import ToolSpec
from collection_demo import Ack, Messages, Query, Send

tools = [
    ToolSpec("get_messages", Query, Messages, "read", record_field="messages"),
    ToolSpec("send_email", Send, Ack, "write", target_fields=("recipients",)),
]
```

Use strict, extra-forbid argument and response models. Declare every routing
argument in `target_fields` and the role vocabulary. Registration checks that
each declared target field exists in the argument model and is recognized by
the lexicon. For a new field such as `target_user`, extend the vocabulary with
`Lexicon().extend(target_arg_hints={"target_user"})`, pass it to the boundary as
`lexicon=...`, and declare `target_fields=("target_user",)` on that tool. The application supplies each
tool's read/write effect and routing semantics. Schema validation checks types,
and the tool provider vouches for identity fields.

## Lists of records

Use `record_field` when the tool owner's response model declares a list of
independent strict record models. The boundary indexes the complete response
once and sanitizes each field of each record separately. A matched region in
a message's body stays in that body, preserving the sender and other records.
Removed text remains available to the egress check.

Use the schema's field boundaries. Do not infer them from separators in the
untrusted text or call `observe_tool_return` once per record, because earlier
records' taint would change later indexing decisions. A tool without
`record_field` uses the library's whole-return path. For the paper's evaluated
mode and settings, use [the reproduction guide](../../reproduce/README.md).
The collection example exercises an application adapter separately from those
measurements.

## Put the boundary in your loop

1. Create one boundary per user task and use it sequentially.
2. Pass every proposed call through `boundary.call(name, args)`. The same
   canonical arguments checked by the guard are sent to the tool host.
3. Give the agent only the returned `model_text`. Successful responses are
   validated and observed. HTTP and schema errors are observed as untyped text.
   Observe retrieved context or memory with `boundary.observe_context(text)`.
4. Return `boundary.final_answer(text)`. If it raises `BoundaryStopped`, stop
   the task without returning an unchecked answer.

The example transport accepts one fixed loopback endpoint, bounds response
size and time, disables environment proxies, and refuses redirects. Adapt the
transport with your application's authentication and authorization. Keep the
validate → check → execute → observe order and record write outcomes for
idempotency and reconciliation.

`requests_sent=0` means the call stopped before transport, `1` means an HTTP
response confirms a request, and `None` means delivery is unknown after a
transport failure. A write's effects remain `unknown` until the application
reconciles them. An error does not roll back the fixture's recorded effect.

## Other data

- Pass Pydantic models and nested models before serialization so their field
  roles remain available.
- For dictionaries, use provider-controlled routing keys and the declared
  vocabulary.
- Parse CSV or JSON text explicitly and validate the parsed objects with the
  tool's model. Raw text remains untyped content.
- Convert a dataclass or a named tuple with `dataclasses.asdict` or `_asdict()`,
  and keep the bare address in the field. `Bob <bob@example.com>` is not indexed.
- A typed `list[str]` roster uses the direct library's explicit `roster=True`
  contract. This HTTP example uses object responses.

[Integration conditions](../../SECURITY.md) ·
[Guard API](../../src/spillway_guard/guard.py) ·
[Project walkthrough](https://saintmachines.github.io/spillway/integrate.html)
