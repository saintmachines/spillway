# Connect a local tool app

This example connects SPILLWAY 0.1.0 to a small HTTP tool host using Pydantic
and the Python standard library. A fixed sequence of proposed calls reads a
message, refuses a redirected recipient, and executes the requested reply and
note. The host stores synthetic data in memory.

Get these examples from the current repository checkout:

```bash
git clone https://github.com/saintmachines/spillway.git
cd spillway
python -m pip install git+https://github.com/saintmachines/spillway.git@v0.1.0
python docs/examples/local_app_demo.py --report app-check.json
```

The example opens a temporary server on `127.0.0.1`, runs the checks, writes the
optional full record, and closes the server. It uses no model or external
account. The examples live in the repository, outside the wheel and source
distribution. The tagged 0.1.0 library is the API they use.

The checks cover real HTTP requests and in-memory effects, strict argument and
response validation, refused calls that never reach the host, error responses
after a write, redirects, oversized responses, task isolation, and safe stops
when a final-answer check fails. These are integration checks with synthetic
data. They are separate from the paper's attack-success measurements.

## Put the boundary in your loop

`boundary.py` defines `ToolSpec`, `ToolBoundary` and `BoundaryStopped`.

1. Register each tool's argument and response models with `strict=True` and
   `extra="forbid"`. Use an appropriate schema for recipient values and
   collections. The example rejects a recipient dictionary before it can
   reach either the guard or the host.
2. Declare read/write effects and the target roles in your `Lexicon`. The
   example's `sender` and `recipients` match the default vocabulary. A new
   argument such as `payee` needs an explicit role extension. Schema validation
   checks shape and value types. It does not authenticate a sender or infer
   which fields a tool owner vouches for.
3. Create one boundary for each user task and use it sequentially. Pass every
   proposed call, reads included, through `boundary.call(name, args)`. The
   exact validated arguments checked by the guard are sent to the host.
4. Give the agent only the returned `model_text`. Successful raw results are
   validated and observed before the sanitized text is returned. HTTP and
   schema errors are observed as untyped text. Retrieved context or memory
   enters through `boundary.observe_context(text)` before the agent reads it.
5. For a final answer, use the checked text from `boundary.final_answer(text)`.
   If it raises `BoundaryStopped`, stop the task. Do not return the unchecked
   text as a fallback.

The example transport accepts one fixed `http://127.0.0.1:<port>` endpoint,
disables environment proxies, and refuses redirects. An application's own
transport, authentication and authorization stay at its boundary. The example
does not connect a Gmail/Slack account or provide a framework plugin.

## Read the execution record correctly

`request_attempted` records a transport attempt. `requests_sent=0` means the
call stopped before transport, `1` means an HTTP response confirms a request,
and `None` means delivery is unknown after a transport failure.

An HTTP error can follow a successful write. The wrapper therefore records
write effects as `unknown` once transport is attempted. The fixture's own
ledger separately records what actually happened. It does not retry writes
automatically. Use the application's idempotency or reconciliation mechanism
when integrating a real write API.

## Supported data paths

- Pydantic models, lists of models, and nested models retain their declared
  field roles.
- A dictionary uses the key-name vocabulary. The provider must control and
  vouch for those routing fields.
- Plain text, JSON strings and raw CSV are observed as text. Parsing them into
  a trusted response model is an explicit application decision. A CSV adapter
  can validate `csv.DictReader` rows with its declared Pydantic model.
- A typed `list[str]` roster needs the explicit `roster=True` contract when
  calling the library directly. This example uses object responses instead.

See [SECURITY.md](../../SECURITY.md) for the integration conditions and
[the project guide](https://saintmachines.github.io/spillway/integrate.html)
for the short walkthrough. Read the existing package API tests for more
formats and boundary cases. Live framework/account integration, concurrent
call execution and long-running service operation have not been established
by this example.
