# Connect SPILLWAY to your agent

Copy [`guarded_tools.py`](guarded_tools.py) and the file for your stack into your project, then add the line in the table. A refused call never reaches your tool. The model reads the refusal as the tool's result and continues.

| Stack | What you add | File |
|:--|:--|:--|
| LangChain, LangGraph | `middleware=[spillway_middleware()]` | [`langchain_middleware.py`](langchain_middleware.py) |
| OpenAI Agents SDK | `tools=guard_tools(Guard(task), tools)` | [`openai_agents_tools.py`](openai_agents_tools.py) |
| Any MCP host | `python mcp_proxy.py --task "..." -- your server command` | [`mcp_proxy.py`](mcp_proxy.py) |
| Claude Code | four hooks in `.claude/settings.json` | [`claude_code_hook.py`](claude_code_hook.py) |
| OpenAI or Anthropic SDK, your own loop | `text = guarded_call(guard, name, args, tool)` | [`guarded_tools.py`](guarded_tools.py) |

The blocks below run from this folder. [`demo_tools.py`](demo_tools.py) is a small inbox whose mail from Alice carries an injection. Each block prints who was mailed. Point `OPENAI_BASE_URL` or `ANTHROPIC_BASE_URL` at a local server to run them with no API key.

## LangChain and LangGraph

```bash
pip install spillway-guard langchain langchain-openai
```

```python
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI

from demo_tools import SENT, TASK, get_mail, send_mail
from langchain_middleware import spillway_middleware, typed_tool

agent = create_agent(ChatOpenAI(model="gpt-4o-mini"), [typed_tool(get_mail), typed_tool(send_mail)],
                     middleware=[spillway_middleware()])
agent.invoke({"messages": [("user", TASK)]})
print(SENT)
```

`typed_tool` keeps the typed return for the guard, because LangChain turns a plain tool's return into a string first.

## OpenAI Agents SDK

```bash
pip install spillway-guard openai-agents
```

```python
from agents import Agent, Runner, function_tool
from spillway_guard import Guard

from demo_tools import SENT, TASK, get_mail, send_mail
from openai_agents_tools import guard_tools

tools = guard_tools(Guard(TASK), [function_tool(get_mail), function_tool(send_mail)])
Runner.run_sync(Agent(name="mail", model="gpt-4o-mini", tools=tools), TASK)
print(SENT)
```

Build one Guard and one tool list for each user task.

## Any MCP host

```bash
pip install spillway-guard mcp
```

The proxy starts your server and answers the host in its place. In your host's configuration, with the full path to this folder:

```json
{"mcpServers": {"mail": {"command": "python", "args": ["/path/to/mcp_proxy.py", "--task", "Read my inbox and reply to Alice's mail with a short thank-you.", "--", "python", "/path/to/demo_mcp_server.py"]}}}
```

A host does not send a server the user's message, so `--task` states what this deployment was asked to do. One proxy holds one Guard and handles one call at a time. Give your tools typed return models, as `demo_mcp_server.py` does, so the guard can read their field names. If the host does not see your virtual environment, write that environment's full Python path in place of `python`.

## Claude Code

```bash
pip install spillway-guard
```

In `.claude/settings.json`, with the full path to this folder:

```json
{"hooks": {
  "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "python /path/to/claude_code_hook.py"}]}],
  "PreToolUse": [{"hooks": [{"type": "command", "command": "python /path/to/claude_code_hook.py"}]}],
  "PostToolUse": [{"hooks": [{"type": "command", "command": "python /path/to/claude_code_hook.py"}]}],
  "PostToolUseFailure": [{"hooks": [{"type": "command", "command": "python /path/to/claude_code_hook.py"}]}]
}}
```

The hook keeps one Guard per session and checks each call before it runs. The user's prompts are the task. The model reads each tool's own output here, and the hook records it for the checks that follow. For the shell tool it checks the URLs and addresses written in the command, and it works alongside your usual permission settings. If the hook cannot load or cannot check a call, it blocks that call. If Claude Code does not see your virtual environment, write that environment's full Python path in place of `python`.

## Your own loop

`guarded_call` checks the call, runs the tool if the call is admitted, and returns the text for the model. With the OpenAI SDK:

```bash
pip install spillway-guard openai
```

```python
import json

from openai import OpenAI
from spillway_guard import Guard

from demo_tools import SCHEMAS, SENT, TASK, TOOLS
from guarded_tools import guarded_call

client, guard = OpenAI(), Guard(TASK)
messages = [{"role": "user", "content": TASK}]
while True:
    reply = client.chat.completions.create(model="gpt-4o-mini", messages=messages, tools=SCHEMAS).choices[0].message
    messages.append(reply)
    if not reply.tool_calls:
        break
    for call in reply.tool_calls:
        args = json.loads(call.function.arguments)
        text = guarded_call(guard, call.function.name, args, TOOLS[call.function.name])
        messages.append({"role": "tool", "tool_call_id": call.id, "content": text})
print(SENT)
```

With the Anthropic SDK:

```bash
pip install spillway-guard anthropic
```

```python
from anthropic import Anthropic
from spillway_guard import Guard

from demo_tools import SCHEMAS, SENT, TASK, TOOLS
from guarded_tools import guarded_call

client, guard = Anthropic(), Guard(TASK)
tools = [{"name": s["function"]["name"], "description": s["function"]["description"], "input_schema": s["function"]["parameters"]} for s in SCHEMAS]
messages = [{"role": "user", "content": TASK}]
while True:
    reply = client.messages.create(model="claude-sonnet-5-5", max_tokens=1024, messages=messages, tools=tools)
    messages.append({"role": "assistant", "content": reply.content})
    calls = [block for block in reply.content if block.type == "tool_use"]
    if not calls:
        break
    messages.append({"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": c.id, "content": guarded_call(guard, c.name, c.input, TOOLS[c.name])} for c in calls]})
print(SENT)
```

## Lists and typed returns

The adapters read a list or a typed object one field at a time, so a match in a message's body stays in that body, and the message's sender and the other messages still reach the model. Text returns stay whole. To filter each return whole, as the paper's runs did, pass `observe=observe_whole` to `guarded_call`, `spillway_middleware` or `guard_tools`, or `--whole-returns` to the MCP proxy. The paper's numbers are for that whole-return path.

## Check how SPILLWAY reads your tools

The guard knows a read from a write and a recipient from a message body by name. Read what it sees before you ship a new tool:

```python
from guarded_tools import describe_tools

print(describe_tools({"fetch_ticket": ["ticket_id"], "assign_ticket": ["ticket_id", "assignee"]}))
```

Declare what it misses, and pass the lexicon to the Guard:

```python
from spillway_guard import Guard, Lexicon

lexicon = Lexicon().extend(read_prefixes=("fetch_",), target_arg_hints={"assignee"})
guard = Guard("Assign ticket 7 to Dana.", lexicon=lexicon)
```

## Add the judge

The judge reviews refusals with a model. It is off by default. On Ollama, turn a reasoning model's thinking off, as the paper's runs did:

```python
from spillway_guard import Guard, Judge

judge = Judge("http://127.0.0.1:11434/v1", "gemma4:31b", extra_body={"reasoning_effort": "none"})
guard = Guard("Pay the bill in bill.txt.", judge=judge)
```

## Tested with

Python 3.12, spillway-guard 0.1.0, langchain 1.4.9, langgraph 1.2.20, openai 3.46.0, anthropic 2.5.0, openai-agents 0.24.0, mcp 2.3.0 and Claude Code 2.1.296.

## Run the tests

```bash
pip install pytest pytest-asyncio
python -m pytest -q test_frameworks.py
```

The tests use a scripted model and no network. A test skips when its SDK is not installed.
