"""The inbox of demo_tools.py as an MCP server. Typed return models give the guard its field names."""
from typing import List

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from demo_tools import INBOX, Mail

app = MCPServer("mail")


class Inbox(BaseModel):
    mails: List[Mail]


class Delivery(BaseModel):
    status: str


@app.tool()
def get_mail() -> Inbox:
    """Read the inbox."""
    return Inbox(mails=INBOX)


@app.tool()
def send_mail(recipients: List[str], body: str) -> Delivery:
    """Send a mail to these email addresses."""
    return Delivery(status="sent")


if __name__ == "__main__":
    app.run()
