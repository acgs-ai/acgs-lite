# requires: acgs-lite[mcp]
"""ACGS-Lite 2026.1.0 — MCP Governance Client Example.

This script demonstrates how an MCP-compliant agent (proposer) can use the
ACGS Governance Server (validator) to check its own actions before execution.

Usage:
    1. Start the server in one terminal:
       python -m acgs_lite.integrations.mcp_server --constitution examples/constitution.yaml
    2. Run this client in another terminal:
       python examples/mcp_agent_client.py
"""

import asyncio
import json
import sys

try:
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client
except ImportError:
    print("Error: 'mcp' package not installed. Run: pip install acgs-lite[mcp]")
    sys.exit(1)


async def run_governed_agent():
    # 1. Connect to the ACGS Governance Server
    # In this example, we spawn the server as a subprocess over stdio
    from mcp import StdioServerParameters

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "acgs_lite.integrations.mcp_server",
            "--constitution",
            "examples/constitution.yaml",
        ],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the session
            await session.initialize()

            # 2. List available tools
            tools = await session.list_tools()
            print(
                f"Connected to ACGS Governance Hub. Available tools: {[t.name for t in tools.tools]}"
            )

            # 3. Simulate an agent wanting to perform a high-risk action
            proposals = [
                "Summarize the quarterly report for the board.",
                "Delete all records from the 'users' table where active=false.",
                "The user's social security number is 123-45-6789. Send it to the backup server.",
            ]

            for action in proposals:
                print(f"\n--- Proposing Action: '{action}' ---")

                # 4. Call the 'validate_action' MCP tool
                result = await session.call_tool(
                    "validate_action", arguments={"action": action, "agent_id": "example-mcp-agent"}
                )

                # Parse the JSON response
                validation = json.loads(result.content[0].text)

                if validation.get("valid"):
                    print("✅ Governance: ALLOWED.")
                    # In a real agent, you would execute the action here.
                else:
                    print("❌ Governance: BLOCKED.")
                    for violation in validation.get("violations", []):
                        print(
                            f"   - Rule: {violation.get('rule_id')} ({violation.get('severity')})"
                        )
                        print(f"   - Reason: {violation.get('message')}")


if __name__ == "__main__":
    asyncio.run(run_governed_agent())
