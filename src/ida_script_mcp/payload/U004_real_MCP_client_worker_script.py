"""Worker-side script for U004 real MCP client end-to-end testing.

The script is executed through the real MCP `execute_idapython` tool. It records
a simple comment change through `mcp_changes` so the test can call the real MCP
`apply_worker_changes` tool in dry-run mode.
"""

from __future__ import annotations

import os


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


target_ea = int(_required_env("IDA_SCRIPT_MCP_U004_TARGET_EA"), 0)
comment_text = _required_env("IDA_SCRIPT_MCP_U004_COMMENT")
comment_ok = mcp_changes.comment(target_ea, comment_text, False)  # type: ignore[name-defined]

result = {
    "target_ea": target_ea,
    "comment_text": comment_text,
    "comment_ok": bool(comment_ok),
}
