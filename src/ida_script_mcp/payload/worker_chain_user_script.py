"""Worker-side user script for the disposable VM V2.3 worker-chain test.

This file is copied into the guest payload and executed by `execute_idapython`
inside the isolated headless IDA worker. It intentionally uses the public
`mcp_changes` API so the worker emits a structured ChangeSet that the payload
can dry-run and replay through `apply_worker_changes`.
"""

from __future__ import annotations

import os


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


target_ea = int(_required_env("IDA_SCRIPT_MCP_WORKER_CHAIN_TARGET_EA"), 0)
new_name = _required_env("IDA_SCRIPT_MCP_WORKER_CHAIN_NEW_NAME")
comment_text = _required_env("IDA_SCRIPT_MCP_WORKER_CHAIN_COMMENT")

rename_ok = mcp_changes.rename(target_ea, new_name)  # type: ignore[name-defined]
comment_ok = mcp_changes.comment(target_ea, comment_text, False)  # type: ignore[name-defined]

result = {
    "target_ea": target_ea,
    "new_name": new_name,
    "comment_text": comment_text,
    "rename_ok": bool(rename_ok),
    "comment_ok": bool(comment_ok),
}
