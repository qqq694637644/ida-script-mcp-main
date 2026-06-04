"""Worker-side recorder-error script for the disposable VM U003 matrix.

This uses the checked-in public `mcp_changes` API with invalid patch bytes. The
API raises `RecorderError`, and `worker_runner.py` should map the script result
to `recorder_error`.
"""

from __future__ import annotations

import os


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


target_ea = int(_required_env("IDA_SCRIPT_MCP_WORKER_FAILURE_TARGET_EA"), 0)

# Invalid hex string. This should raise RecorderError before any mutation.
mcp_changes.patch_bytes(target_ea, "not-hex")  # type: ignore[name-defined]

result = {"unexpected": "recorder error script returned"}
