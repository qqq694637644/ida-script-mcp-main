"""Worker-side blocking script for the disposable VM U002 timeout test.

This file is copied into the guest payload and executed by `execute_idapython`
inside the isolated headless IDA worker. It writes a sentinel before blocking in
`time.sleep`, which is a C call that should not be interrupted by the line-level
soft timeout tracer. The server-side hard timeout should kill the worker process
and report `status=timeout`, `hard_timeout=true`, and `killed=true`.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

sentinel_path = os.environ.get("IDA_SCRIPT_MCP_WORKER_TIMEOUT_SENTINEL")
if sentinel_path:
    Path(sentinel_path).write_text("started", encoding="utf-8")

# Deliberately block longer than both the requested worker timeout and the
# manager's hard timeout margin.
time.sleep(999)

result = {"unexpected": "worker timeout script returned"}
