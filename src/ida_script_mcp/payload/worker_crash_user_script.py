"""Worker-side crash script for the disposable VM U003 failure matrix.

The script exits the IDA worker process before `worker_runner.py` can write
`result.json`. Because the process exits with a non-zero code, the MCP server
should classify the outcome as `worker_crashed`.
"""

from __future__ import annotations

import os

os._exit(13)
