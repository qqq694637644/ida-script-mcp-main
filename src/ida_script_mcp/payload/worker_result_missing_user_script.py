"""Worker-side missing-result script for the disposable VM U003 matrix.

The script exits the IDA worker process before `worker_runner.py` can write
`result.json`. Because the process exits with code 0, the MCP server should
classify the outcome as `worker_result_missing`.
"""

from __future__ import annotations

import os

os._exit(0)
