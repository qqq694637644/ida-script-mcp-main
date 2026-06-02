"""Process helpers for isolated worker management."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from typing import Protocol


class ProcessLike(Protocol):
    pid: int

    def poll(self) -> int | None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...


def kill_process_tree(process: ProcessLike, *, timeout: float = 5.0) -> bool:
    """Best-effort kill of a worker process tree.

    Returns True when the process appears to be gone, or False when the final
    state could not be verified.
    """
    if process.poll() is not None:
        return True

    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except Exception:
            process.kill()

    try:
        process.wait(timeout=timeout)
    except Exception:
        return process.poll() is not None
    return process.poll() is not None
