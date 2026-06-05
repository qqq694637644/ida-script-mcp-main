"""Script-path payload used by the real MCP client end-to-end smoke test.

This script is executed through the real MCP ``execute_idapython`` tool. It
intentionally uses only the strict in-process execute subsystem and returns a
small JSON-serializable result.
"""

from __future__ import annotations

import idaapi
import idautils

functions = list(idautils.Functions())
selected_ea = int(functions[0]) if functions else 0

print("u004 strict script_path execution ok")

result = {
    "imagebase": int(idaapi.get_imagebase()),
    "function_count": len(functions),
    "selected_ea": selected_ea,
}
