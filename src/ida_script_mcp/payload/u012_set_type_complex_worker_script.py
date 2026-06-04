"""Worker-side user script for U012 set_type complex cases.

This script runs inside the isolated headless IDA worker. It applies several
valid C declarations to the copied database through the public ``mcp_changes``
API so the worker emits replayable ``set_type`` ChangeSet operations. The GUI
payload later dry-runs, rejects invalid cases, and destructively replays these
operations into the live IDA database.
"""

from __future__ import annotations

import json
import os


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


target_ea = int(_required_env("IDA_SCRIPT_MCP_U012_TARGET_EA"), 0)
declarations = json.loads(_required_env("IDA_SCRIPT_MCP_U012_DECLS_JSON"))
if not isinstance(declarations, list) or not declarations:
    raise RuntimeError("IDA_SCRIPT_MCP_U012_DECLS_JSON must be a non-empty JSON list")

try:
    import idc
except Exception:
    idc = None  # type: ignore[assignment]

idc_type_aliases = {
    "has_set_type": callable(getattr(idc, "set_type", None)) if idc is not None else False,
    "has_SetType": callable(getattr(idc, "SetType", None)) if idc is not None else False,
}

applied = []
for item in declarations:
    if not isinstance(item, dict):
        raise RuntimeError(f"U012 declaration entry must be an object: {item!r}")
    label = str(item["label"])
    decl = str(item["decl"])
    flags = int(item.get("flags", 0))
    ok = mcp_changes.set_type(target_ea, decl, flags=flags)  # type: ignore[name-defined]  # noqa: F821
    if not ok:
        raise RuntimeError(f"mcp_changes.set_type failed for {label}: {decl}")
    applied.append({"label": label, "decl": decl, "flags": flags, "ok": bool(ok)})

result = {
    "target_ea": target_ea,
    "idc_type_aliases": idc_type_aliases,
    "applied_declarations": applied,
}
