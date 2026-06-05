"""Tests for the protocol fallback used when pydantic is unavailable."""

from __future__ import annotations

import importlib.abc
import importlib.util
import sys
from pathlib import Path

import pytest


class _BlockPydantic(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):  # noqa: D102
        del path, target
        if fullname == "pydantic" or fullname.startswith("pydantic."):
            raise ImportError("blocked pydantic for fallback test")
        return None


def _load_protocol_without_pydantic():
    module_name = "_ida_script_mcp_protocol_without_pydantic"
    protocol_path = Path(__file__).resolve().parents[1] / "src" / "ida_script_mcp" / "protocol.py"
    saved_pydantic = {
        name: module
        for name, module in list(sys.modules.items())
        if name == "pydantic" or name.startswith("pydantic.")
    }
    for name in saved_pydantic:
        sys.modules.pop(name, None)

    blocker = _BlockPydantic()
    sys.meta_path.insert(0, blocker)
    sys.modules.pop(module_name, None)
    try:
        spec = importlib.util.spec_from_file_location(module_name, protocol_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.pop(module_name, None)
        sys.modules.update(saved_pydantic)


def test_execute_request_fallback_validates_strict_inputs():
    protocol = _load_protocol_without_pydantic()

    request = protocol.ExecuteRequest.model_validate({"code": "1 + 2", "timeout_seconds": 5})

    assert request.code == "1 + 2"
    assert request.script_path is None
    assert request.capture_output is True
    assert request.timeout_seconds == 5

    with pytest.raises(ValueError):
        protocol.ExecuteRequest.model_validate({"code": "1", "script_path": "script.py"})
    with pytest.raises(ValueError):
        protocol.ExecuteRequest.model_validate({"code": "1", "capture_output": "true"})
    with pytest.raises(ValueError):
        protocol.ExecuteRequest.model_validate({"code": "1", "timeout_seconds": 0})
    with pytest.raises(ValueError):
        protocol.ExecuteRequest.model_validate({"code": "1", "typo": True})


def test_execute_result_fallback_dumps_and_copies_nested_errors():
    protocol = _load_protocol_without_pydantic()

    result = protocol.ExecuteResult(
        status="script_error",
        error={"type": "ValueError", "message": "boom", "traceback": None},
        duration_seconds=1,
    )
    copied = result.model_copy(update={"instance_id": "sample", "port": 13338})

    dumped = copied.model_dump(mode="json")
    assert dumped["status"] == "script_error"
    assert dumped["error"] == {"type": "ValueError", "message": "boom", "traceback": None}
    assert dumped["duration_seconds"] == 1.0
    assert dumped["instance_id"] == "sample"
    assert dumped["port"] == 13338
