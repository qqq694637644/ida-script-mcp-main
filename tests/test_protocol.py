"""Tests for strict execution protocol models."""

from __future__ import annotations

import os
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_script_mcp.protocol import ExecuteRequest


class TestExecuteRequest:
    """Validate the shared strict ``/execute`` request schema."""

    def test_code_only_defaults(self):
        request = ExecuteRequest(code="1 + 2")
        assert request.code == "1 + 2"
        assert request.script_path is None
        assert request.capture_output is True
        assert request.timeout_seconds == 30

    def test_script_path_only(self):
        request = ExecuteRequest(script_path="/tmp/script.py", timeout_seconds=10)
        assert request.code is None
        assert request.script_path == "/tmp/script.py"
        assert request.timeout_seconds == 10

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"code": "print('hello')", "script_path": "/tmp/script.py"},
            {"code": "   "},
            {"script_path": "   "},
        ],
    )
    def test_requires_exactly_one_non_empty_source(self, payload):
        with pytest.raises(ValidationError):
            ExecuteRequest.model_validate(payload)

    def test_forbids_extra_fields(self):
        with pytest.raises(ValidationError):
            ExecuteRequest.model_validate({"code": "1", "typo": True})

    def test_strict_capture_output(self):
        with pytest.raises(ValidationError):
            ExecuteRequest.model_validate({"code": "1", "capture_output": "true"})

    def test_timeout_bounds(self):
        with pytest.raises(ValidationError):
            ExecuteRequest.model_validate({"code": "1", "timeout_seconds": 0})
        with pytest.raises(ValidationError):
            ExecuteRequest.model_validate({"code": "1", "timeout_seconds": 601})
