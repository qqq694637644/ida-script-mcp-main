from __future__ import annotations

import types

import pytest

from ida_script_mcp.change_recorder import ChangeRecorder, McpChangesApi, RecorderError


def test_monkeypatch_records_success_and_preserves_return_value():
    calls = []

    def set_name(ea, name, flags=0):
        calls.append((ea, name, flags))
        return 1

    idc = types.SimpleNamespace(set_name=set_name)
    recorder = ChangeRecorder()
    recorder.install({"idc": idc})

    try:
        assert idc.set_name(0x1000, "main", 0) == 1
    finally:
        recorder.uninstall()

    assert calls == [(0x1000, "main", 0)]
    assert recorder.operations[0].op == "rename"
    assert recorder.operations[0].source == "monkeypatch"
    assert idc.set_name is set_name


def test_failed_original_return_is_not_recorded():
    idc = types.SimpleNamespace(set_cmt=lambda *_args: 0)
    recorder = ChangeRecorder()
    recorder.install({"idc": idc})

    try:
        assert idc.set_cmt(0x1000, "no", 0) == 0
    finally:
        recorder.uninstall()

    assert recorder.operations == []


def test_original_api_exception_propagates_as_script_error_material():
    def boom(*_args):
        raise ValueError("ida failed")

    idc = types.SimpleNamespace(patch_byte=boom)
    recorder = ChangeRecorder()
    recorder.install({"idc": idc})

    try:
        with pytest.raises(ValueError):
            idc.patch_byte(0x1000, 0x90)
    finally:
        recorder.uninstall()

    assert recorder.operations == []


def test_explicit_mcp_changes_applies_and_records():
    ida_name = types.SimpleNamespace(set_name=lambda *_args: True)
    recorder = ChangeRecorder()
    api = McpChangesApi(recorder, {"ida_name": ida_name})

    assert api.rename(0x1000, "entry") is True

    assert recorder.operations[0].op == "rename"
    assert recorder.operations[0].source == "explicit_api"


def test_monkeypatch_records_ida_name_direct_calls():
    ida_name = types.SimpleNamespace(set_name=lambda *_args: True)
    recorder = ChangeRecorder()
    recorder.install({"ida_name": ida_name})

    try:
        assert ida_name.set_name(0x1000, "main", 0) is True
    finally:
        recorder.uninstall()

    assert len(recorder.operations) == 1
    assert recorder.operations[0].op == "rename"
    assert recorder.operations[0].source == "monkeypatch"


def test_explicit_mcp_changes_suppresses_underlying_monkeypatch_recording():
    ida_name = types.SimpleNamespace(set_name=lambda *_args: True)
    recorder = ChangeRecorder()
    recorder.install({"ida_name": ida_name})
    api = McpChangesApi(recorder, {"ida_name": ida_name})

    try:
        assert api.rename(0x1000, "entry") is True
    finally:
        recorder.uninstall()

    assert len(recorder.operations) == 1
    assert recorder.operations[0].op == "rename"
    assert recorder.operations[0].source == "explicit_api"


def test_explicit_mcp_changes_missing_module_raises_recorder_error():
    recorder = ChangeRecorder()
    api = McpChangesApi(recorder, {})

    with pytest.raises(RecorderError, match="ida_name"):
        api.rename(0x1000, "entry")

    assert recorder.operations == []
