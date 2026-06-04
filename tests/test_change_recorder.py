from __future__ import annotations

import types

import pytest

from ida_script_mcp.change_recorder import ChangeRecorder, McpChangesApi, RecorderError

BASE_EA = 0x1000


def _fake_modules(*, set_cmt_return=True):
    calls = []
    names = {BASE_EA: "old_name"}
    memory = bytearray(range(64))

    def offset(ea):
        return int(ea) - BASE_EA

    def get_name(ea):
        return names.get(int(ea), "")

    def set_name(ea, name, flags=0):
        calls.append(("set_name", ea, name, flags))
        names[int(ea)] = str(name)
        return True

    def set_cmt(ea, text, repeatable=0):
        calls.append(("set_cmt", ea, text, repeatable))
        return set_cmt_return

    def set_func_cmt(ea, text, repeatable=0):
        calls.append(("set_func_cmt", ea, text, repeatable))
        return True

    def get_bytes(ea, size):
        start = offset(ea)
        return bytes(memory[start : start + int(size)])

    def patch_int(width):
        def patch(ea, value):
            start = offset(ea)
            memory[start : start + width] = int(value).to_bytes(width, "little")
            return True

        return patch

    def patch_bytes(ea, data):
        new_bytes = bytes(data)
        start = offset(ea)
        memory[start : start + len(new_bytes)] = new_bytes
        return True

    def set_type(ea, decl):
        calls.append(("set_type", ea, decl))
        return True

    class FakeTinfo:
        def dstr(self):
            return "int __cdecl main(void)"

    def apply_tinfo(ea, tinfo, flags=0):
        assert isinstance(tinfo, FakeTinfo)
        calls.append(("apply_tinfo", ea, flags))
        return True

    idc = types.SimpleNamespace(
        set_name=set_name,
        get_name=get_name,
        set_cmt=set_cmt,
        set_func_cmt=set_func_cmt,
        patch_byte=patch_int(1),
        patch_word=patch_int(2),
        patch_dword=patch_int(4),
        patch_qword=patch_int(8),
        get_bytes=get_bytes,
        SetType=set_type,
        set_type=set_type,
    )
    ida_bytes = types.SimpleNamespace(
        set_cmt=set_cmt,
        patch_byte=patch_int(1),
        patch_word=patch_int(2),
        patch_dword=patch_int(4),
        patch_qword=patch_int(8),
        patch_bytes=patch_bytes,
    )
    modules = {
        "idc": idc,
        "ida_name": types.SimpleNamespace(set_name=set_name),
        "ida_bytes": ida_bytes,
        "ida_funcs": types.SimpleNamespace(set_func_cmt=set_func_cmt),
        "ida_typeinf": types.SimpleNamespace(apply_tinfo=apply_tinfo),
    }
    return modules, calls, names, memory, FakeTinfo


def test_monkeypatch_records_success_old_name_and_preserves_return_value():
    modules, calls, _names, _memory, _fake_tinfo = _fake_modules()
    original = modules["idc"].set_name
    recorder = ChangeRecorder()
    recorder.install(modules)

    try:
        assert modules["idc"].set_name(BASE_EA, "main", 0) is True
    finally:
        recorder.uninstall()

    assert calls == [("set_name", BASE_EA, "main", 0)]
    assert recorder.operations[0].op == "rename"
    assert recorder.operations[0].old_name == "old_name"
    assert recorder.operations[0].source == "monkeypatch"
    assert modules["idc"].set_name is original


def test_failed_original_return_is_not_recorded():
    modules, _calls, _names, _memory, _fake_tinfo = _fake_modules(set_cmt_return=False)
    recorder = ChangeRecorder()
    recorder.install(modules)

    try:
        assert modules["idc"].set_cmt(BASE_EA, "no", 0) is False
    finally:
        recorder.uninstall()

    assert recorder.operations == []


def test_original_api_exception_propagates_without_recording():
    modules, _calls, _names, _memory, _fake_tinfo = _fake_modules()

    def boom(*_args):
        raise ValueError("ida failed")

    modules["idc"].patch_byte = boom
    recorder = ChangeRecorder()
    recorder.install(modules)

    try:
        with pytest.raises(ValueError):
            modules["idc"].patch_byte(BASE_EA, 0x90)
    finally:
        recorder.uninstall()

    assert recorder.operations == []


def test_explicit_mcp_changes_applies_and_records_old_name():
    modules, _calls, _names, _memory, _fake_tinfo = _fake_modules()
    recorder = ChangeRecorder()
    api = McpChangesApi(recorder, modules)

    assert api.rename(BASE_EA, "entry") is True

    assert recorder.operations[0].op == "rename"
    assert recorder.operations[0].old_name == "old_name"
    assert recorder.operations[0].source == "explicit_api"


def test_monkeypatch_records_ida_name_direct_calls():
    modules, _calls, _names, _memory, _fake_tinfo = _fake_modules()
    recorder = ChangeRecorder()
    recorder.install(modules)

    try:
        assert modules["ida_name"].set_name(BASE_EA, "main", 0) is True
    finally:
        recorder.uninstall()

    assert len(recorder.operations) == 1
    assert recorder.operations[0].op == "rename"
    assert recorder.operations[0].source == "monkeypatch"


def test_explicit_mcp_changes_suppresses_underlying_monkeypatch_recording():
    modules, _calls, _names, _memory, _fake_tinfo = _fake_modules()
    recorder = ChangeRecorder()
    recorder.install(modules)
    api = McpChangesApi(recorder, modules)

    try:
        assert api.rename(BASE_EA, "entry") is True
    finally:
        recorder.uninstall()

    assert len(recorder.operations) == 1
    assert recorder.operations[0].op == "rename"
    assert recorder.operations[0].source == "explicit_api"


def test_explicit_mcp_changes_missing_module_raises_recorder_error():
    recorder = ChangeRecorder()
    api = McpChangesApi(recorder, {})

    with pytest.raises(RecorderError, match="idc"):
        api.rename(BASE_EA, "entry")

    assert recorder.operations == []


def test_strict_install_missing_common_api_raises_and_restores_patches():
    modules, _calls, _names, _memory, _fake_tinfo = _fake_modules()
    original = modules["idc"].set_name
    del modules["ida_typeinf"]
    recorder = ChangeRecorder()

    with pytest.raises(RecorderError, match="ida_typeinf"):
        recorder.install(modules)

    assert modules["idc"].set_name is original
    assert recorder.operations == []


def test_install_accepts_ida_83_settype_without_set_type_alias():
    modules, calls, _names, _memory, _fake_tinfo = _fake_modules()
    delattr(modules["idc"], "set_type")
    recorder = ChangeRecorder()
    recorder.install(modules)

    try:
        assert modules["idc"].SetType(BASE_EA, "int __cdecl main(void)") is True
    finally:
        recorder.uninstall()

    assert calls[-1] == ("set_type", BASE_EA, "int __cdecl main(void)")
    assert recorder.operations[0].op == "set_type"
    assert recorder.operations[0].decl == "int __cdecl main(void)"
    assert recorder.operations[0].source == "monkeypatch"


def test_install_accepts_lowercase_set_type_without_settype_alias():
    modules, calls, _names, _memory, _fake_tinfo = _fake_modules()
    delattr(modules["idc"], "SetType")
    recorder = ChangeRecorder()
    recorder.install(modules)

    try:
        assert modules["idc"].set_type(BASE_EA, "int __cdecl main(void)") is True
    finally:
        recorder.uninstall()

    assert calls[-1] == ("set_type", BASE_EA, "int __cdecl main(void)")
    assert recorder.operations[0].op == "set_type"


def test_install_requires_at_least_one_idc_type_alias():
    modules, _calls, _names, _memory, _fake_tinfo = _fake_modules()
    original = modules["idc"].set_name
    delattr(modules["idc"], "SetType")
    delattr(modules["idc"], "set_type")
    recorder = ChangeRecorder()

    with pytest.raises(RecorderError, match="idc.SetType/idc.set_type"):
        recorder.install(modules)

    assert modules["idc"].set_name is original
    assert recorder.operations == []


def test_explicit_mcp_changes_set_type_falls_back_to_settype_alias():
    modules, calls, _names, _memory, _fake_tinfo = _fake_modules()
    delattr(modules["idc"], "set_type")
    recorder = ChangeRecorder()
    api = McpChangesApi(recorder, modules)

    assert api.set_type(BASE_EA, "int __cdecl entry(void)") is True

    assert calls[-1] == ("set_type", BASE_EA, "int __cdecl entry(void)")
    assert recorder.operations[0].op == "set_type"
    assert recorder.operations[0].source == "explicit_api"


def test_patch_byte_captures_old_bytes_before_write():
    modules, _calls, _names, memory, _fake_tinfo = _fake_modules()
    old_byte = bytes(memory[0:1]).hex()
    recorder = ChangeRecorder()
    recorder.install(modules)

    try:
        assert modules["idc"].patch_byte(BASE_EA, 0x90) is True
    finally:
        recorder.uninstall()

    assert recorder.operations[0].op == "patch_bytes"
    assert recorder.operations[0].old_bytes_hex == old_byte
    assert recorder.operations[0].new_bytes_hex == "90"


def test_apply_tinfo_monkeypatch_records_printable_type():
    modules, _calls, _names, _memory, fake_tinfo_type = _fake_modules()
    recorder = ChangeRecorder()
    recorder.install(modules)

    try:
        assert modules["ida_typeinf"].apply_tinfo(BASE_EA, fake_tinfo_type(), 7) is True
    finally:
        recorder.uninstall()

    assert recorder.operations[0].op == "set_type"
    assert recorder.operations[0].decl == "int __cdecl main(void)"
    assert recorder.operations[0].flags == 7
    assert recorder.operations[0].source == "monkeypatch"
