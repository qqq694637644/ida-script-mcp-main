from __future__ import annotations

from ida_script_mcp.ida_plugin import IdaScriptHttpHandler, _unsafe_gui_execute_enabled


def _run_execute_handler(monkeypatch, *, env_value=None):
    if env_value is None:
        monkeypatch.delenv("IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE", raising=False)
    else:
        monkeypatch.setenv("IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE", env_value)

    handler = object.__new__(IdaScriptHttpHandler)
    handler.path = "/execute"
    responses = []
    handler._read_json_body = lambda: {"code": "result = 1"}
    handler._send_json_response = lambda status, payload: responses.append((status, payload))
    handler.do_POST()
    return responses


def test_unsafe_gui_execute_disabled_by_default(monkeypatch):
    assert _run_execute_handler(monkeypatch) == [
        (
            410,
            {
                "status": "rejected",
                "error": "GUI /execute is disabled by default; use isolated worker execution.",
            },
        )
    ]


def test_unsafe_gui_execute_env_gate(monkeypatch):
    assert _unsafe_gui_execute_enabled() is False
    monkeypatch.setenv("IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE", "1")
    assert _unsafe_gui_execute_enabled() is True
