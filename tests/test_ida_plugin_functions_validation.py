from __future__ import annotations

import pytest

from ida_script_mcp import ida_plugin


def test_functions_int_param_accepts_numeric_strings_and_bounds() -> None:
    payload = {"offset": "0", "limit": "5000"}

    assert ida_plugin._coerce_int_param(payload, "offset", 99, minimum=0) == 0
    assert (
        ida_plugin._coerce_int_param(
            payload,
            "limit",
            200,
            minimum=1,
            maximum=ida_plugin.MAX_FUNCTIONS_LIMIT,
        )
        == 5000
    )


def test_functions_int_param_rejects_invalid_values() -> None:
    cases = [
        ({"offset": -1}, "offset", 0, 0, None),
        ({"offset": "not-an-int"}, "offset", 0, 0, None),
        ({"limit": 0}, "limit", 200, 1, ida_plugin.MAX_FUNCTIONS_LIMIT),
        ({"limit": -1}, "limit", 200, 1, ida_plugin.MAX_FUNCTIONS_LIMIT),
        (
            {"limit": ida_plugin.MAX_FUNCTIONS_LIMIT + 1},
            "limit",
            200,
            1,
            ida_plugin.MAX_FUNCTIONS_LIMIT,
        ),
        ({"limit": True}, "limit", 200, 1, ida_plugin.MAX_FUNCTIONS_LIMIT),
    ]

    for payload, field, default, minimum, maximum in cases:
        with pytest.raises(ida_plugin.RequestValidationError) as exc_info:
            ida_plugin._coerce_int_param(
                payload,
                field,
                default,
                minimum=minimum,
                maximum=maximum,
            )
        assert exc_info.value.field == field


def test_functions_bool_param_accepts_bool_and_boolean_strings() -> None:
    assert ida_plugin._coerce_bool_param({"include_thunks": True}, "include_thunks", False) is True
    assert (
        ida_plugin._coerce_bool_param({"include_thunks": "false"}, "include_thunks", True)
        is False
    )
    assert ida_plugin._coerce_bool_param({"include_thunks": "1"}, "include_thunks", False) is True
    assert ida_plugin._coerce_bool_param({}, "include_thunks", False) is False


def test_functions_bool_param_rejects_invalid_strings() -> None:
    with pytest.raises(ida_plugin.RequestValidationError) as exc_info:
        ida_plugin._coerce_bool_param({"include_thunks": "not-bool"}, "include_thunks", False)

    assert exc_info.value.field == "include_thunks"


def test_functions_optional_str_param_rejects_non_strings() -> None:
    assert (
        ida_plugin._coerce_optional_str_param({"name_contains": "☃_*[]"}, "name_contains")
        == "☃_*[]"
    )
    assert ida_plugin._coerce_optional_str_param({}, "name_contains") is None

    with pytest.raises(ida_plugin.RequestValidationError) as exc_info:
        ida_plugin._coerce_optional_str_param({"name_contains": 123}, "name_contains")

    assert exc_info.value.field == "name_contains"
