"""Tests for the v2.3.0 department_id support on qb_create_purchase /
qb_update_purchase. Verifies that DepartmentRef makes it into the QB payload."""
from __future__ import annotations

import pytest


def _tool(m, name):
    return m.mcp._tool_manager._tools[name].fn


def test_create_purchase_with_department(server, captured_qb_json):
    m, _ = server
    _tool(m, "qb_create_purchase")(
        payment_type="CreditCard",
        account_id="42",
        line_items=[{"amount": 100, "expense_account_id": "6116", "description": "Etisalat"}],
        department_id="5",
    )
    posted = next(c for c in captured_qb_json if c["method"].upper() == "POST" and c["path"] == "/purchase")
    assert posted["json_body"]["DepartmentRef"] == {"value": "5"}


def test_create_purchase_without_department_omits_field(server, captured_qb_json):
    m, _ = server
    _tool(m, "qb_create_purchase")(
        payment_type="CreditCard",
        account_id="42",
        line_items=[{"amount": 100, "expense_account_id": "6116", "description": "Etisalat"}],
    )
    posted = next(c for c in captured_qb_json if c["method"].upper() == "POST" and c["path"] == "/purchase")
    assert "DepartmentRef" not in posted["json_body"]


def test_update_purchase_patches_department(server, captured_qb_json):
    m, _ = server
    _tool(m, "qb_update_purchase")(
        purchase_id="20634",
        sync_token="3",
        patch={"department_id": "5"},
        verify_after_update=False,
    )
    posted = next(c for c in captured_qb_json if c["method"].upper() == "POST" and c["path"] == "/purchase")
    assert posted["json_body"]["DepartmentRef"] == {"value": "5"}
    assert posted["json_body"]["Id"] == "20634"
    assert posted["json_body"]["SyncToken"] == "3"
    assert posted["json_body"]["sparse"] is True


def test_update_purchase_clears_department_with_null(server, captured_qb_json):
    m, _ = server
    _tool(m, "qb_update_purchase")(
        purchase_id="20634",
        sync_token="3",
        patch={"department_id": None},
        verify_after_update=False,
    )
    posted = next(c for c in captured_qb_json if c["method"].upper() == "POST" and c["path"] == "/purchase")
    assert posted["json_body"]["DepartmentRef"] is None
