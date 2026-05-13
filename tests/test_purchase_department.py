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


def test_create_purchase_with_note_lines_renders_bullets(server, captured_qb_json):
    m, _ = server
    _tool(m, "qb_create_purchase")(
        payment_type="CreditCard",
        account_id="42",
        line_items=[{"amount": 20, "expense_account_id": "6116", "description": "Etisalat"}],
        private_note_lines=[
            "NEW YORK FRIES DUBAI",
            "Source: CC statement Mar 2026",
            "Category: 6116 Utilities",
        ],
    )
    posted = next(c for c in captured_qb_json if c["method"].upper() == "POST" and c["path"] == "/purchase")
    note = posted["json_body"]["PrivateNote"]
    assert note == "• NEW YORK FRIES DUBAI\n• Source: CC statement Mar 2026\n• Category: 6116 Utilities"


def test_create_purchase_rejects_both_note_paragraph_and_lines(server):
    m, _ = server
    with pytest.raises(m.QuickBooksError) as exc:
        _tool(m, "qb_create_purchase")(
            payment_type="CreditCard",
            account_id="42",
            line_items=[{"amount": 20, "expense_account_id": "6116"}],
            private_note="paragraph",
            private_note_lines=["bullet"],
        )
    assert exc.value.status_code == 400
    assert "not both" in str(exc.value).lower()


def test_update_purchase_patch_note_lines(server, captured_qb_json):
    m, _ = server
    _tool(m, "qb_update_purchase")(
        purchase_id="20634",
        sync_token="3",
        patch={"private_note_lines": ["First", "Second", "Third"]},
        verify_after_update=False,
    )
    posted = next(c for c in captured_qb_json if c["method"].upper() == "POST" and c["path"] == "/purchase")
    assert posted["json_body"]["PrivateNote"] == "• First\n• Second\n• Third"


def test_update_purchase_rejects_multiple_note_modes(server):
    m, _ = server
    with pytest.raises(m.QuickBooksError) as exc:
        _tool(m, "qb_update_purchase")(
            purchase_id="20634",
            sync_token="3",
            patch={
                "private_note": "p",
                "private_note_lines": ["l"],
            },
            verify_after_update=False,
        )
    assert "ONE of" in str(exc.value)


def test_note_lines_skip_empty_and_strip_existing_bullets(server, captured_qb_json):
    m, _ = server
    _tool(m, "qb_create_purchase")(
        payment_type="CreditCard",
        account_id="42",
        line_items=[{"amount": 20, "expense_account_id": "6116"}],
        private_note_lines=[
            "• already-bulleted",
            "",
            None,
            "  - dash-prefix  ",
            "plain",
        ],
    )
    posted = next(c for c in captured_qb_json if c["method"].upper() == "POST" and c["path"] == "/purchase")
    assert posted["json_body"]["PrivateNote"] == "• already-bulleted\n• dash-prefix\n• plain"


def test_create_je_with_note_lines(server, captured_qb_json):
    m, _ = server
    m.SETTINGS.enable_journal_write = True
    _tool(m, "qb_create_journal_entry")(
        line_items=[
            {"amount": 100, "posting_type": "Debit", "account_id": "1"},
            {"amount": 100, "posting_type": "Credit", "account_id": "2"},
        ],
        private_note_lines=["JE bullet one", "JE bullet two"],
    )
    posted = next(c for c in captured_qb_json if c["method"].upper() == "POST" and c["path"] == "/journalentry")
    assert posted["json_body"]["PrivateNote"] == "• JE bullet one\n• JE bullet two"
