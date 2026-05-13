"""Pytest fixtures for the QuickBooks MCP test suite.

These tests exercise the v2.3.0 attachable and purchase tools without touching
the live QuickBooks API or Microsoft Graph. We stub `requests.get` and
`QuickBooksClient.upload_multipart` / `.request` so the tool functions can run
their full validation + idempotency + audit-logging paths offline.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def server(monkeypatch, tmp_path):
    """Import the server module fresh with a minimal env, attachable allowlist
    rooted at tmp_path, and a stub QB connection so pick_realm_id resolves."""
    os.environ.setdefault("QB_CLIENT_ID", "dummy-client")
    os.environ.setdefault("QB_CLIENT_SECRET", "dummy-secret")
    os.environ.setdefault("APP_ENV", "development")

    allowlist_dir = tmp_path / "allowed"
    allowlist_dir.mkdir()
    os.environ["QB_ATTACHABLE_PATH_ALLOWLIST"] = str(allowlist_dir)

    if "quickbooks_mcp_server_prod" in sys.modules:
        del sys.modules["quickbooks_mcp_server_prod"]
    import quickbooks_mcp_server_prod as m

    m.SETTINGS.enable_attachable_write = True
    m.SETTINGS.enable_purchase_write = True
    m.SETTINGS.require_idempotency_key = False
    m.SETTINGS.attachable_path_allowlist_raw = str(allowlist_dir)

    monkeypatch.setattr(m, "pick_realm_id", lambda company_ref=None: "test-realm-9999")
    monkeypatch.setattr(m, "ensure_fresh_connection", lambda realm_id: {"access_token": "stub-token"})

    class _NoopAuditStore:
        @staticmethod
        def write(**kwargs):
            return None

    monkeypatch.setattr(m, "AuditStore", _NoopAuditStore)

    class _NoopIdem:
        @staticmethod
        def get(_k):
            return None

        @staticmethod
        def put(*a, **kw):
            return None

    monkeypatch.setattr(m, "IdempotencyStore", _NoopIdem)
    return m, allowlist_dir


@pytest.fixture
def captured_qb_upload(monkeypatch, server):
    """Capture every multipart QB /upload call so tests can assert on the body."""
    m, _ = server
    captures: List[Dict[str, Any]] = []

    def _stub_upload_multipart(realm_id: str, path: str, files: list) -> Dict[str, Any]:
        captured = {"realm_id": realm_id, "path": path}
        for name, tup in files:
            captured[name] = {"filename": tup[0], "bytes": tup[1], "content_type": tup[2]}
        captures.append(captured)
        return {
            "AttachableResponse": [
                {"Attachable": {
                    "Id": "65279999",
                    "FileName": captured.get("file_content_0", {}).get("filename", "x"),
                    "FileAccessUri": "https://example.com/file/65279999",
                }}
            ]
        }

    monkeypatch.setattr(m.qb_client, "upload_multipart", _stub_upload_multipart)
    return captures


@pytest.fixture
def captured_qb_json(monkeypatch, server):
    """Capture every JSON POST/GET QB call (purchase create/update)."""
    m, _ = server
    captures: List[Dict[str, Any]] = []

    def _stub_request(realm_id, method, path, *, params=None, json_body=None, data=None, content_type="application/json"):
        captures.append({
            "realm_id": realm_id,
            "method": method,
            "path": path,
            "params": params,
            "json_body": json_body,
        })
        if method.upper() == "GET" and path.startswith("/purchase/"):
            pid = path.rsplit("/", 1)[-1]
            return {"Purchase": {"Id": pid, "SyncToken": "0", "Line": [], "TotalAmt": 0, "PrivateNote": ""}}
        if path.startswith("/purchase"):
            body = dict(json_body or {})
            body.setdefault("Id", "20634")
            body.setdefault("SyncToken", "1")
            body.setdefault("TotalAmt", sum(float(ln.get("Amount", 0)) for ln in body.get("Line", []) or []))
            return {"Purchase": body}
        if path.startswith("/journalentry"):
            body = dict(json_body or {})
            body.setdefault("Id", "30001")
            body.setdefault("SyncToken", "0")
            return {"JournalEntry": body}
        return {}

    monkeypatch.setattr(m.qb_client, "request", _stub_request)
    return captures
