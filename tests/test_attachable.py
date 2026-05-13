"""Tests for the v2.3.0 attachable surface — focused source tools plus the
existing multi-mode qb_create_attachable.

The key invariant we care about: file_path / file_url / from_email_attachment
modes must stream raw bytes into the QB multipart body. They must NEVER
base64-encode the content (that's the whole point of these modes — to dodge
the per-MCP-call size budget that base64 imposes).
"""
from __future__ import annotations

import base64
from io import BytesIO

import pytest


def _tool(m, name):
    return m.mcp._tool_manager._tools[name].fn


def _fake_response(*, status=200, content=b"", headers=None, json_body=None):
    """Build a minimal stand-in for a requests.Response with iter_content + .json()."""
    class _Resp:
        def __init__(self):
            self.status_code = status
            self.headers = headers or {}
            self._content = content
            self._json = json_body
            self.text = (content or b"").decode("utf-8", errors="replace")[:500]

        def iter_content(self, chunk_size=65536):
            buf = BytesIO(self._content)
            while True:
                c = buf.read(chunk_size)
                if not c:
                    return
                yield c

        def json(self):
            return self._json

    return _Resp()


def test_attach_from_email_streams_no_b64(server, captured_qb_upload, monkeypatch):
    m, _ = server
    pdf_bytes = b"%PDF-1.4 fake PDF body padding " * 100  # well over inline budget

    def _stub_graph_get(url, headers=None, timeout=None, stream=False, allow_redirects=True):
        if url.endswith("/$value"):
            return _fake_response(status=200, content=pdf_bytes)
        return _fake_response(
            status=200,
            json_body={"name": "Saudia-eticket.pdf", "contentType": "application/pdf", "size": len(pdf_bytes)},
        )

    monkeypatch.setattr(m.requests, "get", _stub_graph_get)

    result = _tool(m, "qb_create_attachable_from_email")(
        mailbox="info@prizm-energy.com",
        email_id="AAMkAD-test-email",
        attachment_id="AAMkAD-test-att",
        link_to_txn_id="20634",
        link_to_txn_type="Purchase",
        graph_access_token="eyJ.GRAPH.TOKEN",
    )

    assert result["attachables"][0]["Id"] == "65279999"
    assert result["resolved_size_bytes"] == len(pdf_bytes)

    captured = captured_qb_upload[0]
    assert captured["path"] == "/upload"
    body_bytes = captured["file_content_0"]["bytes"]
    assert body_bytes == pdf_bytes
    assert body_bytes.startswith(b"%PDF-")
    try:
        decoded = base64.b64decode(body_bytes, validate=True)
        assert decoded != pdf_bytes, "QB body must be raw bytes, not base64-encoded"
    except Exception:
        pass


def test_attach_from_path_streams_raw_bytes(server, captured_qb_upload):
    m, allowlist_dir = server
    fpath = allowlist_dir / "receipt.pdf"
    pdf_bytes = b"%PDF-1.7 hello world " * 50
    fpath.write_bytes(pdf_bytes)

    result = _tool(m, "qb_create_attachable_from_path")(
        file_path=str(fpath),
        link_to_txn_id="20634",
        link_to_txn_type="Purchase",
    )
    assert result["resolved_filename"] == "receipt.pdf"
    assert result["resolved_mime"] == "application/pdf"
    assert captured_qb_upload[0]["file_content_0"]["bytes"] == pdf_bytes


def test_attach_from_path_rejects_outside_allowlist(server, tmp_path):
    m, _ = server
    outside = tmp_path / "outside" / "secret.pdf"
    outside.parent.mkdir()
    outside.write_bytes(b"%PDF-1.4 secret")

    with pytest.raises(m.QuickBooksError) as exc:
        _tool(m, "qb_create_attachable_from_path")(
            file_path=str(outside),
            link_to_txn_id="20634",
            link_to_txn_type="Purchase",
        )
    assert "allowlist" in str(exc.value).lower()
    assert exc.value.status_code == 403


def test_attach_from_path_rejects_missing_file(server):
    m, _ = server
    with pytest.raises(m.QuickBooksError) as exc:
        _tool(m, "qb_create_attachable_from_path")(
            file_path="/nonexistent/nope.pdf",
            link_to_txn_id="20634",
            link_to_txn_type="Purchase",
        )
    assert exc.value.status_code == 404


def test_attach_from_path_rejects_oversized(server):
    m, allowlist_dir = server
    m.SETTINGS.max_attachment_size_bytes = 1024
    big = allowlist_dir / "big.bin"
    big.write_bytes(b"\x00" * 2048)
    with pytest.raises(m.QuickBooksError) as exc:
        _tool(m, "qb_create_attachable_from_path")(
            file_path=str(big),
            link_to_txn_id="20634",
            link_to_txn_type="Purchase",
        )
    assert "size" in str(exc.value).lower() or "limit" in str(exc.value).lower()


def test_attach_from_email_requires_token(server):
    m, _ = server
    with pytest.raises(m.QuickBooksError) as exc:
        _tool(m, "qb_create_attachable_from_email")(
            mailbox="me",
            email_id="X",
            attachment_id="Y",
            link_to_txn_id="20634",
            link_to_txn_type="Purchase",
        )
    assert "graph_access_token" in str(exc.value).lower()
    assert exc.value.status_code == 400


def test_attach_from_email_uses_me_path(server, captured_qb_upload, monkeypatch):
    m, _ = server
    captured_urls = []

    def _stub_get(url, headers=None, timeout=None, stream=False, allow_redirects=True):
        captured_urls.append(url)
        if url.endswith("/$value"):
            return _fake_response(status=200, content=b"%PDF-tiny")
        return _fake_response(status=200, json_body={"name": "f.pdf", "contentType": "application/pdf"})

    monkeypatch.setattr(m.requests, "get", _stub_get)

    _tool(m, "qb_create_attachable_from_email")(
        mailbox="me",
        email_id="abc",
        attachment_id="xyz",
        link_to_txn_id="20634",
        link_to_txn_type="Purchase",
        graph_access_token="t",
    )
    assert any("/me/messages/abc/attachments/xyz" in u for u in captured_urls)


def test_attach_from_email_uses_users_path(server, captured_qb_upload, monkeypatch):
    m, _ = server
    captured_urls = []

    def _stub_get(url, headers=None, timeout=None, stream=False, allow_redirects=True):
        captured_urls.append(url)
        if url.endswith("/$value"):
            return _fake_response(status=200, content=b"%PDF-tiny")
        return _fake_response(status=200, json_body={"name": "f.pdf", "contentType": "application/pdf"})

    monkeypatch.setattr(m.requests, "get", _stub_get)

    _tool(m, "qb_create_attachable_from_email")(
        mailbox="info@prizm-energy.com",
        email_id="abc",
        attachment_id="xyz",
        link_to_txn_id="20634",
        link_to_txn_type="Purchase",
        graph_access_token="t",
    )
    assert any("/users/info@prizm-energy.com/messages/abc" in u for u in captured_urls)


def test_legacy_b64_mode_still_works(server, captured_qb_upload):
    m, _ = server
    pdf_bytes = b"%PDF-1.7 legacy"
    b64 = base64.b64encode(pdf_bytes).decode()

    result = _tool(m, "qb_create_attachable")(
        filename="legacy.pdf",
        mime="application/pdf",
        file_bytes_b64=b64,
        link_to_txn_id="20634",
        link_to_txn_type="Purchase",
    )
    assert result["resolved_size_bytes"] == len(pdf_bytes)
    assert captured_qb_upload[0]["file_content_0"]["bytes"] == pdf_bytes


def test_audit_log_redacts_graph_token(server, monkeypatch):
    m, _ = server
    captured_payloads = []

    class _AuditCapture:
        @staticmethod
        def write(**kwargs):
            captured_payloads.append(kwargs)

    monkeypatch.setattr(m, "AuditStore", _AuditCapture)

    def _stub_get(url, headers=None, timeout=None, stream=False, allow_redirects=True):
        return _fake_response(status=401, json_body={"error": "denied"})

    monkeypatch.setattr(m.requests, "get", _stub_get)

    with pytest.raises(m.QuickBooksError):
        _tool(m, "qb_create_attachable_from_email")(
            mailbox="me",
            email_id="X",
            attachment_id="Y",
            link_to_txn_id="20634",
            link_to_txn_type="Purchase",
            graph_access_token="eyJ.SECRET.SHOULD.NOT.LEAK",
        )

    leaked = any("eyJ.SECRET.SHOULD.NOT.LEAK" in str(rec) for rec in captured_payloads)
    assert not leaked, f"Graph access token leaked into audit log: {captured_payloads}"
