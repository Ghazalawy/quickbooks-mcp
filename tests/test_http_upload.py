"""Tests for the v2.4.0 POST /upload-attachable HTTP endpoint.

Verifies the endpoint bypasses the MCP tool-call wall — multipart bytes
go straight from the HTTP body into the QB upload pipeline. No base64.
"""
from __future__ import annotations

from io import BytesIO

import pytest


@pytest.fixture
def client(server, captured_qb_upload, monkeypatch):
    m, _ = server
    m.SETTINGS.mcp_bearer_token = "test-secret-bearer"
    monkeypatch.setattr(m, "AccessControlMiddleware", m.AccessControlMiddleware)
    from starlette.testclient import TestClient
    return TestClient(m.app), m


def test_upload_rejects_missing_bearer(client):
    tc, _ = client
    resp = tc.post(
        "/upload-attachable",
        files={"file": ("e.pdf", BytesIO(b"%PDF-1.4 hi"), "application/pdf")},
        data={"link_to_txn_id": "20634", "link_to_txn_type": "Purchase"},
    )
    assert resp.status_code == 401


def test_upload_rejects_wrong_bearer(client):
    tc, _ = client
    resp = tc.post(
        "/upload-attachable",
        headers={"Authorization": "Bearer wrong"},
        files={"file": ("e.pdf", BytesIO(b"%PDF-1.4 hi"), "application/pdf")},
        data={"link_to_txn_id": "20634", "link_to_txn_type": "Purchase"},
    )
    assert resp.status_code == 401


def test_upload_streams_raw_bytes_not_b64(client, captured_qb_upload):
    tc, m = client
    pdf_bytes = b"%PDF-1.7 actual PDF body padding " * 200
    resp = tc.post(
        "/upload-attachable",
        headers={"Authorization": "Bearer test-secret-bearer"},
        files={"file": ("eticket.pdf", BytesIO(pdf_bytes), "application/pdf")},
        data={
            "link_to_txn_id": "20634",
            "link_to_txn_type": "Purchase",
            "note": "test note",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resolved_filename"] == "eticket.pdf"
    assert body["resolved_size_bytes"] == len(pdf_bytes)

    captured = captured_qb_upload[0]
    assert captured["file_content_0"]["bytes"] == pdf_bytes
    assert captured["file_content_0"]["bytes"].startswith(b"%PDF-")


def test_upload_rejects_oversized(client):
    tc, m = client
    m.SETTINGS.max_attachment_size_bytes = 1024
    big = b"\x00" * 2048
    resp = tc.post(
        "/upload-attachable",
        headers={"Authorization": "Bearer test-secret-bearer"},
        files={"file": ("big.bin", BytesIO(big), "application/octet-stream")},
        data={"link_to_txn_id": "20634", "link_to_txn_type": "Purchase"},
    )
    assert resp.status_code == 413
    assert "exceeds" in resp.json().get("error", "").lower()


def test_upload_rejects_missing_file_part(client):
    tc, _ = client
    resp = tc.post(
        "/upload-attachable",
        headers={"Authorization": "Bearer test-secret-bearer"},
        data={"link_to_txn_id": "20634", "link_to_txn_type": "Purchase"},
    )
    assert resp.status_code == 400
    assert "file" in resp.json().get("error", "").lower()


def test_upload_returns_attachable_id(client, captured_qb_upload):
    tc, _ = client
    resp = tc.post(
        "/upload-attachable",
        headers={"Authorization": "Bearer test-secret-bearer"},
        files={"file": ("r.pdf", BytesIO(b"%PDF-x"), "application/pdf")},
        data={"link_to_txn_id": "20634", "link_to_txn_type": "Purchase"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["attachables"][0]["Id"] == "65279999"


def test_upload_disabled_when_flag_off(client):
    tc, m = client
    m.SETTINGS.enable_attachable_write = False
    resp = tc.post(
        "/upload-attachable",
        headers={"Authorization": "Bearer test-secret-bearer"},
        files={"file": ("r.pdf", BytesIO(b"%PDF"), "application/pdf")},
        data={"link_to_txn_id": "20634", "link_to_txn_type": "Purchase"},
    )
    assert resp.status_code == 403


def test_upload_filename_override(client, captured_qb_upload):
    tc, _ = client
    resp = tc.post(
        "/upload-attachable",
        headers={"Authorization": "Bearer test-secret-bearer"},
        files={"file": ("ugly-temp-name.bin", BytesIO(b"%PDF-renamed"), "application/octet-stream")},
        data={
            "link_to_txn_id": "20634",
            "link_to_txn_type": "Purchase",
            "filename": "Saudia_ETicket_065-2197177925.pdf",
            "mime": "application/pdf",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["resolved_filename"] == "Saudia_ETicket_065-2197177925.pdf"
    assert body["resolved_mime"] == "application/pdf"
