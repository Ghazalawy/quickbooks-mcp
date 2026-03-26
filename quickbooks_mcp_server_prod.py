#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlencode

import requests
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from sqlalchemy import Boolean, Integer, String, Text, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
import uvicorn

APP_NAME = "QuickBooks Online MCP Server"
APP_VERSION = "2.0.0"  # 62 tools, production-ready
DEFAULT_SCOPE = "com.intuit.quickbooks.accounting"
SANDBOX_DISCOVERY = "https://developer.api.intuit.com/.well-known/openid_sandbox_configuration"
PRODUCTION_DISCOVERY = "https://developer.api.intuit.com/.well-known/openid_configuration"
SANDBOX_API_BASE = "https://sandbox-quickbooks.api.intuit.com"
PRODUCTION_API_BASE = "https://quickbooks.api.intuit.com"
DEFAULT_PORT = 8765
DISCOVERY_CACHE: Dict[str, Any] = {}

load_dotenv()


@dataclass
class Settings:
    app_env: str = os.getenv("APP_ENV", "production").strip().lower()
    log_level: str = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    log_file: str = os.getenv("LOG_FILE", "").strip()

    public_base_url: str = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    host: str = os.getenv("HOST", "0.0.0.0").strip()
    port: int = int(os.getenv("PORT", str(DEFAULT_PORT)).strip())
    allowed_hosts_raw: str = os.getenv("ALLOWED_HOSTS", "*").strip()

    mcp_bearer_token: str = os.getenv("MCP_BEARER_TOKEN", "").strip()
    admin_username: str = os.getenv("ADMIN_USERNAME", "admin").strip()
    admin_password: str = os.getenv("ADMIN_PASSWORD", "").strip()

    qb_client_id: str = os.getenv("QB_CLIENT_ID", "").strip()
    qb_client_secret: str = os.getenv("QB_CLIENT_SECRET", "").strip()
    qb_redirect_uri: str = os.getenv("QB_REDIRECT_URI", "").strip()
    qb_environment: str = os.getenv("QB_ENVIRONMENT", "production").strip().lower()
    qb_scopes: str = os.getenv("QB_SCOPES", DEFAULT_SCOPE).strip()
    qb_default_realm_id: str = os.getenv("QB_DEFAULT_REALM_ID", "").strip()

    db_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/quickbooks_mcp.sqlite3").strip()
    token_encryption_key: str = os.getenv("QB_TOKEN_ENCRYPTION_KEY", "").strip()

    request_timeout_seconds: int = int(os.getenv("QB_REQUEST_TIMEOUT_SECONDS", "45").strip())
    retry_attempts: int = int(os.getenv("QB_RETRY_ATTEMPTS", "3").strip())

    enable_invoice_write: bool = os.getenv("QB_ENABLE_INVOICE_WRITE", "false").strip().lower() in {"1", "true", "yes", "on"}
    max_invoice_total: str = os.getenv("QB_MAX_INVOICE_TOTAL", "50000.00").strip()
    require_idempotency_key: bool = os.getenv("QB_REQUIRE_IDEMPOTENCY_KEY", "true").strip().lower() in {"1", "true", "yes", "on"}

    status_page_enabled: bool = os.getenv("STATUS_PAGE_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
    cors_allow_origins_raw: str = os.getenv("CORS_ALLOW_ORIGINS", "").strip()

    @property
    def allowed_hosts(self) -> List[str]:
        return [x.strip() for x in self.allowed_hosts_raw.split(",") if x.strip()] or ["*"]

    @property
    def cors_allow_origins(self) -> List[str]:
        return [x.strip() for x in self.cors_allow_origins_raw.split(",") if x.strip()]

    @property
    def discovery_url(self) -> str:
        return SANDBOX_DISCOVERY if self.qb_environment == "sandbox" else PRODUCTION_DISCOVERY

    @property
    def api_base_url(self) -> str:
        return SANDBOX_API_BASE if self.qb_environment == "sandbox" else PRODUCTION_API_BASE

    @property
    def redirect_uri(self) -> str:
        if self.qb_redirect_uri:
            return self.qb_redirect_uri
        if self.public_base_url:
            return f"{self.public_base_url}/auth/callback"
        return f"http://localhost:{self.port}/auth/callback"

    @property
    def max_invoice_total_decimal(self) -> Decimal:
        return Decimal(self.max_invoice_total)


SETTINGS = Settings()


class Base(DeclarativeBase):
    pass


class OAuthState(Base):
    __tablename__ = "oauth_state"

    state: Mapped[str] = mapped_column(String(255), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)


class QBConnection(Base):
    __tablename__ = "qb_connections"

    realm_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    company_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    connection_label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_token: Mapped[str] = mapped_column(Text, nullable=False)
    access_expires_at: Mapped[int] = mapped_column(Integer, nullable=False)
    refresh_expires_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    scope: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    realm_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    request_json: Mapped[str] = mapped_column(Text, nullable=False)
    response_json: Mapped[str] = mapped_column(Text, nullable=False)
    error_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def ensure_parent_dir_from_db_url(db_url: str) -> None:
    if not db_url.startswith("sqlite:///"):
        return
    db_path = db_url.replace("sqlite:///", "", 1)
    if db_path == ":memory:":
        return
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)


ensure_parent_dir_from_db_url(SETTINGS.db_url)

engine_kwargs: Dict[str, Any] = {"pool_pre_ping": True}
if SETTINGS.db_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(SETTINGS.db_url, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
Base.metadata.create_all(engine)

if SETTINGS.db_url.startswith("sqlite"):
    with engine.begin() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
        conn.exec_driver_sql("PRAGMA busy_timeout=5000")


class TokenCipher:
    def __init__(self, key: str):
        self._fernet = Fernet(key.encode("utf-8")) if key else None

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    def encrypt(self, value: str) -> str:
        if not value:
            return ""
        if self._fernet is None:
            return value
        return self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt(self, value: str) -> str:
        if not value:
            return ""
        if self._fernet is None:
            return value
        try:
            return self._fernet.decrypt(value.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("Token decryption failed. Check QB_TOKEN_ENCRYPTION_KEY.") from exc


TOKEN_CIPHER = TokenCipher(SETTINGS.token_encryption_key)


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("quickbooks_mcp")
    logger.setLevel(getattr(logging, SETTINGS.log_level, logging.INFO))
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.handlers = [sh]
    if SETTINGS.log_file:
        os.makedirs(os.path.dirname(os.path.abspath(SETTINGS.log_file)), exist_ok=True)
        fh = RotatingFileHandler(SETTINGS.log_file, maxBytes=5_000_000, backupCount=5)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger


logger = configure_logging()


class QuickBooksError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 500, payload: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload or {}


def redacted_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def get_db() -> Session:
    return SessionLocal()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def require_admin(request: Request) -> None:
    if not SETTINGS.admin_password:
        raise QuickBooksError("Admin password is not configured.", status_code=500)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        raise QuickBooksError("Admin authentication required.", status_code=401)
    try:
        decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception as exc:
        raise QuickBooksError("Invalid admin authentication header.", status_code=401) from exc
    if not constant_time_equal(username, SETTINGS.admin_username) or not constant_time_equal(password, SETTINGS.admin_password):
        raise QuickBooksError("Invalid admin credentials.", status_code=401)



class AccessControlMiddleware(BaseHTTPMiddleware):
    # Paths that bypass all auth (OAuth discovery + health)
    PUBLIC_PATHS = frozenset({
        '/.well-known/oauth-protected-resource',
        '/.well-known/oauth-authorization-server',
        '/oauth/register',
        '/oauth/authorize',
        '/oauth/token',
        '/healthz',
        '/readyz',
    })

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Public endpoints — no auth required
        if path in self.PUBLIC_PATHS:
            return await call_next(request)
        # Admin pages require Basic Auth
        if path in {'/', '/status', '/auth/connect'} or path.startswith('/auth/disconnect'):
            require_admin(request)
        # MCP endpoint — accept bearer token OR OAuth access token
        if path.startswith('/mcp') or path.startswith('/sse'):
            if SETTINGS.mcp_bearer_token:
                auth = request.headers.get('Authorization', '')
                if not auth.startswith('Bearer '):
                    raise QuickBooksError('Missing bearer token for MCP endpoint.', status_code=401)
                token = auth.split(' ', 1)[1]
                if not constant_time_equal(token, SETTINGS.mcp_bearer_token):
                    raise QuickBooksError('Invalid MCP bearer token.', status_code=401)
        return await call_next(request)


class StateStore:
    @staticmethod
    def put(state: str) -> None:
        with get_db() as db:
            db.merge(OAuthState(state=state, created_at=iso_now()))
            db.commit()

    @staticmethod
    def consume(state: str) -> bool:
        with get_db() as db:
            row = db.get(OAuthState, state)
            if row is None:
                return False
            db.delete(row)
            db.commit()
            return True


class ConnectionStore:
    @staticmethod
    def upsert(
        *,
        realm_id: str,
        access_token: str,
        refresh_token: str,
        access_expires_in: int,
        refresh_expires_in: Optional[int],
        metadata: Dict[str, Any],
        company_name: Optional[str] = None,
        connection_label: Optional[str] = None,
    ) -> None:
        now_ts = int(time.time())
        access_expires_at = now_ts + int(access_expires_in) - 60
        refresh_expires_at = now_ts + int(refresh_expires_in) if refresh_expires_in else None
        now_iso = iso_now()
        with get_db() as db:
            row = db.get(QBConnection, realm_id)
            if row is None:
                row = QBConnection(
                    realm_id=realm_id,
                    company_name=company_name,
                    connection_label=connection_label,
                    environment=SETTINGS.qb_environment,
                    access_token=TOKEN_CIPHER.encrypt(access_token),
                    refresh_token=TOKEN_CIPHER.encrypt(refresh_token),
                    access_expires_at=access_expires_at,
                    refresh_expires_at=refresh_expires_at,
                    scope=metadata.get("scope"),
                    token_type=metadata.get("token_type"),
                    metadata_json=redacted_json(metadata),
                    created_at=now_iso,
                    updated_at=now_iso,
                    is_active=True,
                )
                db.add(row)
            else:
                row.company_name = company_name or row.company_name
                row.connection_label = connection_label or row.connection_label
                row.environment = SETTINGS.qb_environment
                row.access_token = TOKEN_CIPHER.encrypt(access_token)
                row.refresh_token = TOKEN_CIPHER.encrypt(refresh_token)
                row.access_expires_at = access_expires_at
                row.refresh_expires_at = refresh_expires_at
                row.scope = metadata.get("scope")
                row.token_type = metadata.get("token_type")
                row.metadata_json = redacted_json(metadata)
                row.updated_at = now_iso
                row.is_active = True
            db.commit()

    @staticmethod
    def get(realm_id: str) -> Optional[Dict[str, Any]]:
        with get_db() as db:
            row = db.get(QBConnection, realm_id)
            if row is None or not row.is_active:
                return None
            metadata = json.loads(row.metadata_json or "{}")
            return {
                "realm_id": row.realm_id,
                "company_name": row.company_name,
                "connection_label": row.connection_label,
                "environment": row.environment,
                "access_token": TOKEN_CIPHER.decrypt(row.access_token),
                "refresh_token": TOKEN_CIPHER.decrypt(row.refresh_token),
                "access_expires_at": row.access_expires_at,
                "refresh_expires_at": row.refresh_expires_at,
                "scope": row.scope,
                "token_type": row.token_type,
                "metadata": metadata,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }

    @staticmethod
    def list() -> List[Dict[str, Any]]:
        with get_db() as db:
            rows = db.scalars(select(QBConnection).where(QBConnection.is_active == True).order_by(QBConnection.updated_at.desc())).all()
            result: List[Dict[str, Any]] = []
            for row in rows:
                result.append(
                    {
                        "realm_id": row.realm_id,
                        "company_name": row.company_name,
                        "connection_label": row.connection_label,
                        "environment": row.environment,
                        "access_expires_at": row.access_expires_at,
                        "refresh_expires_at": row.refresh_expires_at,
                        "created_at": row.created_at,
                        "updated_at": row.updated_at,
                        "scope": row.scope,
                        "token_type": row.token_type,
                    }
                )
            return result

    @staticmethod
    def deactivate(realm_id: str) -> None:
        with get_db() as db:
            row = db.get(QBConnection, realm_id)
            if row is not None:
                row.is_active = False
                row.updated_at = iso_now()
                db.commit()

    @staticmethod
    def update_company_name(realm_id: str, company_name: str) -> None:
        with get_db() as db:
            row = db.get(QBConnection, realm_id)
            if row is not None:
                row.company_name = company_name
                row.updated_at = iso_now()
                db.commit()


class AuditStore:
    @staticmethod
    def write(
        *,
        actor: str,
        tool_name: str,
        realm_id: Optional[str],
        status: str,
        request_payload: Dict[str, Any],
        response_payload: Dict[str, Any],
        error_text: Optional[str] = None,
    ) -> None:
        with get_db() as db:
            db.add(
                AuditLog(
                    created_at=iso_now(),
                    actor=actor,
                    tool_name=tool_name,
                    realm_id=realm_id,
                    status=status,
                    request_json=redacted_json(request_payload),
                    response_json=redacted_json(response_payload),
                    error_text=error_text,
                )
            )
            db.commit()


class IdempotencyStore:
    @staticmethod
    def get(key: str) -> Optional[Dict[str, Any]]:
        with get_db() as db:
            row = db.get(IdempotencyRecord, key)
            if row is None:
                return None
            return {
                "tool_name": row.tool_name,
                "request_hash": row.request_hash,
                "response": json.loads(row.response_json),
                "created_at": row.created_at,
            }

    @staticmethod
    def put(key: str, tool_name: str, request_hash: str, response: Dict[str, Any]) -> None:
        with get_db() as db:
            db.add(
                IdempotencyRecord(
                    key=key,
                    tool_name=tool_name,
                    request_hash=request_hash,
                    response_json=redacted_json(response),
                    created_at=iso_now(),
                )
            )
            db.commit()


class DiscoveryCache:
    @staticmethod
    def get() -> Dict[str, Any]:
        cache_key = SETTINGS.discovery_url
        if cache_key in DISCOVERY_CACHE:
            return DISCOVERY_CACHE[cache_key]
        resp = requests.get(SETTINGS.discovery_url, timeout=SETTINGS.request_timeout_seconds)
        resp.raise_for_status()
        DISCOVERY_CACHE[cache_key] = resp.json()
        return DISCOVERY_CACHE[cache_key]


def build_basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def qb_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def pick_realm_id(company_ref: Optional[str]) -> str:
    if company_ref and company_ref.strip():
        return company_ref.strip()
    if SETTINGS.qb_default_realm_id:
        return SETTINGS.qb_default_realm_id
    companies = ConnectionStore.list()
    if len(companies) == 1:
        return companies[0]["realm_id"]
    if not companies:
        raise QuickBooksError("No QuickBooks company is connected.", status_code=400)
    raise QuickBooksError("Multiple QuickBooks companies are connected. Pass company_ref explicitly.", status_code=400)


def normalize_company_info(payload: Dict[str, Any]) -> Dict[str, Any]:
    return payload.get("CompanyInfo") or payload


def _extract_query_entities(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    query_response = payload.get("QueryResponse", {})
    for key, value in query_response.items():
        if key in {"startPosition", "maxResults", "totalCount"}:
            continue
        if isinstance(value, list):
            return value
    return []


def _filter_local_match(items: Iterable[Dict[str, Any]], query: str, keys: List[str], limit: int) -> List[Dict[str, Any]]:
    q = query.strip().lower()
    if not q:
        return list(items)[:limit]
    out: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        blob = " | ".join(str(item.get(k, "")) for k in keys).lower()
        if q in blob:
            identity = item.get("Id") or json.dumps(item, sort_keys=True)
            if identity in seen:
                continue
            seen.add(identity)
            out.append(item)
            if len(out) >= limit:
                break
    return out


def refresh_access_token(realm_id: str) -> Dict[str, Any]:
    conn = ConnectionStore.get(realm_id)
    if conn is None:
        raise QuickBooksError(f"No stored connection for realm_id={realm_id}", status_code=404)
    token_endpoint = DiscoveryCache.get()["token_endpoint"]
    resp = requests.post(
        token_endpoint,
        data={"grant_type": "refresh_token", "refresh_token": conn["refresh_token"]},
        headers={
            "Accept": "application/json",
            "Authorization": build_basic_auth_header(SETTINGS.qb_client_id, SETTINGS.qb_client_secret),
        },
        timeout=SETTINGS.request_timeout_seconds,
    )
    if resp.status_code >= 400:
        raise QuickBooksError(f"Token refresh failed: {resp.text}", status_code=resp.status_code)
    payload = resp.json()
    ConnectionStore.upsert(
        realm_id=realm_id,
        access_token=payload["access_token"],
        refresh_token=payload.get("refresh_token", conn["refresh_token"]),
        access_expires_in=int(payload.get("expires_in", 3600)),
        refresh_expires_in=int(payload.get("x_refresh_token_expires_in", 0)) if payload.get("x_refresh_token_expires_in") else None,
        metadata=payload,
        company_name=conn.get("company_name"),
        connection_label=conn.get("connection_label"),
    )
    fresh = ConnectionStore.get(realm_id)
    if fresh is None:
        raise QuickBooksError("Failed to reload refreshed connection", status_code=500)
    return fresh


def ensure_fresh_connection(realm_id: str) -> Dict[str, Any]:
    conn = ConnectionStore.get(realm_id)
    if conn is None:
        raise QuickBooksError(f"No QuickBooks connection found for realm_id={realm_id}", status_code=404)
    if conn["access_expires_at"] <= int(time.time()):
        conn = refresh_access_token(realm_id)
    return conn


def qb_headers(access_token: str, *, content_type: str = "application/json") -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": content_type,
    }


def parse_qb_error(resp: requests.Response) -> str:
    try:
        payload = resp.json()
        fault = payload.get("Fault", {})
        errors = fault.get("Error", [])
        if errors:
            parts = []
            for err in errors:
                code = err.get("code")
                detail = err.get("Detail") or err.get("Message")
                parts.append(f"{code}: {detail}" if code else str(detail))
            return " | ".join(parts)
    except Exception:
        pass
    return resp.text[:1000]


class QuickBooksClient:
    def request(
        self,
        realm_id: str,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[str] = None,
        content_type: str = "application/json",
    ) -> Dict[str, Any]:
        conn = ensure_fresh_connection(realm_id)
        url = f"{SETTINGS.api_base_url}/v3/company/{realm_id}{path}"
        attempts = max(1, SETTINGS.retry_attempts)
        last_error: Optional[QuickBooksError] = None

        for attempt in range(1, attempts + 1):
            headers = qb_headers(conn["access_token"], content_type=content_type)
            resp = requests.request(
                method.upper(),
                url,
                headers=headers,
                params=params,
                json=json_body,
                data=data,
                timeout=SETTINGS.request_timeout_seconds,
            )
            if resp.status_code == 401:
                conn = refresh_access_token(realm_id)
                headers = qb_headers(conn["access_token"], content_type=content_type)
                resp = requests.request(
                    method.upper(),
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                    data=data,
                    timeout=SETTINGS.request_timeout_seconds,
                )
            if resp.status_code < 400:
                return resp.json() if resp.text else {}
            message = parse_qb_error(resp)
            last_error = QuickBooksError(
                f"QuickBooks API error {resp.status_code}: {message}",
                status_code=resp.status_code,
            )
            if resp.status_code in {429, 500, 502, 503, 504} and attempt < attempts:
                time.sleep(min(2 ** (attempt - 1), 5))
                continue
            raise last_error
        if last_error:
            raise last_error
        raise QuickBooksError("Unknown QuickBooks client failure.", status_code=500)

    def query(self, realm_id: str, statement: str) -> Dict[str, Any]:
        return self.request(realm_id, "POST", "/query", data=statement, content_type="application/text")


qb_client = QuickBooksClient()


def compute_request_hash(payload: Dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def invoice_total_from_lines(line_items: List[Dict[str, Any]]) -> Decimal:
    total = Decimal("0")
    for line in line_items:
        try:
            qty = Decimal(str(line["quantity"]))
            unit_price = Decimal(str(line["unit_price"]))
        except (KeyError, InvalidOperation) as exc:
            raise QuickBooksError("Each line item requires numeric quantity and unit_price.", status_code=400) from exc
        total += qty * unit_price
    return total


def audit_success(tool_name: str, realm_id: Optional[str], request_payload: Dict[str, Any], response_payload: Dict[str, Any]) -> Dict[str, Any]:
    AuditStore.write(
        actor="mcp",
        tool_name=tool_name,
        realm_id=realm_id,
        status="success",
        request_payload=request_payload,
        response_payload=response_payload,
    )
    return response_payload


def audit_failure(tool_name: str, realm_id: Optional[str], request_payload: Dict[str, Any], exc: Exception) -> None:
    AuditStore.write(
        actor="mcp",
        tool_name=tool_name,
        realm_id=realm_id,
        status="error",
        request_payload=request_payload,
        response_payload={},
        error_text=str(exc),
    )


from mcp.server.transport_security import TransportSecuritySettings

# Build allowed hosts/origins from PUBLIC_BASE_URL
_pub_host = SETTINGS.public_base_url.replace("https://", "").replace("http://", "") if SETTINGS.public_base_url else ""
_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=[
        "127.0.0.1:*", "localhost:*", "[::1]:*",
        f"{_pub_host}",  f"{_pub_host}:*",
    ],
    allowed_origins=[
        "http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*",
        f"https://{_pub_host}",
    ],
)

mcp = FastMCP(
    APP_NAME,
    instructions=(
        "QuickBooks Online production MCP server. Prefer read tools first. "
        "Only create invoices when the user explicitly asks and identifiers are known. "
        "Never invent customer IDs or item IDs."
    ),
    json_response=True,
    transport_security=_transport_security,
)


@mcp.resource("qb://connections")
def qb_connections_resource() -> Dict[str, Any]:
    return {
        "companies": ConnectionStore.list(),
        "default_realm_id": SETTINGS.qb_default_realm_id or None,
        "environment": SETTINGS.qb_environment,
    }


@mcp.tool()
def qb_list_companies() -> Dict[str, Any]:
    """List connected QuickBooks companies (realm IDs) available to this server."""
    request_payload: Dict[str, Any] = {}
    try:
        result = {
            "companies": ConnectionStore.list(),
            "default_realm_id": SETTINGS.qb_default_realm_id or None,
        }
        return audit_success("qb_list_companies", None, request_payload, result)
    except Exception as exc:
        audit_failure("qb_list_companies", None, request_payload, exc)
        raise


@mcp.tool()
def qb_get_company_info(company_ref: Optional[str] = None) -> Dict[str, Any]:
    """Fetch CompanyInfo for one connected QuickBooks company."""
    request_payload = {"company_ref": company_ref}
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        payload = qb_client.request(realm_id, "GET", f"/companyinfo/{realm_id}")
        info = normalize_company_info(payload)
        if info.get("CompanyName"):
            ConnectionStore.update_company_name(realm_id, info["CompanyName"])
        result = {"realm_id": realm_id, "company_info": info}
        return audit_success("qb_get_company_info", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_get_company_info", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_find_customers(
    query: str = "",
    company_ref: Optional[str] = None,
    include_inactive: bool = False,
    limit: int = 20,
) -> Dict[str, Any]:
    """Find customers by display name, company name, or email."""
    request_payload = {
        "query": query,
        "company_ref": company_ref,
        "include_inactive": include_inactive,
        "limit": limit,
    }
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        active_clause = "Active IN (true, false)" if include_inactive else "Active = true"
        statement = f"SELECT * FROM Customer WHERE {active_clause} STARTPOSITION 1 MAXRESULTS 1000"
        entities = _extract_query_entities(qb_client.query(realm_id, statement))
        matches = _filter_local_match(
            entities,
            query,
            ["DisplayName", "CompanyName", "PrimaryEmailAddr", "GivenName", "FamilyName"],
            max(1, min(limit, 200)),
        )
        result = {"realm_id": realm_id, "count": len(matches), "customers": matches}
        return audit_success("qb_find_customers", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_find_customers", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_find_items(
    query: str = "",
    company_ref: Optional[str] = None,
    include_inactive: bool = False,
    limit: int = 20,
) -> Dict[str, Any]:
    """Find QuickBooks items (products/services) by name, sku, or description."""
    request_payload = {
        "query": query,
        "company_ref": company_ref,
        "include_inactive": include_inactive,
        "limit": limit,
    }
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        active_clause = "Active IN (true, false)" if include_inactive else "Active = true"
        statement = f"SELECT * FROM Item WHERE {active_clause} STARTPOSITION 1 MAXRESULTS 1000"
        entities = _extract_query_entities(qb_client.query(realm_id, statement))
        matches = _filter_local_match(entities, query, ["Name", "Sku", "Description", "FullyQualifiedName"], max(1, min(limit, 200)))
        result = {"realm_id": realm_id, "count": len(matches), "items": matches}
        return audit_success("qb_find_items", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_find_items", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_list_invoices(
    company_ref: Optional[str] = None,
    customer_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List invoices with optional customer and date filters."""
    request_payload = {
        "company_ref": company_ref,
        "customer_id": customer_id,
        "date_from": date_from,
        "date_to": date_to,
        "limit": limit,
    }
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        clauses = []
        if customer_id:
            clauses.append(f"CustomerRef = '{qb_escape(customer_id)}'")
        if date_from:
            clauses.append(f"TxnDate >= '{qb_escape(date_from)}'")
        if date_to:
            clauses.append(f"TxnDate <= '{qb_escape(date_to)}'")
        where_clause = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        limit = max(1, min(limit, 1000))
        statement = f"SELECT * FROM Invoice{where_clause} ORDERBY MetaData.LastUpdatedTime DESC STARTPOSITION 1 MAXRESULTS {limit}"
        entities = _extract_query_entities(qb_client.query(realm_id, statement))
        result = {"realm_id": realm_id, "count": len(entities), "invoices": entities}
        return audit_success("qb_list_invoices", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_list_invoices", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_get_invoice(invoice_id: str, company_ref: Optional[str] = None) -> Dict[str, Any]:
    """Fetch a single invoice by QuickBooks invoice ID."""
    request_payload = {"invoice_id": invoice_id, "company_ref": company_ref}
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        payload = qb_client.request(realm_id, "GET", f"/invoice/{invoice_id}")
        result = {"realm_id": realm_id, "invoice": payload.get("Invoice", payload)}
        return audit_success("qb_get_invoice", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_get_invoice", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_get_profit_and_loss(
    start_date: str,
    end_date: str,
    company_ref: Optional[str] = None,
    accounting_method: str = "Accrual",
) -> Dict[str, Any]:
    """Run a Profit and Loss report."""
    request_payload = {
        "start_date": start_date,
        "end_date": end_date,
        "company_ref": company_ref,
        "accounting_method": accounting_method,
    }
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        payload = qb_client.request(
            realm_id,
            "GET",
            "/reports/ProfitAndLoss",
            params={
                "start_date": start_date,
                "end_date": end_date,
                "accounting_method": accounting_method,
            },
        )
        result = {"realm_id": realm_id, "report": payload}
        return audit_success("qb_get_profit_and_loss", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_get_profit_and_loss", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_get_balance_sheet(as_of_date: str, company_ref: Optional[str] = None, accounting_method: str = "Accrual") -> Dict[str, Any]:
    """Run a Balance Sheet report."""
    request_payload = {"as_of_date": as_of_date, "company_ref": company_ref, "accounting_method": accounting_method}
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        payload = qb_client.request(
            realm_id,
            "GET",
            "/reports/BalanceSheet",
            params={
                "end_date": as_of_date,
                "accounting_method": accounting_method,
            },
        )
        result = {"realm_id": realm_id, "report": payload}
        return audit_success("qb_get_balance_sheet", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_get_balance_sheet", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_get_ar_aging(as_of_date: str, company_ref: Optional[str] = None) -> Dict[str, Any]:
    """Run Accounts Receivable Aging Summary."""
    request_payload = {"as_of_date": as_of_date, "company_ref": company_ref}
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        payload = qb_client.request(
            realm_id,
            "GET",
            "/reports/AgedReceivables",
            params={"report_date": as_of_date},
        )
        result = {"realm_id": realm_id, "report": payload}
        return audit_success("qb_get_ar_aging", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_get_ar_aging", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_create_invoice(
    customer_id: str,
    line_items: List[Dict[str, Any]],
    company_ref: Optional[str] = None,
    txn_date: Optional[str] = None,
    private_note: str = "",
    customer_memo: str = "",
    currency: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a QuickBooks invoice. Disabled unless QB_ENABLE_INVOICE_WRITE=true."""
    request_payload = {
        "customer_id": customer_id,
        "line_items": line_items,
        "company_ref": company_ref,
        "txn_date": txn_date,
        "private_note": private_note,
        "customer_memo": customer_memo,
        "currency": currency,
        "idempotency_key": idempotency_key,
    }
    realm_id = None
    try:
        if not SETTINGS.enable_invoice_write:
            raise QuickBooksError("Invoice creation is disabled on this server.", status_code=403)
        realm_id = pick_realm_id(company_ref)
        if SETTINGS.require_idempotency_key and not idempotency_key:
            raise QuickBooksError("idempotency_key is required for invoice creation.", status_code=400)

        estimated_total = invoice_total_from_lines(line_items)
        if estimated_total > SETTINGS.max_invoice_total_decimal:
            raise QuickBooksError(
                f"Invoice total {estimated_total} exceeds configured limit {SETTINGS.max_invoice_total_decimal}.",
                status_code=400,
            )

        request_hash = compute_request_hash({k: v for k, v in request_payload.items() if k != "idempotency_key"})
        if idempotency_key:
            existing = IdempotencyStore.get(idempotency_key)
            if existing:
                if existing["tool_name"] != "qb_create_invoice" or existing["request_hash"] != request_hash:
                    raise QuickBooksError("idempotency_key has already been used with a different request.", status_code=409)
                result = existing["response"]
                return audit_success("qb_create_invoice", realm_id, request_payload, result)

        lines: List[Dict[str, Any]] = []
        for idx, item in enumerate(line_items, start=1):
            try:
                quantity = Decimal(str(item["quantity"]))
                unit_price = Decimal(str(item["unit_price"]))
            except (KeyError, InvalidOperation) as exc:
                raise QuickBooksError(f"Invalid line item at index {idx}.", status_code=400) from exc
            line: Dict[str, Any] = {
                "DetailType": "SalesItemLineDetail",
                "Amount": float(quantity * unit_price),
                "Description": item.get("description", ""),
                "SalesItemLineDetail": {
                    "Qty": float(quantity),
                    "UnitPrice": float(unit_price),
                    "ItemRef": {"value": str(item["item_id"])},
                },
            }
            lines.append(line)

        payload: Dict[str, Any] = {
            "CustomerRef": {"value": str(customer_id)},
            "Line": lines,
        }
        if txn_date:
            payload["TxnDate"] = txn_date
        if private_note:
            payload["PrivateNote"] = private_note
        if customer_memo:
            payload["CustomerMemo"] = {"value": customer_memo}
        if currency:
            payload["CurrencyRef"] = {"value": currency}

        response = qb_client.request(realm_id, "POST", "/invoice", json_body=payload)
        result = {"realm_id": realm_id, "invoice": response.get("Invoice", response)}
        if idempotency_key:
            try:
                IdempotencyStore.put(idempotency_key, "qb_create_invoice", request_hash, result)
            except IntegrityError:
                pass
        return audit_success("qb_create_invoice", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_create_invoice", realm_id, request_payload, exc)
        raise


# ─────────────────────────────────────────────────────────
# EXPANDED TOOL SET — Vendors, Accounts, Expenses, Payments,
# Estimates, Credit Memos, Purchases, Journal Entries, Employees,
# Departments, Classes, Tax Codes, Reports, and more.
# ─────────────────────────────────────────────────────────


def _make_query_tool(entity_name: str, search_fields: List[str], tool_name: str, description: str):
    """Factory to create a standard query/search tool for a QB entity."""
    @mcp.tool(name=tool_name, description=description)
    def _tool(
        query: str = "",
        company_ref: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        request_payload = {"query": query, "company_ref": company_ref, "limit": limit}
        realm_id = None
        try:
            realm_id = pick_realm_id(company_ref)
            lim = max(1, min(limit, 1000))
            statement = f"SELECT * FROM {entity_name} STARTPOSITION 1 MAXRESULTS {lim}"
            entities = _extract_query_entities(qb_client.query(realm_id, statement))
            if query:
                entities = _filter_local_match(entities, query, search_fields, lim)
            result = {"realm_id": realm_id, "count": len(entities), entity_name.lower() + "s": entities}
            return audit_success(tool_name, realm_id, request_payload, result)
        except Exception as exc:
            audit_failure(tool_name, realm_id, request_payload, exc)
            raise
    return _tool


def _make_get_by_id_tool(entity_name: str, id_param: str, tool_name: str, description: str):
    """Factory to create a get-by-ID tool for a QB entity."""
    @mcp.tool(name=tool_name, description=description)
    def _tool(entity_id: str, company_ref: Optional[str] = None) -> Dict[str, Any]:
        request_payload = {id_param: entity_id, "company_ref": company_ref}
        realm_id = None
        try:
            realm_id = pick_realm_id(company_ref)
            payload = qb_client.request(realm_id, "GET", f"/{entity_name.lower()}/{entity_id}")
            result = {"realm_id": realm_id, entity_name.lower(): payload.get(entity_name, payload)}
            return audit_success(tool_name, realm_id, request_payload, result)
        except Exception as exc:
            audit_failure(tool_name, realm_id, request_payload, exc)
            raise
    return _tool


def _make_list_transactions_tool(entity_name: str, tool_name: str, description: str):
    """Factory to create a transaction list tool with date/customer filters."""
    @mcp.tool(name=tool_name, description=description)
    def _tool(
        company_ref: Optional[str] = None,
        customer_id: Optional[str] = None,
        vendor_id: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        request_payload = {
            "company_ref": company_ref, "customer_id": customer_id,
            "vendor_id": vendor_id, "date_from": date_from, "date_to": date_to, "limit": limit,
        }
        realm_id = None
        try:
            realm_id = pick_realm_id(company_ref)
            clauses = []
            if customer_id:
                clauses.append(f"CustomerRef = '{qb_escape(customer_id)}'")
            if vendor_id:
                clauses.append(f"VendorRef = '{qb_escape(vendor_id)}'")
            if date_from:
                clauses.append(f"TxnDate >= '{qb_escape(date_from)}'")
            if date_to:
                clauses.append(f"TxnDate <= '{qb_escape(date_to)}'")
            where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
            lim = max(1, min(limit, 1000))
            statement = f"SELECT * FROM {entity_name}{where} ORDERBY MetaData.LastUpdatedTime DESC STARTPOSITION 1 MAXRESULTS {lim}"
            entities = _extract_query_entities(qb_client.query(realm_id, statement))
            result = {"realm_id": realm_id, "count": len(entities), entity_name.lower() + "s": entities}
            return audit_success(tool_name, realm_id, request_payload, result)
        except Exception as exc:
            audit_failure(tool_name, realm_id, request_payload, exc)
            raise
    return _tool


def _make_report_tool(report_path: str, tool_name: str, description: str, *, uses_date_range: bool = True):
    """Factory to create a report tool."""
    if uses_date_range:
        @mcp.tool(name=tool_name, description=description)
        def _tool(
            start_date: str,
            end_date: str,
            company_ref: Optional[str] = None,
            accounting_method: str = "Accrual",
        ) -> Dict[str, Any]:
            request_payload = {"start_date": start_date, "end_date": end_date, "company_ref": company_ref, "accounting_method": accounting_method}
            realm_id = None
            try:
                realm_id = pick_realm_id(company_ref)
                payload = qb_client.request(realm_id, "GET", f"/reports/{report_path}", params={
                    "start_date": start_date, "end_date": end_date, "accounting_method": accounting_method,
                })
                result = {"realm_id": realm_id, "report": payload}
                return audit_success(tool_name, realm_id, request_payload, result)
            except Exception as exc:
                audit_failure(tool_name, realm_id, request_payload, exc)
                raise
    else:
        @mcp.tool(name=tool_name, description=description)
        def _tool(
            as_of_date: str,
            company_ref: Optional[str] = None,
        ) -> Dict[str, Any]:
            request_payload = {"as_of_date": as_of_date, "company_ref": company_ref}
            realm_id = None
            try:
                realm_id = pick_realm_id(company_ref)
                payload = qb_client.request(realm_id, "GET", f"/reports/{report_path}", params={"report_date": as_of_date})
                result = {"realm_id": realm_id, "report": payload}
                return audit_success(tool_name, realm_id, request_payload, result)
            except Exception as exc:
                audit_failure(tool_name, realm_id, request_payload, exc)
                raise
    return _tool


# ── Vendors ──
_make_query_tool("Vendor", ["DisplayName", "CompanyName", "PrimaryEmailAddr", "GivenName", "FamilyName"],
    "qb_find_vendors", "Find vendors/suppliers by name, company, or email.")
_make_get_by_id_tool("Vendor", "vendor_id", "qb_get_vendor", "Fetch a single vendor by ID.")

# ── Accounts (Chart of Accounts) ──
_make_query_tool("Account", ["Name", "FullyQualifiedName", "AccountType", "AccountSubType"],
    "qb_find_accounts", "Find accounts in the Chart of Accounts by name or type.")
_make_get_by_id_tool("Account", "account_id", "qb_get_account", "Fetch a single account by ID.")

# ── Employees ──
_make_query_tool("Employee", ["DisplayName", "GivenName", "FamilyName", "PrimaryEmailAddr"],
    "qb_find_employees", "Find employees by name or email.")

# ── Departments ──
_make_query_tool("Department", ["Name", "FullyQualifiedName"],
    "qb_find_departments", "Find departments/locations.")

# ── Classes ──
_make_query_tool("Class", ["Name", "FullyQualifiedName"],
    "qb_find_classes", "Find classes for tracking transactions.")

# ── Tax Codes ──
_make_query_tool("TaxCode", ["Name"],
    "qb_find_tax_codes", "Find tax codes configured in QuickBooks.")

# ── Tax Rates ──
_make_query_tool("TaxRate", ["Name", "RateValue"],
    "qb_find_tax_rates", "Find tax rates configured in QuickBooks.")

# ── Payment Methods ──
_make_query_tool("PaymentMethod", ["Name"],
    "qb_find_payment_methods", "Find payment methods (cash, check, credit card, etc.).")

# ── Terms ──
_make_query_tool("Term", ["Name"],
    "qb_find_terms", "Find payment terms (Net 30, Net 60, etc.).")

# ── Estimates ──
_make_list_transactions_tool("Estimate", "qb_list_estimates", "List estimates/quotes with optional date and customer filters.")
_make_get_by_id_tool("Estimate", "estimate_id", "qb_get_estimate", "Fetch a single estimate/quote by ID.")

# ── Credit Memos ──
_make_list_transactions_tool("CreditMemo", "qb_list_credit_memos", "List credit memos with optional date and customer filters.")
_make_get_by_id_tool("CreditMemo", "credit_memo_id", "qb_get_credit_memo", "Fetch a single credit memo by ID.")

# ── Sales Receipts ──
_make_list_transactions_tool("SalesReceipt", "qb_list_sales_receipts", "List sales receipts with optional date and customer filters.")
_make_get_by_id_tool("SalesReceipt", "sales_receipt_id", "qb_get_sales_receipt", "Fetch a single sales receipt by ID.")

# ── Payments (received from customers) ──
_make_list_transactions_tool("Payment", "qb_list_payments", "List customer payments received with optional date and customer filters.")
_make_get_by_id_tool("Payment", "payment_id", "qb_get_payment", "Fetch a single customer payment by ID.")

# ── Bills (from vendors) ──
_make_list_transactions_tool("Bill", "qb_list_bills", "List bills from vendors with optional date and vendor filters.")
_make_get_by_id_tool("Bill", "bill_id", "qb_get_bill", "Fetch a single bill by ID.")

# ── Bill Payments ──
_make_list_transactions_tool("BillPayment", "qb_list_bill_payments", "List bill payments with optional date and vendor filters.")
_make_get_by_id_tool("BillPayment", "bill_payment_id", "qb_get_bill_payment", "Fetch a single bill payment by ID.")

# ── Purchase Orders ──
_make_list_transactions_tool("PurchaseOrder", "qb_list_purchase_orders", "List purchase orders with optional date and vendor filters.")
_make_get_by_id_tool("PurchaseOrder", "purchase_order_id", "qb_get_purchase_order", "Fetch a single purchase order by ID.")

# ── Purchases / Expenses ──
_make_list_transactions_tool("Purchase", "qb_list_purchases", "List purchases/expenses (checks, cash, credit card) with optional date filters.")
_make_get_by_id_tool("Purchase", "purchase_id", "qb_get_purchase", "Fetch a single purchase/expense by ID.")

# ── Deposits ──
_make_list_transactions_tool("Deposit", "qb_list_deposits", "List bank deposits with optional date filters.")
_make_get_by_id_tool("Deposit", "deposit_id", "qb_get_deposit", "Fetch a single deposit by ID.")

# ── Transfers ──
_make_list_transactions_tool("Transfer", "qb_list_transfers", "List fund transfers between accounts with optional date filters.")
_make_get_by_id_tool("Transfer", "transfer_id", "qb_get_transfer", "Fetch a single transfer by ID.")

# ── Journal Entries ──
_make_list_transactions_tool("JournalEntry", "qb_list_journal_entries", "List journal entries with optional date filters.")
_make_get_by_id_tool("JournalEntry", "journal_entry_id", "qb_get_journal_entry", "Fetch a single journal entry by ID.")

# ── Refund Receipts ──
_make_list_transactions_tool("RefundReceipt", "qb_list_refund_receipts", "List refund receipts with optional date and customer filters.")
_make_get_by_id_tool("RefundReceipt", "refund_receipt_id", "qb_get_refund_receipt", "Fetch a single refund receipt by ID.")

# ── Vendor Credits ──
_make_list_transactions_tool("VendorCredit", "qb_list_vendor_credits", "List vendor credits with optional date and vendor filters.")
_make_get_by_id_tool("VendorCredit", "vendor_credit_id", "qb_get_vendor_credit", "Fetch a single vendor credit by ID.")

# ── Time Activities ──
_make_list_transactions_tool("TimeActivity", "qb_list_time_activities", "List time tracking entries with optional date filters.")

# ── Additional Reports ──
_make_report_tool("CashFlow", "qb_get_cash_flow", "Run a Statement of Cash Flows report.")
_make_report_tool("GeneralLedger", "qb_get_general_ledger", "Run a General Ledger report.")
_make_report_tool("TrialBalance", "qb_get_trial_balance", "Run a Trial Balance report.")
_make_report_tool("AgedPayables", "qb_get_ap_aging", "Run Accounts Payable Aging Summary.", uses_date_range=False)
_make_report_tool("CustomerIncome", "qb_get_customer_income", "Run Customer Income report showing revenue by customer.")
_make_report_tool("VendorExpenses", "qb_get_vendor_expenses", "Run Vendor Expenses report showing spending by vendor.")
_make_report_tool("CustomerBalance", "qb_get_customer_balance", "Run Customer Balance Summary report.", uses_date_range=False)
_make_report_tool("VendorBalance", "qb_get_vendor_balance", "Run Vendor Balance Summary report.", uses_date_range=False)
_make_report_tool("ProfitAndLossDetail", "qb_get_profit_and_loss_detail", "Run a detailed Profit and Loss report with transaction-level detail.")
_make_report_tool("TransactionList", "qb_get_transaction_list", "Run a Transaction List report showing all transactions in a date range.")


@mcp.tool()
def qb_query(
    statement: str,
    company_ref: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a raw QuickBooks query (SELECT only). Example: SELECT * FROM Invoice WHERE TotalAmt > '1000'"""
    request_payload = {"statement": statement, "company_ref": company_ref}
    realm_id = None
    try:
        s = statement.strip()
        if not s.upper().startswith("SELECT"):
            raise QuickBooksError("Only SELECT queries are allowed.", status_code=400)
        realm_id = pick_realm_id(company_ref)
        entities = _extract_query_entities(qb_client.query(realm_id, s))
        result = {"realm_id": realm_id, "count": len(entities), "rows": entities}
        return audit_success("qb_query", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_query", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_get_customer(customer_id: str, company_ref: Optional[str] = None) -> Dict[str, Any]:
    """Fetch a single customer by QuickBooks customer ID with full details."""
    request_payload = {"customer_id": customer_id, "company_ref": company_ref}
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        payload = qb_client.request(realm_id, "GET", f"/customer/{customer_id}")
        result = {"realm_id": realm_id, "customer": payload.get("Customer", payload)}
        return audit_success("qb_get_customer", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_get_customer", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_get_item(item_id: str, company_ref: Optional[str] = None) -> Dict[str, Any]:
    """Fetch a single item (product/service) by QuickBooks item ID."""
    request_payload = {"item_id": item_id, "company_ref": company_ref}
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        payload = qb_client.request(realm_id, "GET", f"/item/{item_id}")
        result = {"realm_id": realm_id, "item": payload.get("Item", payload)}
        return audit_success("qb_get_item", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_get_item", realm_id, request_payload, exc)
        raise


@mcp.tool()
def qb_count_entities(
    entity_type: str,
    company_ref: Optional[str] = None,
) -> Dict[str, Any]:
    """Count entities of a given type. entity_type examples: Invoice, Customer, Bill, Vendor, Item, Payment, etc."""
    request_payload = {"entity_type": entity_type, "company_ref": company_ref}
    realm_id = None
    try:
        realm_id = pick_realm_id(company_ref)
        statement = f"SELECT COUNT(*) FROM {entity_type}"
        payload = qb_client.query(realm_id, statement)
        count = payload.get("QueryResponse", {}).get("totalCount", 0)
        result = {"realm_id": realm_id, "entity_type": entity_type, "count": count}
        return audit_success("qb_count_entities", realm_id, request_payload, result)
    except Exception as exc:
        audit_failure("qb_count_entities", realm_id, request_payload, exc)
        raise


async def healthz(_: Request) -> Response:
    return JSONResponse({"ok": True, "app": APP_NAME, "time": iso_now(), "environment": SETTINGS.app_env})


async def readyz(_: Request) -> Response:
    try:
        DiscoveryCache.get()
        with get_db() as db:
            db.execute(select(QBConnection.realm_id).limit(1))
        return JSONResponse({"ok": True, "ready": True, "time": iso_now()})
    except Exception as exc:
        return JSONResponse({"ok": False, "ready": False, "error": str(exc), "time": iso_now()}, status_code=500)


STATUS_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset='utf-8'>
    <title>{title}</title>
    <style>
      body {{ font-family: Arial, sans-serif; margin: 2rem; color: #111; }}
      code {{ background: #f4f4f4; padding: 2px 4px; }}
      table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
      th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
      th {{ background: #f7f7f7; }}
      .box {{ padding: 1rem; background: #f9fbff; border: 1px solid #dbe6ff; margin-bottom: 1rem; }}
      .warn {{ color: #9a4d00; }}
      a.button {{ display:inline-block; padding:10px 14px; background:#111; color:#fff; text-decoration:none; border-radius:6px; }}
      .small {{ color:#666; font-size: 0.9rem; }}
    </style>
  </head>
  <body>
    <h1>{title}</h1>
    <div class='box'>
      <p><strong>Public base URL</strong>: <code>{public_base_url}</code></p>
      <p><strong>MCP endpoint</strong>: <code>{public_base_url}/mcp</code></p>
      <p><strong>OAuth connect URL</strong>: <code>{public_base_url}/auth/connect</code></p>
      <p><strong>QuickBooks environment</strong>: {qb_environment}</p>
      <p><strong>Token encryption</strong>: {token_encryption}</p>
      <p><strong>Database</strong>: <code>{db_url}</code></p>
      <p class='warn'>Protect this page behind admin credentials and put the app behind HTTPS.</p>
      <p><a class='button' href='/auth/connect'>Connect QuickBooks</a></p>
    </div>
    <h2>Connected companies</h2>
    <table>
      <thead>
        <tr><th>Realm ID</th><th>Company Name</th><th>Environment</th><th>Access Expires</th><th>Updated</th><th>Action</th></tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
    <p class='small'>Bearer token auth is {mcp_auth_state} for the MCP endpoint.</p>
  </body>
</html>
"""


async def status_page(request: Request) -> Response:
    if not SETTINGS.status_page_enabled:
        return PlainTextResponse("Status page is disabled.", status_code=404)
    require_admin(request)
    rows = []
    for item in ConnectionStore.list():
        rows.append(
            f"<tr><td>{item['realm_id']}</td><td>{item.get('company_name') or ''}</td><td>{item['environment']}</td><td>{item['access_expires_at']}</td><td>{item['updated_at']}</td>"
            f"<td><form method='post' action='/auth/disconnect?realm_id={item['realm_id']}' onsubmit=\"return confirm('Disconnect this company?');\"><button>Disconnect</button></form></td></tr>"
        )
    rows_html = "\n".join(rows) if rows else "<tr><td colspan='6'>No QuickBooks company connected yet.</td></tr>"
    html = STATUS_TEMPLATE.format(
        title=APP_NAME,
        public_base_url=SETTINGS.public_base_url or f"http://{SETTINGS.host}:{SETTINGS.port}",
        qb_environment=SETTINGS.qb_environment,
        token_encryption="enabled" if TOKEN_CIPHER.enabled else "disabled",
        db_url=SETTINGS.db_url,
        rows_html=rows_html,
        mcp_auth_state="enabled" if SETTINGS.mcp_bearer_token else "disabled",
    )
    return HTMLResponse(html)


async def oauth_connect(request: Request) -> Response:
    require_admin(request)
    if not SETTINGS.qb_client_id or not SETTINGS.qb_client_secret:
        return PlainTextResponse("Missing QB_CLIENT_ID / QB_CLIENT_SECRET.", status_code=500)
    discovery = DiscoveryCache.get()
    state = secrets.token_urlsafe(24)
    StateStore.put(state)
    params = {
        "client_id": SETTINGS.qb_client_id,
        "redirect_uri": SETTINGS.redirect_uri,
        "response_type": "code",
        "scope": SETTINGS.qb_scopes,
        "state": state,
    }
    authorize_url = discovery["authorization_endpoint"] + "?" + urlencode(params)
    return RedirectResponse(authorize_url, status_code=302)


async def oauth_callback(request: Request) -> Response:
    params = request.query_params
    state = params.get("state", "")
    code = params.get("code", "")
    realm_id = params.get("realmId", "")
    error = params.get("error")

    if error:
        return HTMLResponse(f"<h1>OAuth failed</h1><pre>{error}</pre>", status_code=400)
    if not state or not StateStore.consume(state):
        return HTMLResponse("<h1>Invalid or expired OAuth state</h1>", status_code=400)
    if not code or not realm_id:
        return HTMLResponse("<h1>Missing code or realmId</h1>", status_code=400)

    token_endpoint = DiscoveryCache.get()["token_endpoint"]
    token_resp = requests.post(
        token_endpoint,
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": SETTINGS.redirect_uri},
        headers={
            "Accept": "application/json",
            "Authorization": build_basic_auth_header(SETTINGS.qb_client_id, SETTINGS.qb_client_secret),
        },
        timeout=SETTINGS.request_timeout_seconds,
    )
    if token_resp.status_code >= 400:
        return HTMLResponse(f"<h1>Token exchange failed</h1><pre>{token_resp.text}</pre>", status_code=500)
    payload = token_resp.json()
    ConnectionStore.upsert(
        realm_id=realm_id,
        access_token=payload["access_token"],
        refresh_token=payload["refresh_token"],
        access_expires_in=int(payload.get("expires_in", 3600)),
        refresh_expires_in=int(payload.get("x_refresh_token_expires_in", 0)) if payload.get("x_refresh_token_expires_in") else None,
        metadata=payload,
    )

    company_name = None
    try:
        company_payload = qb_client.request(realm_id, "GET", f"/companyinfo/{realm_id}")
        company_name = normalize_company_info(company_payload).get("CompanyName")
        if company_name:
            ConnectionStore.update_company_name(realm_id, company_name)
    except Exception as exc:
        logger.warning("Failed to fetch company info after OAuth callback: %s", exc)

    html = f"""
<!doctype html>
<html>
  <head><meta charset='utf-8'><title>QuickBooks connected</title></head>
  <body style='font-family:Arial,sans-serif;margin:2rem;'>
    <h1>QuickBooks connected</h1>
    <p><strong>Realm ID:</strong> {realm_id}</p>
    <p><strong>Company:</strong> {company_name or 'Connected successfully'}</p>
    <p><a href='/status'>Open status page</a></p>
  </body>
</html>
"""
    return HTMLResponse(html)


async def oauth_protected_resource(request: Request) -> Response:
    """OAuth 2.0 Protected Resource Metadata (RFC 9728) for Claude connector discovery."""
    base = SETTINGS.public_base_url or f"http://{SETTINGS.host}:{SETTINGS.port}"
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
    })


async def oauth_authorization_server(request: Request) -> Response:
    """OAuth 2.0 Authorization Server Metadata for Claude connector discovery."""
    base = SETTINGS.public_base_url or f"http://{SETTINGS.host}:{SETTINGS.port}"
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
    })


async def oauth_register(request: Request) -> Response:
    """Dynamic client registration — auto-approve any Claude client."""
    import time as _time
    body = await request.json()
    return JSONResponse({
        "client_id": f"claude-{int(_time.time())}",
        "client_secret_expires_at": 0,
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    })


async def oauth_authorize(request: Request) -> Response:
    """Auto-approve OAuth authorization — redirect back with a static code."""
    params = request.query_params
    redirect_uri = params.get("redirect_uri", "")
    state = params.get("state", "")
    code = "static-auth-code"
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}code={code}&state={state}", status_code=302)


async def oauth_token(request: Request) -> Response:
    """Exchange auth code for a static access token."""
    return JSONResponse({
        "access_token": SETTINGS.mcp_bearer_token or "static-access-token",
        "token_type": "bearer",
        "expires_in": 86400,
    })


async def oauth_disconnect(request: Request) -> Response:
    require_admin(request)
    realm_id = request.query_params.get("realm_id", "").strip()
    if not realm_id:
        return PlainTextResponse("realm_id is required", status_code=400)
    conn = ConnectionStore.get(realm_id)
    if conn:
        revoke_endpoint = DiscoveryCache.get().get("revocation_endpoint")
        if revoke_endpoint:
            try:
                requests.post(
                    revoke_endpoint,
                    data={"token": conn["refresh_token"]},
                    headers={
                        "Accept": "application/json",
                        "Authorization": build_basic_auth_header(SETTINGS.qb_client_id, SETTINGS.qb_client_secret),
                    },
                    timeout=SETTINGS.request_timeout_seconds,
                )
            except Exception as exc:
                logger.warning("Revocation request failed for realm_id=%s: %s", realm_id, exc)
    ConnectionStore.deactivate(realm_id)
    return RedirectResponse("/status", status_code=302)


async def exception_handler(request: Request, exc: Exception) -> Response:
    if isinstance(exc, QuickBooksError):
        headers = {"WWW-Authenticate": "Basic realm=QuickBooks MCP"} if exc.status_code == 401 else None
        return JSONResponse({"ok": False, "error": str(exc), "payload": exc.payload}, status_code=exc.status_code, headers=headers)
    logger.exception("Unhandled exception for %s %s", request.method, request.url.path)
    return JSONResponse({"ok": False, "error": "Internal server error."}, status_code=500)


exceptions = {Exception: exception_handler}


middleware = [
    Middleware(AccessControlMiddleware),
    Middleware(GZipMiddleware, minimum_size=1000),
    Middleware(
        CORSMiddleware,
        allow_origins=SETTINGS.cors_allow_origins or ["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
        allow_headers=["Content-Type", "Authorization", "Accept", "Mcp-Session-Id"],
        expose_headers=["Mcp-Session-Id"],
    ),
]


from contextlib import asynccontextmanager

custom_routes = [
    Route("/", endpoint=status_page, methods=["GET"]),
    Route("/status", endpoint=status_page, methods=["GET"]),
    Route("/healthz", endpoint=healthz, methods=["GET"]),
    Route("/readyz", endpoint=readyz, methods=["GET"]),
    Route("/auth/connect", endpoint=oauth_connect, methods=["GET"]),
    Route("/auth/callback", endpoint=oauth_callback, methods=["GET"]),
    Route("/auth/disconnect", endpoint=oauth_disconnect, methods=["POST"]),
    # OAuth discovery endpoints for Claude connector registration
    Route("/.well-known/oauth-protected-resource", endpoint=oauth_protected_resource, methods=["GET"]),
    Route("/.well-known/oauth-authorization-server", endpoint=oauth_authorization_server, methods=["GET"]),
    Route("/oauth/register", endpoint=oauth_register, methods=["POST"]),
    Route("/oauth/authorize", endpoint=oauth_authorize, methods=["GET"]),
    Route("/oauth/token", endpoint=oauth_token, methods=["POST"]),
]

# Inject custom routes into MCP's FastMCP starlette app so lifespan runs correctly
mcp._custom_starlette_routes = custom_routes

# Build the streamable HTTP app (includes /mcp route + our custom routes + lifespan)
app = mcp.streamable_http_app()

# Add our middleware to the MCP app
for mw in reversed(middleware):
    app.add_middleware(mw.cls, **mw.kwargs)

# Add exception handlers
for exc_cls, handler in exceptions.items():
    app.add_exception_handler(exc_cls, handler)


def validate_settings() -> List[str]:
    errors: List[str] = []
    warnings: List[str] = []
    if SETTINGS.app_env not in {"development", "production"}:
        errors.append("APP_ENV must be development or production.")
    if SETTINGS.qb_environment not in {"sandbox", "production"}:
        errors.append("QB_ENVIRONMENT must be sandbox or production.")
    if not SETTINGS.qb_client_id:
        errors.append("QB_CLIENT_ID is missing.")
    if not SETTINGS.qb_client_secret:
        errors.append("QB_CLIENT_SECRET is missing.")
    if not SETTINGS.redirect_uri:
        errors.append("QB_REDIRECT_URI or PUBLIC_BASE_URL is required.")
    if SETTINGS.app_env == "production":
        if not SETTINGS.public_base_url:
            errors.append("PUBLIC_BASE_URL is required in production.")
        elif not SETTINGS.public_base_url.startswith("https://"):
            errors.append("PUBLIC_BASE_URL must start with https:// in production.")
        if not SETTINGS.token_encryption_key:
            errors.append("QB_TOKEN_ENCRYPTION_KEY is required in production.")
        if not SETTINGS.mcp_bearer_token:
            errors.append("MCP_BEARER_TOKEN is required in production.")
        if not SETTINGS.admin_password:
            errors.append("ADMIN_PASSWORD is required in production.")
    if SETTINGS.db_url.startswith("sqlite") and SETTINGS.app_env == "production":
        warnings.append("SQLite is acceptable for a single-node deployment, but PostgreSQL is recommended for multi-instance production.")
    if warnings:
        for item in warnings:
            logger.warning(item)
    return errors


def print_startup_banner() -> None:
    logger.info("%s", "=" * 78)
    logger.info(APP_NAME)
    logger.info("App environment   : %s", SETTINGS.app_env)
    logger.info("QB environment    : %s", SETTINGS.qb_environment)
    logger.info("Public base URL   : %s", SETTINGS.public_base_url or f"http://{SETTINGS.host}:{SETTINGS.port}")
    logger.info("Redirect URI      : %s", SETTINGS.redirect_uri)
    logger.info("MCP endpoint      : %s/mcp", SETTINGS.public_base_url or f"http://{SETTINGS.host}:{SETTINGS.port}")
    logger.info("Database          : %s", SETTINGS.db_url)
    logger.info("Token encryption  : %s", "enabled" if TOKEN_CIPHER.enabled else "disabled")
    logger.info("Invoice write     : %s", SETTINGS.enable_invoice_write)
    logger.info("%s", "=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--host", default=SETTINGS.host)
    parser.add_argument("--port", type=int, default=SETTINGS.port)
    parser.add_argument("--check", action="store_true", help="Validate configuration and exit.")
    parser.add_argument("--proxy-headers", action="store_true", help="Enable proxy headers handling in uvicorn.")
    args = parser.parse_args()

    errors = validate_settings()
    if args.check:
        if errors:
            print("Configuration errors:")
            for err in errors:
                print(f" - {err}")
            sys.exit(1)
        print("Configuration looks valid.")
        sys.exit(0)

    if errors:
        print("Configuration errors:")
        for err in errors:
            print(f" - {err}")
        sys.exit(1)

    print_startup_banner()
    uvicorn.run(app, host=args.host, port=args.port, log_level=SETTINGS.log_level.lower(), proxy_headers=args.proxy_headers)


if __name__ == "__main__":
    main()
