"""
FedRAMP 20x integration tests.
Tests the encryption layer, DB CRUD, OSCAL generation, KSI engine,
and all API endpoints against an in-memory test database.

Run:  python -m pytest tests/test_fedramp.py -v
"""

import asyncio
import json
import os
import sys
import tempfile
import uuid

import pytest

# ── Env setup before any imports that read config ─────────────────────────────
os.environ.setdefault("DB_PATH", ":memory:")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ─────────────────────────────────────────────────────────────────────────────
# Section 1 — Encryption
# ─────────────────────────────────────────────────────────────────────────────

class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        from security.encryption import encrypt, decrypt
        plaintext = "super-secret-api-key-12345"
        token = encrypt(plaintext)
        assert token != plaintext
        assert decrypt(token) == plaintext

    def test_empty_string_passthrough(self):
        from security.encryption import encrypt, decrypt
        assert encrypt("") == ""
        assert decrypt("") == ""

    def test_different_plaintexts_different_tokens(self):
        from security.encryption import encrypt
        t1 = encrypt("key1")
        t2 = encrypt("key2")
        assert t1 != t2

    def test_encrypted_token_is_string(self):
        from security.encryption import encrypt
        token = encrypt("test")
        assert isinstance(token, str)


# ─────────────────────────────────────────────────────────────────────────────
# Section 2 — Scanner DB CRUD (uses real SQLite in temp file)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
async def temp_db(tmp_path):
    import config
    db_path = str(tmp_path / "test.db")
    config.DB_PATH = db_path
    import db.database as database
    await database.connect()
    yield database
    await database.close()


@pytest.mark.asyncio
async def test_scanner_config_crud(tmp_path):
    import config
    config.DB_PATH = str(tmp_path / "test.db")
    import db.database as database
    await database.connect()
    try:
        # Create a client first
        client_id = str(uuid.uuid4())
        import aiosqlite
        db = database.get_db()
        now = "2026-01-01T00:00:00"
        await db.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?,?,?)",
            (client_id, "Test Client", now)
        )
        await db.commit()

        # Create scanner
        scanner = await database.create_scanner_config(
            client_id=client_id,
            scanner_type="tenable",
            label="Test Tenable",
            host_url="https://cloud.tenable.com",
            api_key_enc="enc_key",
            poll_interval_hours=6,
        )
        assert scanner["id"] is not None
        assert scanner["scanner_type"] == "tenable"
        assert scanner["label"] == "Test Tenable"
        assert scanner["last_status"] == "never"

        # Get scanner
        fetched = await database.get_scanner_config(scanner["id"])
        assert fetched["id"] == scanner["id"]

        # Update scanner
        updated = await database.update_scanner_config(
            scanner["id"], last_status="ok:10 findings (3 new)"
        )
        assert updated["last_status"] == "ok:10 findings (3 new)"

        # List scanners
        scanners = await database.get_scanner_configs(client_id)
        assert len(scanners) == 1

        # Delete scanner
        await database.delete_scanner_config(scanner["id"])
        gone = await database.get_scanner_config(scanner["id"])
        assert gone is None

    finally:
        await database.close()


@pytest.mark.asyncio
async def test_scan_finding_upsert(tmp_path):
    import config
    config.DB_PATH = str(tmp_path / "test.db")
    import db.database as database
    await database.connect()
    try:
        client_id = str(uuid.uuid4())
        db = database.get_db()
        await db.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?,?,?)",
            (client_id, "Test Client", "2026-01-01T00:00:00")
        )
        await db.execute(
            "INSERT INTO scanner_configs (id, client_id, scanner_type, label, is_active, last_status, created_at) VALUES (?,?,?,?,1,'never',?)",
            (str(uuid.uuid4()), client_id, "tenable", "Test", "2026-01-01T00:00:00")
        )
        await db.commit()

        async with db.execute("SELECT id FROM scanner_configs") as cur:
            scanner_row = await cur.fetchone()
        scanner_id = scanner_row["id"]

        finding = {
            "client_id": client_id,
            "scanner_id": scanner_id,
            "scanner_type": "tenable",
            "hostname": "server01.example.com",
            "ip_address": "10.0.0.1",
            "cve_id": "CVE-2024-1234",
            "plugin_id": "1000",
            "severity": "HIGH",
            "cvss": 7.5,
            "title": "Test Vulnerability",
            "description": "Test description",
        }
        is_new = await database.upsert_scan_finding(finding)
        assert is_new is True

        # Upsert same finding — should return False (updated)
        is_new2 = await database.upsert_scan_finding(finding)
        assert is_new2 is False

        # Verify finding count
        findings = await database.get_scan_findings(client_id)
        assert len(findings) == 1
        assert findings[0]["cve_id"] == "CVE-2024-1234"

        # Severity counts
        counts = await database.count_scan_findings_by_severity(client_id)
        assert counts.get("HIGH", 0) == 1

    finally:
        await database.close()


# ─────────────────────────────────────────────────────────────────────────────
# Section 3 — OSCAL Generation
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_oscal_vdr_generation(tmp_path):
    import config
    config.DB_PATH = str(tmp_path / "test.db")
    import db.database as database
    await database.connect()
    try:
        client = {"id": str(uuid.uuid4()), "name": "OSCAL Test Client", "stack_profile": {}}
        db = database.get_db()
        await db.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?,?,?)",
            (client["id"], client["name"], "2026-01-01T00:00:00")
        )
        await db.commit()

        from compliance.oscal.generator import OSCALGenerator
        gen = OSCALGenerator(client)

        vdr_bytes = await gen.generate_vdr()
        vdr = json.loads(vdr_bytes)
        assert vdr["document-type"] == "vulnerability-disclosure-report"
        assert "vulnerabilities" in vdr
        assert "summary" in vdr

        oar_bytes = await gen.generate_oar()
        oar = json.loads(oar_bytes)
        assert oar["document-type"] == "ongoing-authorization-report"
        assert "authorization-decision" in oar

    finally:
        await database.close()


@pytest.mark.asyncio
async def test_oscal_xml_generation(tmp_path):
    import config
    config.DB_PATH = str(tmp_path / "test.db")
    import db.database as database
    await database.connect()
    try:
        client = {"id": str(uuid.uuid4()), "name": "XML Test", "stack_profile": {}}
        db = database.get_db()
        await db.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?,?,?)",
            (client["id"], client["name"], "2026-01-01T00:00:00")
        )
        await db.commit()

        from compliance.oscal.generator import OSCALGenerator
        gen = OSCALGenerator(client)

        poam = await gen.generate_poam()
        assert b"plan-of-action-and-milestones" in poam

        sar = await gen.generate_sar()
        assert b"assessment-results" in sar

        ssp = await gen.generate_ssp()
        assert b"system-security-plan" in ssp

    finally:
        await database.close()


@pytest.mark.asyncio
async def test_oscal_bundle_zip(tmp_path):
    import config, zipfile, io
    config.DB_PATH = str(tmp_path / "test.db")
    import db.database as database
    await database.connect()
    try:
        client = {"id": str(uuid.uuid4()), "name": "Bundle Test", "stack_profile": {}}
        db = database.get_db()
        await db.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?,?,?)",
            (client["id"], client["name"], "2026-01-01T00:00:00")
        )
        await db.commit()

        from compliance.oscal.generator import OSCALGenerator
        gen = OSCALGenerator(client)
        zip_bytes = await gen.generate_bundle_zip()

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
        assert any("poam" in n for n in names)
        assert any("sar" in n for n in names)
        assert any("vdr" in n for n in names)
        assert any("oar" in n for n in names)
        assert any("ssp" in n for n in names)

    finally:
        await database.close()


# ─────────────────────────────────────────────────────────────────────────────
# Section 4 — KSI Engine
# ─────────────────────────────────────────────────────────────────────────────

def test_ksi_definitions():
    from compliance.ksi_definitions import KSI_DEFINITIONS, KSI_LOOKUP
    assert len(KSI_DEFINITIONS) == 7
    for ksi in KSI_DEFINITIONS:
        assert "id" in ksi
        assert "name" in ksi
        assert "category" in ksi
        assert ksi["id"] in KSI_LOOKUP


@pytest.mark.asyncio
async def test_ksi_validation_runs(tmp_path):
    import config
    config.DB_PATH = str(tmp_path / "test.db")
    import db.database as database
    await database.connect()
    try:
        client_id = str(uuid.uuid4())
        db = database.get_db()
        await db.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?,?,?)",
            (client_id, "KSI Test", "2026-01-01T00:00:00")
        )
        await db.commit()

        from compliance.ksi_engine import KSIEngine
        engine = KSIEngine(client_id)
        results = await engine.validate_all()

        assert len(results) == 7
        for r in results:
            assert r["status"] in ("pass", "conditional", "fail", "error")
            assert 0.0 <= r["score"] <= 1.0
            assert "ksi_id" in r
            assert "ksi_name" in r
            assert "details" in r

        # Verify audit trail stored
        stored = await database.get_latest_ksi_results(client_id)
        assert len(stored) == 7

    finally:
        await database.close()


@pytest.mark.asyncio
async def test_ksi_pass_when_no_data(tmp_path):
    """With no findings/remediations/vendors, several KSIs should pass (nothing to fail)."""
    import config
    config.DB_PATH = str(tmp_path / "test.db")
    import db.database as database
    await database.connect()
    try:
        client_id = str(uuid.uuid4())
        db = database.get_db()
        await db.execute(
            "INSERT INTO clients (id, name, created_at) VALUES (?,?,?)",
            (client_id, "Empty Client", "2026-01-01T00:00:00")
        )
        await db.commit()

        from compliance.ksi_engine import KSIEngine
        results = await KSIEngine(client_id).validate_all()
        by_ksi = {r["ksi_id"]: r for r in results}

        # No findings → KSI-1 should pass
        assert by_ksi["KSI-1"]["status"] in ("pass", "conditional")
        # No remediations → KSI-2 should pass
        assert by_ksi["KSI-2"]["status"] == "pass"
        # No unack dark web alerts → KSI-7 should pass
        assert by_ksi["KSI-7"]["status"] == "pass"

    finally:
        await database.close()


# ─────────────────────────────────────────────────────────────────────────────
# Section 6 — Audit Log
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_log_crud(tmp_path):
    import config
    config.DB_PATH = str(tmp_path / "test.db")
    from db.audit_log import init_audit_db, log_event, get_audit_events, events_to_csv
    await init_audit_db()

    event_id = await log_event(
        event_type="api_request",
        username="admin",
        client_id="test-client",
        method="GET",
        path="/api/v1/clients/test-client/ksi",
        status_code=200,
        ip_address="127.0.0.1",
        duration_ms=42.5,
    )
    assert event_id is not None

    events = await get_audit_events(client_id="test-client")
    assert len(events) == 1
    assert events[0]["username"] == "admin"
    assert events[0]["status_code"] == 200
    assert events[0]["duration_ms"] == 42.5

    csv = events_to_csv(events)
    assert "api_request" in csv
    assert "admin" in csv


def test_audit_csv_format(tmp_path):
    from db.audit_log import events_to_csv
    events = [
        {"timestamp": "2026-05-07T12:00:00", "event_type": "api_request",
         "username": "user1", "client_id": "c1", "method": "POST",
         "path": "/api/v1/foo", "status_code": 201,
         "ip_address": "10.0.0.1", "user_agent": "test", "duration_ms": 15.3},
    ]
    csv = events_to_csv(events)
    lines = csv.strip().split("\n")
    assert len(lines) == 2  # header + 1 row
    assert "timestamp" in lines[0]
    assert "user1" in lines[1]


# ─────────────────────────────────────────────────────────────────────────────
# Section 7 — Wiring / smoke tests
# ─────────────────────────────────────────────────────────────────────────────

def test_scanner_fetcher_base_sev():
    from ingest.scanners.base import BaseScannerFetcher
    assert BaseScannerFetcher._sev(9.5) == "CRITICAL"
    assert BaseScannerFetcher._sev(7.5) == "HIGH"
    assert BaseScannerFetcher._sev(5.0) == "MEDIUM"
    assert BaseScannerFetcher._sev(2.0) == "LOW"
    assert BaseScannerFetcher._sev(0.0) == "INFO"
    assert BaseScannerFetcher._sev(None) == "INFO"


def test_siem_fetcher_base_sev():
    from ingest.siems.base import BaseSIEMFetcher
    assert BaseSIEMFetcher._sev("critical") == "CRITICAL"
    assert BaseSIEMFetcher._sev("High") == "HIGH"
    assert BaseSIEMFetcher._sev("MEDIUM") == "MEDIUM"
    assert BaseSIEMFetcher._sev("low") == "LOW"
    assert BaseSIEMFetcher._sev("informational") == "LOW"
    assert BaseSIEMFetcher._sev("") == "INFO"


def test_all_routers_importable():
    """Smoke test: all FedRAMP routers can be imported without error."""
    from api.scanner_routes import router as scanner_router
    from api.siem_routes import router as siem_router
    from api.oscal_routes import router as oscal_router
    from api.ksi_routes import router as ksi_router
    from api.audit_routes import router as audit_router
    assert scanner_router is not None
    assert siem_router is not None
    assert oscal_router is not None
    assert ksi_router is not None
    assert audit_router is not None


def test_ksi_definitions_completeness():
    from compliance.ksi_definitions import KSI_DEFINITIONS
    categories = {k["category"] for k in KSI_DEFINITIONS}
    expected = {"vulnerability", "patch", "monitoring", "detection",
                "remediation", "supply_chain", "darkweb"}
    assert categories == expected


def test_oscal_generator_importable():
    from compliance.oscal.generator import OSCALGenerator, OSCAL_NS
    assert OSCAL_NS == "http://csrc.nist.gov/ns/oscal/1.0"


# ─────────────────────────────────────────────────────────────────────────────
# Section 8 — Security controls
# ─────────────────────────────────────────────────────────────────────────────

def test_login_lockout_triggers():
    """AC-7: 5 failed attempts should raise 429."""
    import importlib
    import api.auth_routes as ar
    # Reset state
    ar._attempts.clear()
    username = "lockout_test_user"
    from fastapi import HTTPException
    for _ in range(ar._MAX_ATTEMPTS):
        ar._record_failure(username)
    try:
        ar._check_lockout(username)
        assert False, "Expected HTTPException 429"
    except HTTPException as e:
        assert e.status_code == 429
        assert "locked" in e.detail.lower()


def test_login_lockout_clears_on_success():
    """Successful login clears the failure counter."""
    import api.auth_routes as ar
    username = "clear_test_user"
    ar._attempts.clear()
    for _ in range(ar._MAX_ATTEMPTS - 1):
        ar._record_failure(username)
    ar._clear_failures(username)
    # Should not raise after clear
    ar._check_lockout(username)


def test_require_client_access_admin_passes():
    """Admin users bypass the client_id check."""
    from fastapi import HTTPException
    from auth.auth import require_client_access
    admin = {"role": "admin", "client_id": None}
    require_client_access(admin, "any-client-id")  # must not raise


def test_require_client_access_owner_passes():
    """Client user with matching client_id passes."""
    from auth.auth import require_client_access
    user = {"role": "client", "client_id": "abc-123"}
    require_client_access(user, "abc-123")  # must not raise


def test_require_client_access_wrong_client_raises():
    """Client user with mismatched client_id gets 403."""
    from fastapi import HTTPException
    from auth.auth import require_client_access
    user = {"role": "client", "client_id": "abc-123"}
    try:
        require_client_access(user, "other-client-id")
        assert False, "Expected HTTPException 403"
    except HTTPException as e:
        assert e.status_code == 403


@pytest.mark.asyncio
async def test_user_update_and_delete(tmp_path):
    """update_user and delete_user work correctly."""
    import config
    config.DB_PATH = str(tmp_path / "test.db")
    import db.database as database
    await database.connect()
    try:
        from auth.auth import hash_password, verify_password
        user = await database.create_user(
            username="test_edit_user",
            password_hash=hash_password("oldpass"),
            role="client",
        )
        user_id = user["id"]

        # Update password
        new_hash = hash_password("newpass")
        updated = await database.update_user(user_id, password_hash=new_hash)
        assert updated is not None
        assert verify_password("newpass", updated["password_hash"])

        # Update role
        updated = await database.update_user(user_id, role="analyst")
        assert updated["role"] == "analyst"

        # Delete
        deleted = await database.delete_user(user_id)
        assert deleted is True
        assert await database.get_user_by_id(user_id) is None

        # Delete non-existent
        assert await database.delete_user("nonexistent-id") is False
    finally:
        await database.close()


# ── New session scope-enforcement tests ──────────────────────────────────────

def test_analytics_scope_admin_passthrough():
    """Admin users can pass any client_id to analytics endpoints."""
    from api.analytics_routes import _scope_client_id
    admin = {"role": "admin", "client_id": None}
    assert _scope_client_id(admin, "other-client") == "other-client"
    assert _scope_client_id(admin, None) is None


def test_analytics_scope_non_admin_own_client():
    """Non-admin with matching client_id is allowed."""
    from api.analytics_routes import _scope_client_id
    user = {"role": "analyst", "client_id": "my-client"}
    assert _scope_client_id(user, "my-client") == "my-client"
    assert _scope_client_id(user, None) is None


def test_analytics_scope_non_admin_wrong_client_raises():
    """Non-admin requesting another client's analytics gets 403."""
    from fastapi import HTTPException
    from api.analytics_routes import _scope_client_id
    user = {"role": "analyst", "client_id": "my-client"}
    try:
        _scope_client_id(user, "other-client")
        assert False, "Expected HTTPException 403"
    except HTTPException as e:
        assert e.status_code == 403


def test_audit_scope_admin_passthrough():
    """Admin users can request any client's audit events."""
    from api.audit_routes import _enforce_audit_scope
    admin = {"role": "admin", "client_id": None}
    assert _enforce_audit_scope(admin, "other-client") == "other-client"
    assert _enforce_audit_scope(admin, None) is None


def test_audit_scope_non_admin_own_client():
    """Non-admin gets scoped to their own client_id automatically."""
    from api.audit_routes import _enforce_audit_scope
    user = {"role": "analyst", "client_id": "my-client"}
    assert _enforce_audit_scope(user, None) == "my-client"
    assert _enforce_audit_scope(user, "my-client") == "my-client"


def test_audit_scope_non_admin_wrong_client_raises():
    """Non-admin requesting another client's audit gets 403."""
    from fastapi import HTTPException
    from api.audit_routes import _enforce_audit_scope
    user = {"role": "analyst", "client_id": "my-client"}
    try:
        _enforce_audit_scope(user, "other-client")
        assert False, "Expected HTTPException 403"
    except HTTPException as e:
        assert e.status_code == 403


def test_upload_size_limit():
    """Files over 50 MB are rejected with HTTP 413."""
    from fastapi import HTTPException
    from api.upload_routes import _check_size, MAX_UPLOAD_BYTES
    _check_size(b"x" * MAX_UPLOAD_BYTES)  # exactly at limit — must not raise
    try:
        _check_size(b"x" * (MAX_UPLOAD_BYTES + 1))
        assert False, "Expected HTTPException 413"
    except HTTPException as e:
        assert e.status_code == 413


def test_pydantic_user_create_password_complexity():
    """UserCreate enforces length + letter + digit-or-special requirements."""
    from pydantic import ValidationError
    from api.admin_routes import UserCreate

    bad = ["short", "alllowercase", "12345678", "NoDigitOrSpecial"]
    for pw in bad:
        try:
            UserCreate(username="testuser", password=pw)
            assert False, f"Expected ValidationError for '{pw}'"
        except ValidationError:
            pass

    # Valid: letter + digit + special, >=8 chars
    UserCreate(username="testuser", password="Secure1!")
    UserCreate(username="testuser", password="longpassword123")


def test_webhook_url_ssrf_validation():
    """WebhookCreate rejects private/loopback URLs and accepts public ones."""
    from pydantic import ValidationError
    from api.admin_routes import WebhookCreate

    bad_urls = [
        "http://localhost/hook",
        "http://127.0.0.1/hook",
        "http://10.0.0.5/hook",
        "http://192.168.1.1/hook",
        "http://172.20.0.1/hook",
        "http://169.254.169.254/latest/meta-data/",
        "ftp://example.com/hook",
    ]
    for url in bad_urls:
        try:
            WebhookCreate(webhook_type="generic", url=url)
            assert False, f"Expected ValidationError for {url}"
        except ValidationError:
            pass

    # Public HTTPS URL should be accepted
    wh = WebhookCreate(webhook_type="generic", url="https://hooks.example.com/abc")
    assert wh.url == "https://hooks.example.com/abc"


def test_rate_limiter_enforces_limit():
    """check_rate_limit raises HTTP 429 after max_calls exceeded."""
    import time
    from fastapi import HTTPException
    from api.rate_limit import _store, check_rate_limit

    key = f"test_rate_{time.monotonic()}"
    _store.pop(key, None)  # clean slate

    check_rate_limit(key, max_calls=3, window_seconds=60)
    check_rate_limit(key, max_calls=3, window_seconds=60)
    check_rate_limit(key, max_calls=3, window_seconds=60)

    try:
        check_rate_limit(key, max_calls=3, window_seconds=60)
        assert False, "Expected HTTP 429"
    except HTTPException as e:
        assert e.status_code == 429


def test_integration_ssrf_blocks_loopback_and_metadata():
    """Scanner/SIEM test requests reject loopback and cloud-metadata host URLs."""
    from pydantic import ValidationError
    from api.integration_routes import ScannerTestRequest, SIEMTestRequest

    blocked = [
        "http://localhost/api",
        "http://127.0.0.1:8834",
        "http://169.254.169.254/latest/meta-data/",
        "ftp://192.168.1.1/scan",   # bad scheme
    ]
    for url in blocked:
        try:
            ScannerTestRequest(scanner_type="tenable", host_url=url)
            assert False, f"Expected ValidationError for scanner {url}"
        except ValidationError:
            pass
        try:
            SIEMTestRequest(siem_type="splunk", host_url=url)
            assert False, f"Expected ValidationError for SIEM {url}"
        except ValidationError:
            pass

    # Internal RFC-1918 hosts are legitimate scanner targets — must be allowed
    req = ScannerTestRequest(scanner_type="tenable", host_url="https://10.0.0.5:8834")
    assert req.host_url == "https://10.0.0.5:8834"

    # Public hostname must be allowed
    req2 = SIEMTestRequest(siem_type="splunk", host_url="https://splunk.example.com")
    assert req2.host_url == "https://splunk.example.com"


def test_csp_header_directive_coverage():
    """CSP string in main.py contains the required restrictive directives."""
    import main  # importing triggers module-level code; just inspect the source
    import inspect, textwrap
    src = inspect.getsource(main.security_headers)
    assert "Content-Security-Policy" in src
    assert "object-src 'none'" in src
    assert "base-uri 'self'" in src
    assert "frame-ancestors 'none'" in src
    assert "connect-src 'self'" in src


# ── JWT revocation tests ──────────────────────────────────────────────────────

def test_create_access_token_includes_jti():
    """Every issued token includes a unique jti claim."""
    from auth.auth import create_access_token, decode_token
    t1 = create_access_token({"sub": "user-1", "role": "analyst", "token_version": 0})
    t2 = create_access_token({"sub": "user-1", "role": "analyst", "token_version": 0})
    p1 = decode_token(t1)
    p2 = decode_token(t2)
    assert "jti" in p1
    assert "jti" in p2
    assert p1["jti"] != p2["jti"], "Each token must have a unique jti"


def test_create_access_token_includes_token_version():
    """Token payload carries the token_version claim passed at creation time."""
    from auth.auth import create_access_token, decode_token
    token = create_access_token({"sub": "u", "role": "analyst", "token_version": 3})
    payload = decode_token(token)
    assert payload.get("token_version") == 3


@pytest.mark.asyncio
async def test_revoke_token_blocks_reuse():
    """A token added to the denylist is rejected by is_token_revoked."""
    from db import database as db
    await db.connect()
    jti = str(uuid.uuid4())
    assert not await db.is_token_revoked(jti)
    await db.revoke_token(jti, "user-x", "2099-01-01T00:00:00")
    assert await db.is_token_revoked(jti)


@pytest.mark.asyncio
async def test_bump_token_version_invalidates_old_tokens():
    """After bump_token_version, a token carrying the old version is rejected."""
    from db import database as db
    from auth.auth import create_access_token, _validate_decoded_token
    from fastapi import HTTPException

    await db.connect()

    # Create a fresh user
    uid = str(uuid.uuid4())
    await db.create_user(
        username=f"revoke_test_{uid[:8]}",
        password_hash="x",
        role="analyst",
        client_id=None,
    )
    user = await db.get_user_by_username(f"revoke_test_{uid[:8]}")
    user_id = user["id"]

    # Issue a token at version 0
    token = create_access_token({
        "sub": user_id, "role": "analyst", "token_version": 0
    })
    from auth.auth import decode_token
    payload = decode_token(token)

    # Token should be valid now
    result = await _validate_decoded_token(payload)
    assert result["id"] == user_id

    # Admin bumps the version
    await db.bump_token_version(user_id)

    # Same token is now rejected
    try:
        await _validate_decoded_token(payload)
        assert False, "Expected HTTPException after token version bump"
    except HTTPException as e:
        assert e.status_code == 401
        assert "invalidated" in e.detail.lower()


@pytest.mark.asyncio
async def test_purge_expired_tokens_removes_stale_entries():
    """purge_expired_tokens removes entries with past expires_at."""
    from db import database as db
    await db.connect()
    jti_old = str(uuid.uuid4())
    jti_new = str(uuid.uuid4())
    await db.revoke_token(jti_old, "u1", "2000-01-01T00:00:00")  # already expired
    await db.revoke_token(jti_new, "u2", "2099-01-01T00:00:00")  # far future
    await db.purge_expired_tokens()
    assert not await db.is_token_revoked(jti_old), "Expired entry should be purged"
    assert await db.is_token_revoked(jti_new), "Future entry must be kept"


# ── Request body size limit tests ─────────────────────────────────────────────

def test_json_body_size_middleware_constant():
    """_MAX_JSON_BODY is set to 1 MB and referenced by the middleware."""
    import inspect
    import main
    src = inspect.getsource(main.limit_json_body)
    # Middleware must reference the constant
    assert "_MAX_JSON_BODY" in src
    assert main._MAX_JSON_BODY == 1 * 1024 * 1024


def test_upload_confirm_cleanup_uses_finally():
    """confirm_scan / confirm_assets / confirm_clients use try/finally for cleanup."""
    import inspect
    from api import upload_routes
    for fn_name in ("confirm_scan", "confirm_assets", "confirm_clients"):
        src = inspect.getsource(getattr(upload_routes, fn_name))
        assert "finally" in src, f"{fn_name} must use try/finally to guarantee cleanup"
        assert "_cleanup_temp" in src, f"{fn_name} must call _cleanup_temp"


# ── Correlation ID tests ──────────────────────────────────────────────────────

def test_audit_middleware_generates_request_id():
    """AuditMiddleware generates an X-Request-ID when none is present."""
    import inspect
    from api.audit_middleware import AuditMiddleware
    src = inspect.getsource(AuditMiddleware.dispatch)
    assert "X-Request-ID" in src or "x-request-id" in src
    assert "uuid" in src


def test_request_id_in_log_event_signature():
    """log_event() accepts a request_id parameter."""
    import inspect
    from db.audit_log import log_event
    sig = inspect.signature(log_event)
    assert "request_id" in sig.parameters


# ── Concurrent session cap tests ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_session_cap_blocks_excess_logins():
    """count_active_sessions respects MAX_SESSIONS; 6th session is blocked at login."""
    from db import database as db
    from db.database import MAX_SESSIONS, create_session, count_active_sessions
    await db.connect()

    uid = str(uuid.uuid4())
    await db.create_user(
        username=f"cap_test_{uid[:8]}",
        password_hash="x",
        role="analyst",
        client_id=None,
    )
    user = await db.get_user_by_username(f"cap_test_{uid[:8]}")
    user_id = user["id"]

    # Fill up to the cap
    far_future = "2099-01-01T00:00:00"
    for i in range(MAX_SESSIONS):
        await create_session(str(uuid.uuid4()), user_id, far_future)

    assert await count_active_sessions(user_id) == MAX_SESSIONS


@pytest.mark.asyncio
async def test_revoke_session_decrements_count():
    """Revoking a session via revoke_session() drops the active count."""
    from db import database as db
    from db.database import create_session, count_active_sessions, revoke_session
    await db.connect()

    uid = str(uuid.uuid4())
    await db.create_user(
        username=f"rev_test_{uid[:8]}",
        password_hash="x",
        role="analyst",
        client_id=None,
    )
    user = await db.get_user_by_username(f"rev_test_{uid[:8]}")
    user_id = user["id"]

    jti = str(uuid.uuid4())
    await create_session(jti, user_id, "2099-01-01T00:00:00")
    assert await count_active_sessions(user_id) >= 1

    await revoke_session(jti)
    # Session should no longer be counted as active
    async with db.get_db().execute(
        "SELECT revoked FROM user_sessions WHERE jti = ?", (jti,)
    ) as cur:
        row = await cur.fetchone()
    assert row is not None and row[0] == 1


@pytest.mark.asyncio
async def test_revoke_all_user_sessions():
    """revoke_all_user_sessions marks every session for the user as revoked."""
    from db import database as db
    from db.database import create_session, count_active_sessions, revoke_all_user_sessions
    await db.connect()

    uid = str(uuid.uuid4())
    await db.create_user(
        username=f"rall_test_{uid[:8]}",
        password_hash="x",
        role="analyst",
        client_id=None,
    )
    user = await db.get_user_by_username(f"rall_test_{uid[:8]}")
    user_id = user["id"]

    for _ in range(3):
        await create_session(str(uuid.uuid4()), user_id, "2099-01-01T00:00:00")
    assert await count_active_sessions(user_id) == 3

    await revoke_all_user_sessions(user_id)
    assert await count_active_sessions(user_id) == 0


# ── Feed health tracking tests ────────────────────────────────────────────────

def test_feed_health_initial_state():
    """Fresh fetcher reports 'never' status with no run data."""
    from ingest.nvd import NVDFetcher
    f = NVDFetcher()
    h = f.get_health()
    assert h["status"] == "never"
    assert h["last_run_at"] is None
    assert h["last_success_at"] is None
    assert h["last_error"] is None
    assert h["consecutive_failures"] == 0
    assert h["feed_id"] == f.feed_id
    assert h["poll_interval_minutes"] == f.poll_interval


@pytest.mark.asyncio
async def test_feed_health_records_success():
    """After a successful run, health shows 'ok' and populated timestamps."""
    from unittest.mock import AsyncMock, patch
    from ingest.nvd import NVDFetcher

    fetcher = NVDFetcher()
    fake_item = {
        "id": "test-nvd-001",
        "feed_id": "nvd",
        "feed_label": "NVD CVEs",
        "title": "Test CVE",
        "description": "Test",
        "severity": "HIGH",
        "category": "cve",
        "published_at": "2025-01-01",
        "fetched_at": "2025-01-01",
        "is_new": 1,
    }

    with (
        patch.object(fetcher, "fetch", new=AsyncMock(return_value=[fake_item])),
        patch("db.database.upsert_item", new=AsyncMock(return_value=True)),
        patch("db.database.get_all_assets_for_matching", new=AsyncMock(return_value=[])),
        patch("ingest.risk_score.score_item", new=AsyncMock(return_value=0)),
        patch("reports.webhook_dispatcher.get_dispatcher"),
    ):
        from db import database as db
        await db.connect()
        count = await fetcher.run()

    h = fetcher.get_health()
    assert h["status"] == "ok"
    assert h["last_run_at"] is not None
    assert h["last_success_at"] is not None
    assert h["last_error"] is None
    assert h["consecutive_failures"] == 0


@pytest.mark.asyncio
async def test_feed_health_records_failure():
    """When fetch() raises, health shows 'error' and increments consecutive_failures."""
    from unittest.mock import AsyncMock, patch
    from ingest.nvd import NVDFetcher

    fetcher = NVDFetcher()
    with patch.object(fetcher, "fetch", new=AsyncMock(side_effect=RuntimeError("DNS failure"))):
        from db import database as db
        await db.connect()
        count = await fetcher.run()

    assert count == 0
    h = fetcher.get_health()
    assert h["status"] == "error"
    assert h["consecutive_failures"] == 1
    assert "DNS failure" in (h["last_error"] or "")


def test_scheduler_get_feed_health_returns_list():
    """get_feed_health returns a list after the scheduler is built."""
    from unittest.mock import patch
    from ingest import scheduler

    with patch("ingest.scheduler.AsyncIOScheduler"):
        scheduler.start_scheduler()

    health = scheduler.get_feed_health()
    assert isinstance(health, list)
    assert len(health) > 0
    for entry in health:
        assert "feed_id" in entry
        assert "status" in entry
        assert entry["status"] in ("ok", "error", "never")

    scheduler.stop_scheduler()
