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
