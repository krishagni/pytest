import csv
import io
import os
import pytest
import requests

from utilities import logger, BASE_URL

import os_test_framework
import security_test_framework

MASTER_GSHEET_ID   = os.getenv("MASTER_GSHEET_ID", "")
MASTER_GSHEET_SUMMARY_GID = os.getenv("MASTER_GSHEET_SUMMARY_GID", "")

# ── Summary-sheet URL ─────────────────────────────────────────────────────────
_SUMMARY_EXPORT_URL = (
    f"https://docs.google.com/spreadsheets/d/{MASTER_GSHEET_ID}"
    f"/export?format=csv&gid={MASTER_GSHEET_SUMMARY_GID}"
)

# ── Registry loader ────────────────────────────────────────────────────────────

def load_resource_registry() -> list[dict]:
    if not MASTER_GSHEET_ID:
        logger.critical("MASTER_GSHEET_ID is not set in .env — cannot load resource registry.")
        pytest.exit("MASTER_GSHEET_ID missing from .env")

    logger.info(f"📋 Loading resource registry from master sheet: {MASTER_GSHEET_ID}")
    try:
        resp = requests.get(_SUMMARY_EXPORT_URL, timeout=30)
        resp.raise_for_status()
    except Exception as exc:
        logger.critical(f"❌ Failed to download summary sheet: {exc}")
        pytest.exit(f"Could not reach master summary sheet: {exc}")

    reader = csv.DictReader(io.StringIO(resp.text))
    registry = []
    for row in reader:
        enabled = row.get("enabled", "true").strip().lower()
        if enabled != "true":
            logger.info(f"⏭  Skipping disabled resource: {row.get('resource_name', '?')}")
            continue

        api_path  = row.get("api_path", "").strip().lstrip("/")
        gid       = row.get("gid", "").strip()
        name      = row.get("resource_name", "unknown").strip()

        if not api_path or not gid:
            logger.warning(f"⚠️  Skipping row with missing api_path or gid: {row}")
            continue

        api_url = f"{BASE_URL}/{api_path}"
        csv_url = (
            f"https://docs.google.com/spreadsheets/d/{MASTER_GSHEET_ID}"
            f"/export?format=csv&gid={gid}"
        )
        items_url_template = row.get("validation_url", "").strip()
        registry.append({
            "resource_name": name,
            "api_url": api_url,
            "csv_url": csv_url,
            "validation_url": items_url_template,
        })
        logger.info(f"✅  Registered resource '{name}': {api_url}" + (f" (items: {items_url_template})" if items_url_template else ""))

    if not registry:
        logger.critical("No enabled resources found in the summary sheet.")
        pytest.exit("Summary sheet has no enabled resources.")

    return registry

# ── Cached registry (loaded once per session) ──────────────────────────────────
_RESOURCES: list[dict] | None = None

def get_resources() -> list[dict]:
    global _RESOURCES
    if _RESOURCES is None:
        _RESOURCES = load_resource_registry()
    return _RESOURCES


# ── Tests ──────────────────────────────────────────────────────────────

@pytest.mark.security
def test_security(sec_tc_row, record_property):
    """Executes the security test scenarios."""
    result = security_test_framework.execute_security_tc(sec_tc_row)
    security_test_framework.write_security_result(result)

    for field in security_test_framework.SECURITY_OUTPUT_EXTRA:
        record_property(field, str(result.get(field, "")))

    if result["TC_Status"] != "PASS":
        tc_id   = sec_tc_row.get("TC_ID", "?")
        details = result.get("Security_Assertion") or result.get("Error_Details") or "No details"
        pytest.fail(f"[{tc_id}] {details}", pytrace=False)

def test_resource(os_tc_row, record_property):
    """Generic test executing the payload against the dynamic URL for primary scenarios."""
    os_test_framework.execute_and_record_test(os_tc_row, record_property)
