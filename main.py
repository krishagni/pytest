import csv
import io
import logging
import os

import pytest
import requests
from dotenv import load_dotenv

import os_test_framework

env_file = os.getenv("ENV_FILE", ".env")
load_dotenv(env_file)

logger = logging.getLogger(__name__)

BASE_URL           = os.getenv("OS_BASE_URL", "").rstrip("/")
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

        api_url = f"{BASE_URL}/{api_path}".rstrip("/")
        csv_url = (
            f"https://docs.google.com/spreadsheets/d/{MASTER_GSHEET_ID}"
            f"/export?format=csv&gid={gid}"
        )
        registry.append({"resource_name": name, "api_url": api_url, "csv_url": csv_url})
        logger.info(f"✅  Registered resource '{name}': {api_url}")

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


# ── pytest hooks ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="session", autouse=True)
def save_combined_results():
    """Clean up temp data after all tests run."""
    yield
    os_test_framework.cleanup_temp_data()


def pytest_generate_tests(metafunc):
    if "tc_row" not in metafunc.fixturenames:
        return

    all_cases = []
    for resource in get_resources():
        all_cases.extend(
            os_test_framework.run_tc(
                resource["api_url"], resource["csv_url"], metafunc
            )
        )

    if all_cases:
        metafunc.parametrize(
            "tc_row",
            all_cases,
            ids=[f"{r.get('TC_ID', 'TC')}" for r in all_cases],
        )


def test_resource(tc_row, record_property):
    """Generic test executing the payload against the dynamic URL."""
    os_test_framework.execute_and_record_test(tc_row, record_property)
