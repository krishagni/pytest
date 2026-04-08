"""
security_test_framework.py
──────────────────────────
OpenSpecimen Security Test Suite — single-file engine + pytest entry point.

Reads a 7-column Google Sheet:
  TC_ID | TC_Description | Operation | Endpoint | Expected_Result | File_Info | Comments

Loads per-TC payload files from:
  <SECURITY_TC_DATA_DIR>/<TC_ID>/<File_Info>

Supports operations: POST, GET, PUT, DELETE
Security assertions: HTTP-status based + optional body reflection check

Run with:
  pytest security_test_framework.py -v
  pytest security_test_framework.py -v -k "TC_XSS_01"
  pytest security_test_framework.py -v --html=security_report.html
"""

import csv
import io
import json
import logging
import os
import threading
from datetime import datetime
from typing import Optional

import requests
from dotenv import load_dotenv

# ── Bootstrap ─────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)

env_file = os.getenv("ENV_FILE", ".env")
load_dotenv(env_file)

# ── Config (all from .env) ────────────────────────────────────────────────────

BASE_URL              = os.getenv("OS_BASE_URL", "").rstrip("/")
SECURITY_GSHEET_URL   = os.getenv("SECURITY_GSHEET_URL", "")
SECURITY_TC_DATA_DIR  = os.getenv("SECURITY_TC_DATA_DIR", "security_tests/tc_data")
MASTER_GSHEET_ID      = os.getenv("MASTER_GSHEET_ID", "")
SECURITY_GSHEET_GID   = os.getenv("SECURITY_GSHEET_GID", "")
ROLES_GSHEET_GID      = os.getenv("ROLES_GSHEET_GID", "")

_env_sec_out          = os.getenv("SECURITY_OUTPUT_FILE", "security_output.csv")
_base, _ext           = os.path.splitext(_env_sec_out)
SECURITY_OUTPUT_FILE  = f"{_base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{_ext}"

# Bulk-import endpoint pattern (can be overridden via .env)
BULK_IMPORT_URL       = os.getenv("BULK_IMPORT_URL", f"{BASE_URL}/bulk-imports")

# Output columns for the security results CSV
SECURITY_META_FIELDS = [
    "TC_ID", "TC_Description", "Operation", "Endpoint",
    "Expected_Result", "File_Info", "Comments",
]
SECURITY_OUTPUT_EXTRA = [
    "TC_Status", "HTTP_Status_Code", "Security_Assertion",
    "Reflected_Input_Found", "Error_Details", "Latency_ms",
]

# ── Auth (reuses the Roles sheet from .env) ───────────────────────────────────

_ROLES_CACHE: Optional[dict] = None
_TOKEN_CACHE: dict = {}
_token_lock = threading.Lock()


def _load_roles() -> dict:
    """Load credential roles from the Roles tab of the master GSheet."""
    global _ROLES_CACHE
    if _ROLES_CACHE is not None:
        return _ROLES_CACHE

    roles_url = (
        f"https://docs.google.com/spreadsheets/d/{MASTER_GSHEET_ID}"
        f"/export?format=csv&gid={ROLES_GSHEET_GID}"
    )
    try:
        resp = requests.get(roles_url, timeout=30)
        resp.raise_for_status()
        reader = csv.DictReader(io.StringIO(resp.text))
        roles = {}
        for row in reader:
            r = row.get("Role", "").strip().upper()
            if r:
                roles[r] = {
                    "login": row.get("Login_Name", "").strip(),
                    "password": row.get("Password", "").strip(),
                    "domain": row.get("Domain_Name", "").strip(),
                }
        logger.info(f"🔑 Loaded {len(roles)} roles from GSheet")
        _ROLES_CACHE = roles
        return roles
    except Exception as exc:
        logger.warning(f"⚠️ Failed to load roles: {exc}")
        _ROLES_CACHE = {}
        return {}


def get_security_token(role: str = "admin") -> str:
    """Return a cached auth token for `role`."""
    key = role.upper().strip()
    with _token_lock:
        if key in _TOKEN_CACHE:
            return _TOKEN_CACHE[key]

    roles = _load_roles()
    creds_info = roles.get(key, {})
    login    = creds_info.get("login")
    password = creds_info.get("password")
    domain   = creds_info.get("domain")

    if not login or not password:
        raise ValueError(
            f"No credentials found for role '{role}'. "
            "Check the Roles tab in your GSheet."
        )

    body = {"loginName": login, "password": password}
    if domain:
        body["domainName"] = domain

    resp = requests.post(f"{BASE_URL}/sessions", json=body, timeout=10)
    resp.raise_for_status()
    token = resp.json()["token"]

    with _token_lock:
        _TOKEN_CACHE[key] = token
    return token


# ── Sheet Loader ──────────────────────────────────────────────────────────────

def _resolve_security_url() -> str:
    """
    Build the GSheet CSV export URL.
    Priority:
      1. SECURITY_GSHEET_URL  (full URL already set in .env)
      2. MASTER_GSHEET_ID + SECURITY_GSHEET_GID
    """
    if SECURITY_GSHEET_URL:
        return SECURITY_GSHEET_URL
    if MASTER_GSHEET_ID and SECURITY_GSHEET_GID:
        return (
            f"https://docs.google.com/spreadsheets/d/{MASTER_GSHEET_ID}"
            f"/export?format=csv&gid={SECURITY_GSHEET_GID}"
        )
    return ""


def load_security_cases() -> list[dict]:
    """
    Download and parse the 7-column security GSheet.
    Returns a list of row dicts with normalised keys.
    """
    url = _resolve_security_url()
    if not url:
        raise EnvironmentError(
            "No security sheet configured. Set SECURITY_GSHEET_URL "
            "or MASTER_GSHEET_ID + SECURITY_GSHEET_GID in .env"
        )

    logger.info(f"📥 Downloading security sheet from: {url}")
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()

    reader = csv.DictReader(io.StringIO(resp.text))
    cases = []
    for row in reader:
        # Normalise: strip whitespace from all keys and values
        normalised = {k.strip(): v.strip() for k, v in row.items() if k}
        tc_id = normalised.get("TC_ID", "").strip()
        if not tc_id:
            continue  # skip blank rows
        cases.append(normalised)

    logger.info(f"✅ Loaded {len(cases)} security test cases")
    return cases


# ── File Loader (per-TC) ──────────────────────────────────────────────────────

def load_tc_file(tc_id: str, file_info: str) -> Optional[dict | bytes]:
    """
    Load the payload file for a TC from its dedicated folder.

    Returns:
      - dict  → for .json files
      - bytes → for .csv files (bulk-import)
      - None  → if file_info is blank (e.g. GET / DELETE with no body)
    """
    file_info = (file_info or "").strip()
    if not file_info:
        return None

    # Resolve path: <SECURITY_TC_DATA_DIR>/<TC_ID>/<file_info>
    tc_folder = os.path.join(SECURITY_TC_DATA_DIR, tc_id)
    file_path = os.path.join(tc_folder, file_info)

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"[{tc_id}] Expected payload file not found: {file_path}"
        )

    _, ext = os.path.splitext(file_info.lower())

    if ext == ".json":
        with open(file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        logger.info(f"📄 [{tc_id}] Loaded JSON from: {file_path}")
        return data

    if ext == ".csv":
        with open(file_path, "rb") as fh:
            data = fh.read()
        logger.info(f"📄 [{tc_id}] Loaded CSV bytes from: {file_path}")
        return data

    # Unknown extension — try JSON first, then raw bytes
    logger.warning(f"[{tc_id}] Unknown file extension '{ext}', trying JSON…")
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        with open(file_path, "rb") as fh:
            return fh.read()


# ── Request Builder ───────────────────────────────────────────────────────────

def _build_url(endpoint: str) -> str:
    """Combine BASE_URL with the endpoint from the sheet."""
    endpoint = endpoint.strip().lstrip("/")
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint
    return f"{BASE_URL}/{endpoint}"


def _auth_headers(token: str) -> dict:
    return {"X-OS-API-TOKEN": token, "Content-Type": "application/json"}


def _dispatch_request(
    operation: str,
    url: str,
    headers: dict,
    payload,
    file_info: str,
) -> requests.Response:
    """
    Send the HTTP request based on Operation column.

    payload can be:
      - dict  → sent as JSON for POST / PUT
      - bytes → sent as multipart file upload (bulk-import CSV)
      - None  → no body (GET / DELETE)
    """
    op = operation.strip().upper()
    timeout = 20

    if isinstance(payload, bytes):
        # Bulk-import: multipart upload
        # Strip Content-Type so requests sets multipart boundary
        multipart_headers = {k: v for k, v in headers.items() if k != "Content-Type"}
        files = {"file": (file_info, payload, "text/csv")}
        if op == "POST":
            return requests.post(url, headers=multipart_headers, files=files, timeout=timeout)
        if op == "PUT":
            return requests.put(url, headers=multipart_headers, files=files, timeout=timeout)

    if op == "POST":
        return requests.post(url, headers=headers, json=payload, timeout=timeout)
    if op == "PUT":
        return requests.put(url, headers=headers, json=payload, timeout=timeout)
    if op == "GET":
        return requests.get(url, headers=headers, timeout=timeout)
    if op == "DELETE":
        return requests.delete(url, headers=headers, timeout=timeout)

    raise ValueError(f"Unsupported operation: '{operation}'")


# ── Security Assertion ────────────────────────────────────────────────────────

# Patterns that indicate the server reflected the input (bad for security)
_REFLECTION_PATTERNS = [
    "<script", "alert(", "onerror=", "onload=",   # XSS
    "' OR '", "' OR 1=1", "--",                    # SQL injection
    "UNION SELECT", "DROP TABLE",                  # SQLi DDL
]


def _check_reflection(payload, response_text: str) -> bool:
    """
    Returns True if any XSS/SQLi token from the payload appears in the response.
    This catches reflected XSS and verbose SQL error leakage.
    """
    if payload is None or isinstance(payload, bytes):
        return False

    # Flatten all string values from the payload dict
    def _extract_strings(obj) -> list[str]:
        if isinstance(obj, str):
            return [obj]
        if isinstance(obj, dict):
            result = []
            for v in obj.values():
                result.extend(_extract_strings(v))
            return result
        if isinstance(obj, list):
            result = []
            for item in obj:
                result.extend(_extract_strings(item))
            return result
        return []

    payload_strings = _extract_strings(payload)
    resp_lower = response_text.lower()

    for s in payload_strings:
        s_lower = s.lower()
        for pattern in _REFLECTION_PATTERNS:
            if pattern.lower() in s_lower and pattern.lower() in resp_lower:
                return True
    return False


def assert_security(
    row: dict,
    response: requests.Response,
    payload,
) -> tuple[str, str, bool]:
    """
    Evaluate the security test result.

    Returns:
        (TC_Status, Security_Assertion_message, reflected_input_found)
    """
    expected = row.get("Expected_Result", "").strip().lower()
    resp_text = response.text or ""

    # Reflection check (relevant mainly for Expected_Result=fail)
    reflected = _check_reflection(payload, resp_text)

    if expected == "fail":
        # The test PASSES if the server rejects the request (non-2xx)
        # AND does NOT reflect malicious content back in its response.
        if not response.ok:
            if reflected:
                return (
                    "FAIL",
                    f"Server rejected (HTTP {response.status_code}) but REFLECTED malicious input in response body",
                    True,
                )
            return (
                "PASS",
                f"Server correctly rejected malicious input (HTTP {response.status_code})",
                False,
            )
        else:
            # Server returned 2xx — it accepted the malicious payload
            msg = f"SECURITY VULNERABILITY: Server accepted malicious input (HTTP {response.status_code})"
            if reflected:
                msg += " AND reflected it in the response (Reflected XSS risk)"
            return "FAIL", msg, reflected

    elif expected == "pass":
        # Positive test: expect a 2xx response with a legitimate payload
        if response.ok:
            return "PASS", f"Legitimate request accepted (HTTP {response.status_code})", False
        else:
            return (
                "FAIL",
                f"Legitimate request unexpectedly rejected (HTTP {response.status_code})",
                False,
            )

    else:
        return (
            "ERROR",
            f"Unknown Expected_Result value: '{expected}' (use 'pass' or 'fail')",
            False,
        )


# ── Test Executor ─────────────────────────────────────────────────────────────

def execute_security_tc(row: dict) -> dict:
    """
    Run a single security test case row and return the full result dict.
    """
    tc_id       = row.get("TC_ID", "UNKNOWN")
    operation   = row.get("Operation", "POST")
    endpoint    = row.get("Endpoint", "")
    file_info   = row.get("File_Info", "")
    role        = row.get("Role", "admin").strip()

    result = {field: row.get(field, "") for field in SECURITY_META_FIELDS}
    for field in SECURITY_OUTPUT_EXTRA:
        result[field] = ""
    result["TC_Status"] = "ERROR"

    try:
        # 1. Authenticate
        token   = get_security_token(role)
        headers = _auth_headers(token)

        # 2. Load payload file (if any)
        try:
            payload = load_tc_file(tc_id, file_info)
        except FileNotFoundError as fnf:
            result["Error_Details"] = str(fnf)
            return result

        # 3. Build URL
        url = _build_url(endpoint)
        logger.info(f"🔐 [{tc_id}] {operation} → {url}  (file: {file_info or 'none'})")

        # 4. Dispatch HTTP request
        t0 = datetime.now()
        response = _dispatch_request(operation, url, headers, payload, file_info)
        latency_ms = int((datetime.now() - t0).total_seconds() * 1000)

        result["HTTP_Status_Code"] = response.status_code
        result["Latency_ms"]       = latency_ms

        # 5. Security assertion
        tc_status, assertion_msg, reflected = assert_security(row, response, payload)
        result["TC_Status"]              = tc_status
        result["Security_Assertion"]     = assertion_msg
        result["Reflected_Input_Found"]  = str(reflected)

        if tc_status == "FAIL":
            # Capture a short snippet of the response for diagnosis
            try:
                body_snippet = json.dumps(response.json())[:300]
            except Exception:
                body_snippet = (response.text or "")[:300]
            result["Error_Details"] = body_snippet

        logger.info(f"{'✅' if tc_status == 'PASS' else '❌'} [{tc_id}] {tc_status} — {assertion_msg}")

    except Exception as exc:
        result["Error_Details"] = str(exc)
        logger.error(f"💥 [{tc_id}] Unexpected error: {exc}")

    return result


# ── Output CSV ────────────────────────────────────────────────────────────────

_csv_lock = threading.Lock()
_header_written = False


def init_security_output():
    """Write the CSV header once, thread-safely."""
    global _header_written
    with _csv_lock:
        if not _header_written:
            cols = SECURITY_META_FIELDS + SECURITY_OUTPUT_EXTRA
            with open(SECURITY_OUTPUT_FILE, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
                writer.writeheader()
            _header_written = True


def write_security_result(result: dict):
    """Append a single test result row to the security output CSV."""
    init_security_output()
    cols = SECURITY_META_FIELDS + SECURITY_OUTPUT_EXTRA
    with _csv_lock:
        with open(SECURITY_OUTPUT_FILE, "a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            writer.writerow(result)


# ── pytest hooks & test (self-contained — no conftest / test file needed) ──────

import sys as _sys  # noqa: E402

import pytest  # noqa: E402

# Ensure the project root is on sys.path so env / sibling modules resolve
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)

# Reload .env from project root (handles running from any cwd)
load_dotenv(os.path.join(_PROJECT_ROOT, env_file), override=False)


def pytest_configure(config):
    """Register the 'security' marker."""
    config.addinivalue_line(
        "markers",
        "security: mark test as part of the OpenSpecimen Security Test Suite",
    )


def pytest_generate_tests(metafunc):
    """Parametrize test_security with one row per security TC from the GSheet."""
    if "tc_row" not in metafunc.fixturenames:
        return

    try:
        cases = load_security_cases()
    except EnvironmentError as env_err:
        # Sheet not configured yet — skip gracefully rather than hard-exit.
        # Fill in SECURITY_GSHEET_URL or SECURITY_GSHEET_GID in .env to enable.
        logger.warning(f"⚠️  Security sheet not configured — skipping: {env_err}")
        metafunc.parametrize("tc_row", [], ids=[])
        return
    except Exception as exc:
        pytest.exit(f"❌ Failed to load security test cases: {exc}")
        return

    if not cases:
        logger.warning("⚠️  No security test cases found in the sheet.")
        return

    metafunc.parametrize(
        "tc_row",
        cases,
        ids=[r.get("TC_ID", f"TC_{i}") for i, r in enumerate(cases)],
    )


@pytest.fixture(scope="session", autouse=True)
def _security_session():
    """Session-scoped setup/teardown: initialise CSV header before any test runs."""
    logger.info("🛡️  Security Test Suite — session started")
    init_security_output()
    yield
    logger.info(f"📊 Security results written to: {SECURITY_OUTPUT_FILE}")


@pytest.mark.security
def test_security(tc_row, record_property):
    """
    Generic security test.
    Each `tc_row` is one row from the 7-column security Google Sheet.
    """
    result = execute_security_tc(tc_row)
    write_security_result(result)

    # Emit extra properties to the HTML / JUnit report
    for field in SECURITY_OUTPUT_EXTRA:
        record_property(field, str(result.get(field, "")))

    # Fail the pytest test if the TC did not pass
    if result["TC_Status"] != "PASS":
        tc_id   = tc_row.get("TC_ID", "?")
        details = result.get("Security_Assertion") or result.get("Error_Details") or "No details"
        pytest.fail(f"[{tc_id}] {details}", pytrace=False)

