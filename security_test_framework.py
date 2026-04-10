
import csv
import io
import json
import logging
import os
import threading
import time
from datetime import datetime

import requests
from dotenv import load_dotenv

# ── Bootstrap ─────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)

env_file = os.getenv("ENV_FILE", ".env")
load_dotenv(env_file)

# ── Config (all from .env) ────────────────────────────────────────────────────

BASE_URL             = os.getenv("OS_BASE_URL", "").rstrip("/")
SECURITY_GSHEET_URL  = os.getenv("SECURITY_GSHEET_URL", "")
SECURITY_TC_DATA_DIR = os.getenv("SECURITY_TC_DATA_DIR", "security_tests/tc_data")


_env_sec_out         = os.getenv("SECURITY_OUTPUT_FILE", "security_output.csv")
_base, _ext          = os.path.splitext(_env_sec_out)
SECURITY_OUTPUT_FILE = f"{_base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{_ext}"

# Output columns for the security results CSV
SECURITY_META_FIELDS  = json.loads(os.environ["SECURITY_META_FIELDS"])
SECURITY_OUTPUT_EXTRA = json.loads(os.environ["SECURITY_OUTPUT_EXTRA"])

# ── Auth ──────────────────────────────────────────────────────────────────────

OS_LOGIN_NAME  = os.getenv("OS_LOGIN_NAME", "")
OS_PASSWORD    = os.getenv("OS_PASSWORD", "")
OS_DOMAIN_NAME = os.getenv("OS_DOMAIN_NAME", "")

_API_TOKEN   = None
_token_lock  = threading.Lock()


def get_auth_headers() -> dict:
    global _API_TOKEN
    with _token_lock:
        if _API_TOKEN is not None:
            return {"X-OS-API-TOKEN": _API_TOKEN, "Content-Type": "application/json"}

    if not OS_LOGIN_NAME or not OS_PASSWORD:
        raise ValueError("Missing OS_LOGIN_NAME or OS_PASSWORD in .env!")

    body = {"loginName": OS_LOGIN_NAME, "password": OS_PASSWORD}
    if OS_DOMAIN_NAME:
        body["domainName"] = OS_DOMAIN_NAME

    resp = requests.post(f"{BASE_URL}/sessions", json=body, timeout=10)
    resp.raise_for_status()
    _API_TOKEN = resp.json()["token"]

    return {"X-OS-API-TOKEN": _API_TOKEN, "Content-Type": "application/json"}

# ── Sheet Loader ──────────────────────────────────────────────────────────────

def _resolve_security_url() -> str:
    if SECURITY_GSHEET_URL:
        # Convert web UI links to CSV export links automatically
        if "/edit" in SECURITY_GSHEET_URL:
            return SECURITY_GSHEET_URL.split("/edit")[0] + "/export?format=csv"
        return SECURITY_GSHEET_URL
    return ""



def load_security_cases() -> list[dict]:
    """
    Download and parse the 8-column security GSheet.
    Returns a list of row dicts with normalised keys.
    """
    url = _resolve_security_url()
    if not url:
        raise EnvironmentError(
            "No security sheet configured. Set SECURITY_GSHEET_URL in .env"
        )


    logger.info(f"Downloading security sheet from: {url}")
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()

    resp.encoding = "utf-8-sig"
    reader = csv.DictReader(io.StringIO(resp.text))
    cases = []
    for row in reader:
        # normalise keys (strip whitespace, just in case)
        normalised = {str(k).strip(): (v or "").strip() for k, v in row.items() if k}
        if not normalised.get("TC_ID"):
            continue
        cases.append(normalised)

    logger.info(f"Loaded {len(cases)} security test cases")
    return cases


# ── File Loader (per-TC) ──────────────────────────────────────────────────────

def load_tc_file(tc_id: str, file_info: str) -> dict | bytes | None:
    """
    Load the payload file for a TC from its dedicated folder.
    """
    file_info = (file_info or "").strip()
    if not file_info:
        return None

    file_path = os.path.join(SECURITY_TC_DATA_DIR, tc_id, file_info)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"[{tc_id}] File not found: {file_path}")

    _, ext = os.path.splitext(file_info.lower())
    if ext == ".json":
        if "workflow.json" in file_info.lower():
            with open(file_path, "rb") as fh:
                return fh.read()
        with open(file_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    
    with open(file_path, "rb") as fh:
        return fh.read()


# ── Request Builder ───────────────────────────────────────────────────────────

def _build_url(endpoint: str) -> str:
    endpoint = endpoint.strip()
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    return f"{BASE_URL}/{endpoint.lstrip('/')}"


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
      - dict  : sent as JSON for POST / PUT
      - bytes : sent as multipart file upload (bulk-import CSV)
      - None  : no body (GET / DELETE)
    """
    op      = operation.strip().upper()
    timeout = 20

    # Simplified trigger: strictly workflow.json or .csv files
    is_multipart = ("workflow.json" in file_info.lower() or file_info.lower().endswith(".csv"))

    if op == "POST" and is_multipart:
        multipart_headers = {k: v for k, v in headers.items() if k != "Content-Type"}
        content = json.dumps(payload) if isinstance(payload, dict) else payload
        
        # Use the actual filename from File_info (no more hardcoding "upload.json")
        fname = file_info
        mime = "text/csv" if fname.lower().endswith(".csv") else "application/json"
        
        # Standard OpenSpecimen part name is 'file'
        files = {"file": (fname, content, mime)}
        logger.info(f"Using SMART-MULTIPART (mime:{mime}) for {fname} to {url}")
        return requests.post(url, headers=multipart_headers, files=files, timeout=timeout)

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
def assert_security(
    row: dict,
    response: requests.Response,
    payload,
) -> tuple[str, str]: # ("PASS/FAIL/ERROR", "message") 
    """
    Evaluate the security test result.

    Returns:
        (TC_Status, Security_Assertion_message)
    """
    expected = str(row.get("Expected_Results", "")).strip().lower()

    if expected == "fail":
        if not response.ok:
            return (
                "PASS",
                f"Server correctly rejected input (HTTP {response.status_code})",
            )
        msg = f"SECURITY VULNERABILITY: Server accepted malicious input (HTTP {response.status_code}). Response: {response.text}"
        return "FAIL", msg

    if expected == "pass":
        if response.ok:
            return "PASS", f"Legitimate request accepted (HTTP {response.status_code})"
        return (
            "FAIL",
            f"Legitimate request unexpectedly rejected (HTTP {response.status_code}). Response: {response.text}",
        )

    return (
        "ERROR",
        f"Unknown Expected_Result value: '{expected}' (use 'pass' or 'fail')",
    )


# ── Test Executor ─────────────────────────────────────────────────────────────

def execute_security_tc(row: dict) -> dict:
    """Run a single security test case row and return the full result dict."""
    tc_id     = row.get("TC_ID", "UNKNOWN")
    operation = row.get("Operation", "POST")
    endpoint  = row.get("Endpoint", "")
    file_info = row.get("File_info", "")

    result = {field: row.get(field, "") for field in SECURITY_META_FIELDS}
    for field in SECURITY_OUTPUT_EXTRA:
        result[field] = ""
    result["TC_Status"] = "ERROR"

    try:
        payload = load_tc_file(tc_id, file_info)

        url     = _build_url(endpoint)
        headers = get_auth_headers()

        if file_info.lower().endswith(".csv"):
            # ── Two-step bulk import ────────────────────────────────────────
            # Step 1: Upload the CSV file, extract fileId from response
            file_bytes  = load_tc_file(tc_id, file_info)
            upload_resp = _dispatch_request("POST", url, headers, file_bytes, file_info)
            file_id     = upload_resp.json().get("fileId")
            logger.info(f"[{tc_id}] CSV upload → fileId={file_id}")

            # Step 2: POST job payload to parent endpoint (strip last segment)
            payload    = load_tc_file(tc_id, "payload.json")
            job_str    = json.dumps(payload).replace("{file_id}", str(file_id))
            payload    = json.loads(job_str)
            job_url    = _build_url(endpoint.rsplit("/", 1)[0])
            logger.info(f"[{tc_id}] Creating import job at {job_url}")

            t0       = datetime.now()
            response = _dispatch_request("POST", job_url, headers, payload, "payload.json")

            if response.ok:
                try:
                    job_data = response.json()
                    job_id = job_data.get("id")
                    if job_id:
                        job_status_url = f"{BASE_URL}/import-jobs/{job_id}"
                        logger.info(f"[{tc_id}] Polling import job {job_id} at {job_status_url}...")
                        
                        timeout = 60
                        start_time = time.time()
                        final_status = "UNKNOWN"
                        job_info = {}
                        
                        while time.time() - start_time < timeout:
                            status_resp = requests.get(job_status_url, headers=headers, timeout=10)
                            if status_resp.ok:
                                job_info = status_resp.json()
                                status = job_info.get("status")
                                if status in ("COMPLETED", "FAILED", "STOPPED"):
                                    final_status = status
                                    break
                            time.sleep(2)
                        
                        logger.info(f"[{tc_id}] Import job {job_id} finished with status: {final_status}")
                        
                        # Adjust response so assert_security works correctly
                        if final_status == "FAILED":
                            response.status_code = 400
                            response._content = json.dumps(job_info).encode("utf-8")
                        elif final_status == "COMPLETED":
                            response.status_code = 200
                            response._content = json.dumps(job_info).encode("utf-8")
                        else:
                            response.status_code = 500
                            response._content = json.dumps({"error": f"Job status {final_status} timeout", **job_info}).encode("utf-8")
                except Exception as e:
                    logger.warning(f"[{tc_id}] Failed to poll job status: {e}")
        else:
            # ── Default: single-step ────────────────────────────────────────
            payload  = load_tc_file(tc_id, file_info)
            logger.info(f"[{tc_id}] {operation} -> {url}  (file: {file_info or 'none'})")
            t0       = datetime.now()
            response = _dispatch_request(operation, url, headers, payload, file_info)

        latency_ms = int((datetime.now() - t0).total_seconds() * 1000)

        result["HTTP_Status_Code"] = response.status_code
        result["Latency_ms"]       = latency_ms

        tc_status, assertion_msg = assert_security(row, response, payload)
        result["TC_Status"]             = tc_status
        result["Security_Assertion"]    = assertion_msg

        if tc_status == "FAIL":
            try:
                body_snippet = json.dumps(response.json())[:300]
            except Exception:
                body_snippet = (response.text or "")[:300]
            result["Error_Details"] = body_snippet

        logger.info(f"[{tc_id}] {tc_status} -- {assertion_msg}")

    except FileNotFoundError as fnf:
        result["Error_Details"] = str(fnf)
        logger.error(f"[{tc_id}] File not found: {fnf}")

    except Exception as exc:
        result["Error_Details"] = str(exc)
        logger.error(f"[{tc_id}] Unexpected error: {exc}")

    return result


# ── Output CSV ────────────────────────────────────────────────────────────────

_csv_lock       = threading.Lock()
_header_written = False


def init_security_output():
    """Write the CSV header once, thread-safely."""
    global _header_written
    with _csv_lock:
        if _header_written:
            return
        cols = SECURITY_META_FIELDS + SECURITY_OUTPUT_EXTRA
        with open(SECURITY_OUTPUT_FILE, "w", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore").writeheader()
        _header_written = True


def write_security_result(result: dict):
    """Append a single test result row to the security output CSV."""
    init_security_output()
    cols = SECURITY_META_FIELDS + SECURITY_OUTPUT_EXTRA
    with _csv_lock:
        with open(SECURITY_OUTPUT_FILE, "a", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore").writerow(result)


# ── pytest hooks & test ───────────────────────────────────────────────────────

import pytest  # noqa: E402


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
        logger.warning(f"Security sheet not configured -- skipping: {env_err}")
        metafunc.parametrize("tc_row", [], ids=[])
        return
    except Exception as exc:
        pytest.exit(f"Failed to load security test cases: {exc}")
        return

    if not cases:
        logger.warning("No security test cases found in the sheet.")
        metafunc.parametrize("tc_row", [], ids=[])
        return

    metafunc.parametrize(
        "tc_row",
        cases,
        ids=[r.get("TC_ID", f"TC_{i}") for i, r in enumerate(cases)],
    )


@pytest.fixture(scope="session", autouse=True)
def _security_session():
    """Session-scoped setup: initialise CSV header before any test runs."""
    logger.info("Security Test Suite -- session started")
    init_security_output()
    yield
    logger.info(f"Security results written to: {SECURITY_OUTPUT_FILE}")


@pytest.mark.security
def test_security(tc_row, record_property): # runs once per test case 
    """
    Generic security test.
    Each `tc_row` is one row from the 8-column security Google Sheet.
    """
    result = execute_security_tc(tc_row)
    write_security_result(result)

    for field in SECURITY_OUTPUT_EXTRA:
        record_property(field, str(result.get(field, "")))

    if result["TC_Status"] != "PASS":
        tc_id   = tc_row.get("TC_ID", "?")
        details = result.get("Security_Assertion") or result.get("Error_Details") or "No details"
        pytest.fail(f"[{tc_id}] {details}", pytrace=False)