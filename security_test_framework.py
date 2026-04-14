import csv
import io
import json
import logging
import os
import threading
import time
from datetime import datetime

import requests
from utilities import logger, BASE_URL, get_auth_headers, CSVLogger

# ── Config (all from .env) ────────────────────────────────────────────────────

SECURITY_GSHEET_URL  = os.getenv("SECURITY_GSHEET_URL", "")
SECURITY_TC_DATA_DIR = os.getenv("SECURITY_TC_DATA_DIR", "security_tests/tc_data")

_env_sec_out         = os.getenv("SECURITY_OUTPUT_FILE", "security_output.csv")
_base, _ext          = os.path.splitext(_env_sec_out)
SECURITY_OUTPUT_FILE = f"{_base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{_ext}"

# Output columns for the security results CSV
SECURITY_META_FIELDS  = json.loads(os.environ["SECURITY_META_FIELDS"])
SECURITY_OUTPUT_EXTRA = json.loads(os.environ["SECURITY_OUTPUT_EXTRA"])

# ── Sheet Loader ──────────────────────────────────────────────────────────────

def _resolve_security_url() -> str:
    if SECURITY_GSHEET_URL:
        if "/edit" in SECURITY_GSHEET_URL:
            return SECURITY_GSHEET_URL.split("/edit")[0] + "/export?format=csv"
        return SECURITY_GSHEET_URL
    return ""

def load_security_cases() -> list[dict]:
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
        normalised = {str(k).strip(): (v or "").strip() for k, v in row.items() if k}
        if not normalised.get("TC_ID"):
            continue
        cases.append(normalised)

    logger.info(f"Loaded {len(cases)} security test cases")
    return cases

# ── File Loader (per-TC) ──────────────────────────────────────────────────────

def load_tc_file(tc_id: str, file_info: str, as_bytes: bool = False) -> dict | bytes | None:
    """Load the file, parsing JSON by default unless as_bytes is True."""
    file_info = (file_info or "").strip()
    if not file_info:
        return None

    file_path = os.path.join(SECURITY_TC_DATA_DIR, tc_id, file_info)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"[{tc_id}] File not found: {file_path}")

    _, ext = os.path.splitext(file_info.lower())
    
    if ext == ".json" and not as_bytes:
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
    is_multipart: bool = False
) -> requests.Response:
    
    op      = operation.strip().upper()
    timeout = 20

    if op == "POST" and is_multipart:
        multipart_headers = {k: v for k, v in headers.items() if k != "Content-Type"}
        content = json.dumps(payload) if isinstance(payload, dict) else payload
        
        fname = file_info
        mime = "text/csv" if fname.lower().endswith(".csv") else "application/octet-stream"
        
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
) -> tuple[str, str]:
    expected = str(row.get("Expected_Results", "")).strip().lower()

    if expected == "fail":
        if not response.ok:
            return "PASS", f"Server correctly rejected input (HTTP {response.status_code})"
        msg = f"SECURITY VULNERABILITY: Server accepted malicious input (HTTP {response.status_code}). Response: {response.text}"
        return "FAIL", msg

    if expected == "pass":
        if response.ok:
            return "PASS", f"Legitimate request accepted (HTTP {response.status_code})"
        return "FAIL", f"Legitimate request unexpectedly rejected (HTTP {response.status_code}). Response: {response.text}"

    return "ERROR", f"Unknown Expected_Result value: '{expected}' (use 'pass' or 'fail')"

# ── Test Executor ─────────────────────────────────────────────────────────────

def execute_security_tc(row: dict) -> dict:
    tc_id     = row.get("TC_ID", "UNKNOWN")
    operation = row.get("Operation", "POST")
    endpoint  = row.get("Endpoint", "")
    file_info = row.get("File_info", "")
    
    # Defaults to 'json' if left blank in the sheet
    file_type = row.get("File_type", "json").strip().lower()

    result = {field: row.get(field, "") for field in SECURITY_META_FIELDS}
    for field in SECURITY_OUTPUT_EXTRA:
        result[field] = ""
    result["TC_Status"] = "ERROR"

    try:
        # 1. ALWAYS load payload.json (hardcoded and mandatory for all tests)
        try:
            core_payload = load_tc_file(tc_id, "payload.json")
        except FileNotFoundError:
            core_payload = None
            if operation in ("POST", "PUT") and file_type == "json":
                logger.warning(f"[{tc_id}] payload.json missing for {operation} request.")

        url     = _build_url(endpoint)
        headers = get_auth_headers()

        # 2. Route based strictly on 'csv' or 'json'
        if file_type == "csv":
            # ── Two-step bulk import ────────────────────────────────────────
            file_bytes  = load_tc_file(tc_id, file_info, as_bytes=True)
            upload_resp = _dispatch_request("POST", url, headers, file_bytes, file_info, is_multipart=True)
            
            if not upload_resp.ok:
                 raise Exception(f"CSV Upload failed: {upload_resp.text}")
                 
            file_id     = upload_resp.json().get("fileId")
            logger.info(f"[{tc_id}] CSV Upload → fileId={file_id}")

            # Inject file_id into the mandatory payload.json
            job_str     = json.dumps(core_payload).replace("{file_id}", str(file_id))
            job_payload = json.loads(job_str)
            job_url     = _build_url(endpoint.rsplit("/", 1)[0])
            logger.info(f"[{tc_id}] Creating import job at {job_url}")

            t0       = datetime.now()
            response = _dispatch_request("POST", job_url, headers, job_payload, "payload.json", is_multipart=False)

            if response.ok:
                try:
                    job_data = response.json()
                    job_id = job_data.get("id")
                    if job_id:
                        job_status_url = f"{job_url}/{job_id}"
                        logger.info(f"[{tc_id}] Polling job {job_id} at {job_status_url}...")
                        
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
                        
                        logger.info(f"[{tc_id}] Job {job_id} finished with status: {final_status}")
                        
                        if final_status == "FAILED":
                            response.status_code = 400
                            response._content = json.dumps(job_info).encode("utf-8")
                        elif final_status == "COMPLETED":
                            response.status_code = 200
                            response._content = json.dumps(job_info).encode("utf-8")
                        else:
                            response.status_code = 500
                            response._content = json.dumps({"error": f"Job timeout", **job_info}).encode("utf-8")
                except Exception as e:
                    logger.warning(f"[{tc_id}] Failed to poll job status: {e}")
                    
        elif file_type == "json":
            # ── Default: standard REST request using payload.json ────────────
            logger.info(f"[{tc_id}] JSON STANDARD {operation} -> {url}")
            t0       = datetime.now()
            response = _dispatch_request(operation, url, headers, core_payload, "payload.json", is_multipart=False)
            
        else:
            # ── Fallback: Single-step file upload (e.g., pdf, exe, png) ───────
            attachment = load_tc_file(tc_id, file_info, as_bytes=True)
            logger.info(f"[{tc_id}] UPLOAD {operation} -> {url} (file: {file_info})")
            t0       = datetime.now()
            response = _dispatch_request(operation, url, headers, attachment, file_info, is_multipart=True)

        latency_ms = int((datetime.now() - t0).total_seconds() * 1000)

        result["HTTP_Status_Code"] = response.status_code
        result["Latency_ms"]       = latency_ms

        tc_status, assertion_msg = assert_security(row, response, core_payload)
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

_sec_logger = CSVLogger(SECURITY_OUTPUT_FILE, SECURITY_META_FIELDS + SECURITY_OUTPUT_EXTRA)

def write_security_result(result: dict):
    _sec_logger.write_row(result)

def execute_and_record_security_test(row: dict, record_property):
    """Refactored helper to execute, log, and fail security tests."""
    import pytest
    result = execute_security_tc(row)
    write_security_result(result)

    for field in SECURITY_OUTPUT_EXTRA:
        record_property(field, str(result.get(field, "")))

    if result["TC_Status"] != "PASS":
        tc_id   = row.get("TC_ID", "?")
        details = result.get("Security_Assertion") or result.get("Error_Details") or "No details"
        pytest.fail(f"[{tc_id}] {details}", pytrace=False)