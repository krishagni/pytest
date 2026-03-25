"""
OpenSpecimen Participant API – Automated Test Framework
=======================================================
• Reads test cases from Google Sheet (if GSHEET_ID set in .env) or INPUT_FILE (CSV)
• Supports operations: create
• Deep validation: GET after POST to verify every field was actually stored
• Writes results to OUTPUT_FILE (timestamped CSV)
• pytest-html report with Response_Payload, Latency_ms, deep-diff per TC
• Role-based auth via .env

─── New .env keys needed ────────────────────────────────────────────────────
  GSHEET_ID         = <your Google Sheet ID>          # optional; falls back to CSV
  GSHEET_TAB        = Sheet1                          # tab name, default: Sheet1
  GSHEET_CREDS_JSON = service_account.json            # path to GCP service-account JSON
─────────────────────────────────────────────────────────────────────────────

Run with HTML report:
  pytest test_participants.py -v --html=report.html --self-contained-html
"""

import os, csv, json, pytest, requests, functools
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────

BASE_URL = os.getenv("OS_BASE_URL", os.getenv("BASE_URL", "https://test.openspecimen.org/rest/ng"))
INPUT_FILE = os.getenv("INPUT_FILE", "input_participants.csv")

_env_output = os.getenv("OUTPUT_FILE", "output_results.csv")
_base, _ext = os.path.splitext(_env_output)
OUTPUT_FILE = f"{_base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{_ext}"

# Google Sheets config — all optional; falls back to CSV if GSHEET_ID is absent
GSHEET_ID    = os.getenv("GSHEET_ID", "15Day-53kkDxvtZk2lmLBqWP5T-Hd7cQ0cz4AG3KMctY")
GSHEET_TAB   = os.getenv("GSHEET_TAB", "Sheet1")
GSHEET_CREDS = os.getenv("GSHEET_CREDS_JSON", "service_account.json")

# Column order in output CSV
META_FIELDS  = ["TC_ID", "TC_Description", "Expected_Result", "Role"]
OUTPUT_EXTRA = [
    "TC_Status", "Validation_Status", "Validation_Diff",
    "Error_Received", "HTTP_Status_Code", "Latency_ms", "Response_Payload",
]

# ── Auth ──────────────────────────────────────────────────────────────────────

@functools.lru_cache(maxsize=10)
def get_token(role: str) -> str:
    """Fetch + cache an API token for the given role using .env credentials."""
    key = role.upper()
    login = os.getenv(f"ROLE_{key}_LOGIN_NAME", os.getenv(f"ROLE_{key}_USER", ""))
    pwd   = os.getenv(f"ROLE_{key}_PASSWORD",   os.getenv(f"ROLE_{key}_PASS", ""))
    if not login or not pwd:
        raise ValueError(f"No credentials for role '{role}' in .env")

    creds = {"loginName": login, "password": pwd}
    if domain := os.getenv(f"ROLE_{key}_DOMAIN_NAME", os.getenv(f"ROLE_{key}_DOMAIN", "")):
        creds["domainName"] = domain

    resp = requests.post(f"{BASE_URL}/sessions", json=creds, timeout=10)
    resp.raise_for_status()
    return resp.json()["token"]

# ── Input loading ─────────────────────────────────────────────────────────────

def _load_from_gsheet() -> list[dict]:
    """
    Pull rows from a public Google Sheet using pandas (Option 2).
    Skips rows where the 'Enabled' column is No / FALSE / 0 / empty.
    Requires: pip install pandas
    """
    try:
        import pandas as pd
    except ImportError:
        raise ImportError(
            "GSheet support via public link needs pandas:\n"
            "  pip install pandas"
        )

    # Use GSHEET_ID from .env, or fallback to the hardcoded ID provided
    sheet_id = GSHEET_ID or "15Day-53kkDxvtZk2lmLBqWP5T-Hd7cQ0cz4AG3KMctY"
    csv_url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv"
    
    df = pd.read_csv(csv_url)
    # Pandas natively uses NaN for empty cells; replace with empty strings
    # so the rest of the framework handles them correctly like gspread/CSV does.
    df = df.fillna("")
    
    rows = df.to_dict(orient="records")

    # Honour the optional "Enabled" column so sheet authors can skip TCs
    return [
        r for r in rows
        if str(r.get("Enabled", "yes")).strip().lower() not in ("no", "false", "0", "")
    ]


def load_test_cases() -> list[dict]:
    """Return test-case rows from GSheet (if configured) or CSV."""
    if GSHEET_ID:
        print(f"\n📊  Loading TCs from Google Sheet '{GSHEET_TAB}' (id={GSHEET_ID})")
        rows = _load_from_gsheet()
        # GSheet numbers can come back as int/float — stringify everything so the
        # rest of the framework (which always calls .strip()) never breaks.
        return [{k: str(v) for k, v in r.items()} for r in rows]

    print(f"\n📄  Loading TCs from CSV: {INPUT_FILE}")
    with open(INPUT_FILE, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

# ── Payload builder ───────────────────────────────────────────────────────────

def row_to_payload(row: dict) -> dict:
    val = lambda k: row.get(k, "").strip()

    pmis_dict, races, ethns = {}, [], []
    for k, v in row.items():
        v = v.strip() if isinstance(v, str) else str(v) if v else ""
        if not k or not v:
            continue

        if k.startswith("PMI#") and k.count("#") == 2:
            _, idx, field = k.split("#")
            pmi = pmis_dict.setdefault(idx, {"siteName": "", "mrn": ""})
            pmi["siteName" if field == "Site Name" else "mrn"] = v
        elif k.startswith("Race#"):
            races.append(v)
        elif k.startswith("Ethnicity#"):
            ethns.append(v)

    return {
        "cpShortTitle":      val("CP Short Title"),
        "ppid":              val("PPID"),
        "registrationDate":  val("Registration Date"),
        "site":              val("Registration Site"),
        "externalSubjectId": val("External Subject ID"),
        "activityStatus":    val("Activity Status") or "Active",
        "participant": {
            "firstName":    val("First Name"),
            "lastName":     val("Last Name"),
            "middleName":   val("Middle Name"),
            "emailAddress": val("Email Address"),
            "phoneNumber":  val("Phone Number"),
            "dob":          val("Date Of Birth"),
            "deathDate":    val("Death Date"),
            "gender":       val("Gender"),
            "races":        races,
            "ethnicities":  ethns,
            "vitalStatus":  val("Vital Status"),
            "nationalId":   val("National ID"),
            "empi":         val("eMPI"),
            "pmis":         [p for p in pmis_dict.values() if p["siteName"] or p["mrn"]],
        },
    }

# ── Deep validation ───────────────────────────────────────────────────────────

# Maps CSV column → (top-level key in GET response, nested key or None)
# Only fields listed here are compared; everything else is ignored.
_FIELD_MAP = {
    "PPID":               ("ppid",             None),
    "Registration Date":  ("registrationDate", None),
    "Registration Site":  ("site",             None),
    "External Subject ID":("externalSubjectId",None),
    "Activity Status":    ("activityStatus",   None),
    "First Name":         ("participant",      "firstName"),
    "Last Name":          ("participant",      "lastName"),
    "Middle Name":        ("participant",      "middleName"),
    "Email Address":      ("participant",      "emailAddress"),
    "Phone Number":       ("participant",      "phoneNumber"),
    "Date Of Birth":      ("participant",      "dob"),
    "Death Date":         ("participant",      "deathDate"),
    "Gender":             ("participant",      "gender"),
    "Vital Status":       ("participant",      "vitalStatus"),
    "National ID":        ("participant",      "nationalId"),
    "eMPI":               ("participant",      "empi"),
}

def _norm(v) -> str:
    """Lowercase + strip for case-insensitive field comparison."""
    return str(v).strip().lower() if v is not None else ""


def deep_validate(cpr_id: int, row: dict, headers: dict) -> tuple[str, str]:
    """
    GET /collection-protocol-registrations/{id} and compare every
    provided input field against what was actually stored.

    Returns
    -------
    status : "Pass" | "Fail" | "Error"
    diff   : human-readable list of mismatches (empty when Pass)
    """
    try:
        resp = requests.get(
            f"{BASE_URL}/collection-protocol-registrations/{cpr_id}",
            headers=headers, timeout=15
        )
        if not resp.ok:
            return "Fail", f"GET returned HTTP {resp.status_code}: {resp.text[:200]}"

        data = resp.json()
        diffs: list[str] = []

        # ── Scalar fields ─────────────────────────────────────────────────────
        for csv_col, (top_key, nested_key) in _FIELD_MAP.items():
            expected = _norm(row.get(csv_col, ""))
            if not expected:
                continue  # field wasn't in this TC — skip

            if nested_key is None:
                actual_raw = data.get(top_key)
            else:
                actual_raw = (data.get(top_key) or {}).get(nested_key)

            # Convert OpenSpecimen millisecond timestamps back to YYYY-MM-DD strings
            # if csv_col in ("Registration Date", "Date Of Birth", "Death Date") and isinstance(actual_raw, (int, float)):
            #     import datetime as dt_module
            #     try:
            #         actual_raw = datetime.fromtimestamp(actual_raw / 1000, dt_module.UTC).strftime('%Y-%m-%d')
            #     except Exception:
            #         pass

            actual = _norm(actual_raw)
            if expected != actual:
                diffs.append(f"{csv_col}: expected='{expected}' | actual='{actual}'")

        # ── MRNs (set comparison — order doesn't matter) ──────────────────────
        input_mrns = {
            _norm(v)
            for k, v in row.items()
            if k.startswith("PMI#") and k.count("#") == 2 and k.split("#")[2] == "mrn" and (v or "").strip()
        }
        if input_mrns:
            stored_mrns = {
                _norm(p.get("mrn", ""))
                for p in (data.get("participant") or {}).get("pmis", [])
            }
            missing = input_mrns - stored_mrns
            if missing:
                diffs.append(f"MRNs missing from stored record: {sorted(missing)}")

        # ── Races (set comparison) ────────────────────────────────────────────
        input_races = {
            _norm(v)
            for k, v in row.items()
            if k.startswith("Race#") and (v or "").strip()
        }
        if input_races:
            stored_races = {
                _norm(r)
                for r in (data.get("participant") or {}).get("races", [])
            }
            missing_races = input_races - stored_races
            if missing_races:
                diffs.append(f"Races missing from stored record: {sorted(missing_races)}")

        # ── Ethnicities (set comparison) ──────────────────────────────────────
        input_ethns = {
            _norm(v)
            for k, v in row.items()
            if k.startswith("Ethnicity#") and (v or "").strip()
        }
        if input_ethns:
            stored_ethns = {
                _norm(e)
                for e in (data.get("participant") or {}).get("ethnicities", [])
            }
            missing_ethns = input_ethns - stored_ethns
            if missing_ethns:
                diffs.append(f"Ethnicities missing from stored record: {sorted(missing_ethns)}")

        if diffs:
            return "Fail", " | ".join(diffs)
        return "Pass", ""

    except Exception as exc:
        return "Error", f"Exception during deep validation: {exc}"

# ── Test execution ────────────────────────────────────────────────────────────

def execute_tc(row: dict) -> dict:
    result = dict(
        row,
        TC_Status="FAIL",
        Validation_Status="",
        Validation_Diff="",
        Error_Received="",
        HTTP_Status_Code="",
        Latency_ms="",
        Response_Payload="",
    )
    try:
        operation = row.get("Operation", "").strip().lower()
        if operation != "create":
            raise ValueError(f"Unknown operation: '{operation}'")

        token = get_token(row.get("Role", "admin").strip())
        headers = {"X-OS-API-TOKEN": token, "Content-Type": "application/json"}

        # ── POST ──────────────────────────────────────────────────────────────
        t0 = datetime.now()
        resp = requests.post(
            f"{BASE_URL}/collection-protocol-registrations/",
            headers=headers,
            json=row_to_payload(row),
            timeout=15,
        )
        result["Latency_ms"]     = int((datetime.now() - t0).total_seconds() * 1000)
        result["HTTP_Status_Code"] = resp.status_code

        # Truncate + store the raw response so reviewers can see what came back
        try:
            payload_str = json.dumps(resp.json())
        except Exception:
            payload_str = resp.text
        result["Response_Payload"] = payload_str[:600] + ("…" if len(payload_str) > 600 else "")

        pass_expected    = row.get("Expected_Result", "").strip().lower() in ("pass", "p", "success")
        expected_err_code = row.get("Expected_Error_Code", "").strip()  # optional column

        # ── Positive TC ───────────────────────────────────────────────────────
        if pass_expected:
            if resp.ok:
                result["TC_Status"] = "PASS"

                # Deep validation — compare every input field against stored data
                cpr_id = resp.json().get("id")
                if cpr_id:
                    dv_status, dv_diff = deep_validate(cpr_id, row, headers)
                    result["Validation_Status"] = dv_status
                    result["Validation_Diff"]   = dv_diff
                    # Promote to FAIL so the test is marked red in the report
                    if dv_status != "Pass":
                        result["TC_Status"] = "FAIL"
                else:
                    result["Validation_Status"] = "SKIPPED – no id in POST response"
            else:
                result["TC_Status"] = "FAIL"
                try:
                    err = resp.json()
                    result["Error_Received"] = err.get("message", err.get("code", resp.text[:300]))
                except Exception:
                    result["Error_Received"] = resp.text[:300]

        # ── Negative TC ───────────────────────────────────────────────────────
        else:
            if not resp.ok:
                result["TC_Status"] = "PASS"
                try:
                    err_body = resp.json()
                    actual_code = err_body.get("code", "")
                    result["Error_Received"] = actual_code or resp.text[:200]

                    # If sheet specifies Expected_Error_Code, validate it matches
                    if expected_err_code and _norm(actual_code) != _norm(expected_err_code):
                        result["TC_Status"] = "FAIL"
                        result["Error_Received"] = (
                            f"Wrong error code — "
                            f"expected='{expected_err_code}' actual='{actual_code}'"
                        )
                except Exception:
                    result["Error_Received"] = resp.text[:200]
            else:
                result["TC_Status"] = "FAIL"
                result["Error_Received"] = "Expected failure but API succeeded (HTTP 2xx)"

    except ValueError as exc:
        result["TC_Status"]    = "SKIP"
        result["Error_Received"] = str(exc)
    except Exception as exc:
        result["Error_Received"] = f"Unexpected error: {exc}"

    return result

# ── Session-level CSV writer ──────────────────────────────────────────────────

_results: list[dict] = []


@pytest.fixture(scope="session", autouse=True)
def write_results_after_suite():
    yield  # all tests run here

    if not _results:
        return

    base_keys   = list(_results[0].keys())
    output_cols = (
        [c for c in META_FIELDS  if c in base_keys] +
        [c for c in base_keys    if c not in META_FIELDS and c not in OUTPUT_EXTRA] +
        [c for c in OUTPUT_EXTRA if c in base_keys]
    )

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=output_cols, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(_results)

    print(f"\n✅  Results written → {OUTPUT_FILE}")

# ── Parametrize from whichever source is active ───────────────────────────────

_test_cases: list[dict] | None = None


def pytest_generate_tests(metafunc):
    global _test_cases
    if "tc_row" in metafunc.fixturenames:
        if _test_cases is None:
            _test_cases = load_test_cases()
        metafunc.parametrize(
            "tc_row",
            _test_cases,
            ids=[r.get("TC_ID", f"tc_{i}") for i, r in enumerate(_test_cases)],
        )

# ── Test function ─────────────────────────────────────────────────────────────

def test_participant(tc_row, record_property):
    """
    One pytest test per row. record_property attaches rich metadata to
    each row inside the pytest-html report.
    """
    result = execute_tc(tc_row)
    _results.append(result)

    # ── Attach columns to pytest-html report ──────────────────────────────────
    record_property("TC_ID",           tc_row.get("TC_ID", ""))
    record_property("Description",     tc_row.get("TC_Description", ""))
    record_property("HTTP_Status",     str(result.get("HTTP_Status_Code", "")))
    record_property("Latency_ms",      str(result.get("Latency_ms", "")))
    record_property("Validation_Status", result.get("Validation_Status", ""))
    record_property("Validation_Diff",   result.get("Validation_Diff", ""))
    record_property("Error_Received",  result.get("Error_Received", ""))
    record_property("Response_Payload",result.get("Response_Payload", ""))

    # ── Drive pytest pass / fail / skip ──────────────────────────────────────
    if result.get("TC_Status") == "SKIP":
        pytest.skip(result.get("Error_Received", "Skipped"))

    if result["TC_Status"] not in ("PASS",):
        deep_info = (
            f" | Validation diff: {result['Validation_Diff']}"
            if result.get("Validation_Diff") else ""
        )
        pytest.fail(
            f"[{tc_row.get('TC_ID')}] {result.get('Error_Received', '')} "
            f"| HTTP {result.get('HTTP_Status_Code')}"
            f"{deep_info}",
            pytrace=False,
        )