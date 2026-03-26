import os, csv, json, pytest, requests, functools, io
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
BASE_URL            = os.getenv("OS_BASE_URL")
GSHEET_CSV_URL      = os.getenv("GSHEET_CSV_URL")
INPUT_FILE          = os.getenv("INPUT_FILE", "input_participants.csv")
SAVE_SNAPSHOT       = os.getenv("SAVE_INPUT_SNAPSHOT", "false").lower() == "true"
SNAPSHOT_DIR        = os.getenv("SNAPSHOT_DIR", "input_snapshots")

_env_output         = os.getenv("OUTPUT_FILE", "output_results.csv")
_base, _ext         = os.path.splitext(_env_output)
OUTPUT_FILE         = f"{_base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{_ext}"

META_FIELDS  = json.loads(os.environ["META_FIELDS"])
OUTPUT_EXTRA = json.loads(os.environ["OUTPUT_EXTRA"])

# ── Auth ──────────────────────────────────────────────────────────────────────

@functools.lru_cache(maxsize=10)
def get_token(role: str) -> str:
    key = role.upper().strip()
    login  = os.getenv(f"ROLE_{key}_LOGIN_NAME") or os.getenv(f"ROLE_{key}_USER")
    pwd    = os.getenv(f"ROLE_{key}_PASSWORD")   or os.getenv(f"ROLE_{key}_PASS")
    domain = os.getenv(f"ROLE_{key}_DOMAIN_NAME") or os.getenv(f"ROLE_{key}_DOMAIN")

    if not login or not pwd:
        raise ValueError(f"Credentials missing for role '{role}' in .env")

    creds = {"loginName": login, "password": pwd}
    if domain: creds["domainName"] = domain

    resp = requests.post(f"{BASE_URL}/sessions", json=creds, timeout=10)
    resp.raise_for_status()
    return resp.json()["token"]

# ── Data Loading (Now Saves Locally First) ────────────────────────────────────

def load_test_cases() -> list[dict]:
    """Downloads the GSheet to a local CSV file, then reads it."""
    
    if GSHEET_CSV_URL:
        print(f"\n📡 Downloading data from GSheet...")
        try:
            resp = requests.get(GSHEET_CSV_URL, timeout=30)
            resp.raise_for_status()
            
            # 1. Save the primary input file locally
            with open(INPUT_FILE, "w", encoding="utf-8") as f:
                f.write(resp.text)
            print(f"💾 Saved latest TCs to: {INPUT_FILE}")

            # 2. Handle Snapshots (if enabled in .env)
            if SAVE_SNAPSHOT:
                if not os.path.exists(SNAPSHOT_DIR):
                    os.makedirs(SNAPSHOT_DIR)
                snap_path = os.path.join(SNAPSHOT_DIR, f"input_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
                with open(snap_path, "w", encoding="utf-8") as sf:
                    sf.write(resp.text)
                print(f"📸 Snapshot archived: {snap_path}")

        except Exception as e:
            print(f"⚠️ Download failed ({e}). Attempting to use existing {INPUT_FILE}...")

    # 3. Process the local file
    if not os.path.exists(INPUT_FILE):
        pytest.exit(f"CRITICAL: {INPUT_FILE} not found. Script cannot proceed.")

    with open(INPUT_FILE, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    
    if not rows:
        pytest.exit("No test cases found in input file.")
    return rows

# ── Payload Builder & Smart Casting ──────────────────────────────────────────

def _smart_cast(v: str):
    val = str(v).strip()
    if val.lower() == "true": return True
    if val.lower() == "false": return False
    if val.lower() in ("null", "none"): return None
    try:
        if "." in val: return float(val)
        return int(val)
    except ValueError:
        return val

def row_to_payload(row: dict) -> dict:
    payload = {}
    for k, v in row.items():
        if not k or k in META_FIELDS or k in OUTPUT_EXTRA or v == "":
            continue

        value = _smart_cast(v)
        keys = k.split(".")
        current = payload

        for i, key in enumerate(keys[:-1]):
            next_key = keys[i + 1]
            if next_key.isdigit():
                if key not in current or not isinstance(current[key], list):
                    current[key] = []
                idx = int(next_key)
                
                is_last_key = (i + 1 == len(keys) - 1)
                
                while len(current[key]) <= idx:
                    current[key].append(None if is_last_key else {})
                
                if not is_last_key:
                    current = current[key][idx]
            elif not key.isdigit():
                if key not in current or not isinstance(current[key], dict):
                    current[key] = {}
                current = current[key]

        last_key = keys[-1]
        if last_key.isdigit():
            list_name = keys[-2]
            current[list_name][int(last_key)] = value
        else:
            current[last_key] = value

    if "activityStatus" not in payload:
        payload["activityStatus"] = "Active"
    return payload

# ── Deep Validation ───────────────────────────────────────────────────────────

def _norm(v) -> str:
    return str(v).strip().lower() if v is not None else ""

def _ts_to_date(ms_value) -> str:
    return datetime.fromtimestamp(ms_value / 1000, tz=timezone.utc).strftime("%Y-%m-%d")

def compare_dicts(expected, actual, path="") -> list[str]:
    diffs = []
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{path}: expected dict, got {type(actual).__name__}"]
        for k, v in expected.items():
            diffs.extend(compare_dicts(v, actual.get(k), f"{path}.{k}" if path else k))
    elif isinstance(expected, list):
        if not isinstance(actual, list):
            return [f"{path}: expected list, got {type(actual).__name__}"]
        for i, ev in enumerate(expected):
            found = any(not compare_dicts(ev, av) for av in actual if isinstance(av, dict))
            if not found:
                diffs.append(f"{path}[{i}]: no matching item found in response")
    else:
        actual_norm = _norm(actual)
        if isinstance(actual, (int, float)) and any(x in path.lower() for x in ("date", "dob")):
            try: actual_norm = _norm(_ts_to_date(actual))
            except: pass
        if _norm(expected) != actual_norm:
            diffs.append(f"{path}: expected='{expected}' | actual='{actual}'")
    return diffs

def deep_validate(cpr_id: int, expected_payload: dict, headers: dict) -> tuple[str, str]:
    try:
        resp = requests.get(f"{BASE_URL}/collection-protocol-registrations/{cpr_id}", headers=headers, timeout=15)
        if not resp.ok: return "Fail", f"GET HTTP {resp.status_code}"
        diffs = compare_dicts(expected_payload, resp.json())
        return ("Pass", "") if not diffs else ("Fail", " | ".join(diffs))
    except Exception as exc:
        return "Error", str(exc)

# ── Execution ─────────────────────────────────────────────────────────────────

def execute_tc(row: dict) -> dict:
    result = {**row, "TC_Status": "FAIL", "Validation_Status": "", "Validation_Diff": "", 
              "Error_Received": "", "HTTP_Status_Code": "", "Latency_ms": "", "Response_Payload": ""}
    try:
        role = row.get("Role", "admin").strip()
        token = get_token(role)
        headers = {"X-OS-API-TOKEN": token, "Content-Type": "application/json"}
        payload = row_to_payload(row)

        t0 = datetime.now()
        resp = requests.post(f"{BASE_URL}/collection-protocol-registrations/", headers=headers, json=payload, timeout=15)
        
        result["Latency_ms"] = int((datetime.now() - t0).total_seconds() * 1000)
        result["HTTP_Status_Code"] = resp.status_code
        
        try:
            resp_body = resp.json()
            result["Response_Payload"] = json.dumps(resp_body)
        except:
            resp_body = resp.text
            result["Response_Payload"] = resp_body

        is_positive = row.get("Expected_Result", "").lower() in ("pass", "p", "success")
        
        if is_positive:
            if resp.ok:
                result["TC_Status"] = "PASS"
                cpr_id = resp_body.get("id") if isinstance(resp_body, dict) else None
                if cpr_id:
                    v_stat, v_diff = deep_validate(cpr_id, payload, headers)
                    result["Validation_Status"], result["Validation_Diff"] = v_stat, v_diff
                    if v_stat != "Pass": result["TC_Status"] = "FAIL"
            else:
                result["Error_Received"] = result["Response_Payload"][:500]
        else:
            expected_err = row.get("Expected_Error_Code", "").strip().lower()
            actual_err = str(resp_body.get("code", "")).lower() if isinstance(resp_body, dict) else ""
            if not resp.ok:
                if not expected_err or expected_err in actual_err or expected_err in result["Response_Payload"].lower():
                    result["TC_Status"] = "PASS"
                else:
                    result["Error_Received"] = f"Code mismatch: {actual_err}"
            else:
                result["Error_Received"] = "Expected fail but got HTTP 200"
    except Exception as e:
        result["Error_Received"] = str(e)
    return result

# ── Pytest Hooks ──────────────────────────────────────────────────────────────

_results = []

def pytest_generate_tests(metafunc):
    if "tc_row" in metafunc.fixturenames:
        test_cases = load_test_cases()
        metafunc.parametrize("tc_row", test_cases, ids=[f"{r.get('TC_ID', 'TC')}" for r in test_cases])

@pytest.fixture(scope="session", autouse=True)
def save_results_to_csv():
    yield
    if _results:
        keys = list(_results[0].keys())
        cols = [c for c in META_FIELDS if c in keys] + \
               [c for c in keys if c not in META_FIELDS and c not in OUTPUT_EXTRA] + \
               [c for c in OUTPUT_EXTRA if c in keys]
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(_results)
        print(f"\n✅ Results: {OUTPUT_FILE}")

def test_participant(tc_row, record_property):
    res = execute_tc(tc_row)
    _results.append(res)
    for field in OUTPUT_EXTRA:
        record_property(field, str(res.get(field, "")))
    if res["TC_Status"] != "PASS":
        pytest.fail(f"[{tc_row.get('TC_ID')}] {res.get('Error_Received') or res.get('Validation_Diff')}", pytrace=False) 