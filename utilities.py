import csv
import io
import json
import logging
import os
import shutil
import threading
import functools
import gdown
import functools
from datetime import datetime

import requests
from dotenv import load_dotenv

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Load environment variables
env_file = os.getenv("ENV_FILE", ".env")
load_dotenv(env_file)

# ── Global Config ─────────────────────────────────────────────────────────────
BASE_URL = os.getenv("OS_BASE_URL", "").rstrip("/")
SECURITY_TC_DATA_GDRIVE_FOLDER_ID = os.getenv("SECURITY_TC_DATA_GDRIVE_FOLDER_ID", "")
SECURITY_TC_DATA_DIR = os.getenv("SECURITY_TC_DATA_DIR", "security_tests/tc_data")
QUERY_TC_DATA_GDRIVE_FOLDER_ID = os.getenv("QUERY_TC_DATA_GDRIVE_FOLDER_ID", "")
QUERY_TC_DATA_DIR = os.getenv("QUERY_TC_DATA_DIR", "query_tests/tc_data")

# ── Dynamic Field Definitions ────────────────────────────────────────────────
# Field names are driven by .env to allow easy rename without script changes.
STATUS_FLD      = os.getenv("STATUS_FLD", "TC_Status")
VALID_STAT_FLD  = os.getenv("VALID_STAT_FLD", "Validation_Status")
ERR_FLD         = os.getenv("ERR_FLD", "Error_Received")
HTTP_CODE_FLD   = os.getenv("HTTP_CODE_FLD", "HTTP_Status_Code")
SEC_ASSERTION_FLD = os.getenv("SEC_ASSERTION_FLD", "Security_Assertion")
REFL_INPUT_FLD    = os.getenv("REFL_INPUT_FLD", "Reflected_Input_Found")

# ── Google Drive Download ────────────────────────────────────────────────────
def _download_gdrive_folder(folder_id: str, target_dir: str):
    """Generic function to download a Google Drive folder using gdown."""
    if not folder_id:
        logger.info(f"GDrive folder ID not set for {target_dir} — skipping download.")
        return

    temp_download_dir = f"temp_{os.path.basename(target_dir)}_{folder_id}_download"
    
    if os.path.exists(temp_download_dir):
        shutil.rmtree(temp_download_dir)
        
    try:
        downloaded_paths = gdown.download_folder(id=folder_id, output=temp_download_dir, quiet=True, use_cookies=True)
        
        if not downloaded_paths or not os.path.exists(temp_download_dir):
            raise Exception("Download completed but temp folder not found locally.")

        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
            
        os.makedirs(os.path.dirname(target_dir), exist_ok=True)
        shutil.move(temp_download_dir, target_dir)
        
    except Exception as e:
        logger.error(f"❌ Failed to download from Google Drive ({folder_id}): {e}")
        if os.path.exists(temp_download_dir):
            shutil.rmtree(temp_download_dir)

def download_tc_data_from_gdrive():
    """Downloads the security tc_data folder from Google Drive."""
    _download_gdrive_folder(SECURITY_TC_DATA_GDRIVE_FOLDER_ID, SECURITY_TC_DATA_DIR)

def download_query_tc_data_from_gdrive():
    """Downloads the query tc_data folder from Google Drive."""
    _download_gdrive_folder(QUERY_TC_DATA_GDRIVE_FOLDER_ID, QUERY_TC_DATA_DIR)

# ── Authentication ────────────────────────────────────────────────────────────
_ROLES_CACHE = None
_API_TOKEN_CACHE = {}  # Allow multiple tokens per role or env
_token_lock = threading.Lock()

def load_roles_from_gsheet() -> dict:
    master_id = os.getenv("MASTER_GSHEET_ID")
    roles_gid = os.getenv("ROLES_GSHEET_GID")
    if not master_id or not roles_gid:
        return {}
    url = f"https://docs.google.com/spreadsheets/d/{master_id}/export?format=csv&gid={roles_gid}"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        reader = csv.DictReader(io.StringIO(resp.text))
        roles = {}
        for row in reader:
            r = row.get("Role", "").strip().upper()
            if r:
                roles[r] = {
                    "login": row.get("Login_Name", "").strip(),
                    "password": row.get("Password", "").strip(),
                    "domain": row.get("Domain_Name", "").strip()
                }
        # logger.info(f"🔑 Loaded {len(roles)} roles from GSheet")
        return roles
    except Exception as e:
        logger.warning(f"Failed to load roles from GSheet: {e}")
        return {}

def get_token(role: str = None) -> str:
    """Gets token for a given role from the gsheet, or defaults to .env credentials."""
    global _ROLES_CACHE, _API_TOKEN_CACHE
    
    key = str(role).upper().strip() if role else "ENV_DEFAULT"
    
    with _token_lock:
        if key in _API_TOKEN_CACHE:
            return _API_TOKEN_CACHE[key]

    with _token_lock:
        if _ROLES_CACHE is None:
            _ROLES_CACHE = load_roles_from_gsheet()

    gsheet_role = _ROLES_CACHE.get(key, {})
    
    login = gsheet_role.get("login")
    pwd = gsheet_role.get("password")
    domain = gsheet_role.get("domain")

    # Fallback to pure env variables if role not found
    if not login or not pwd:
        login = os.getenv("OS_LOGIN_NAME", "")
        pwd = os.getenv("OS_PASSWORD", "")
        domain = os.getenv("OS_DOMAIN_NAME", "")

    if not login or not pwd:
        raise ValueError(f"Missing credentials for role '{role}' and no default in .env!")

    creds = {"loginName": login, "password": pwd}
    if domain: creds["domainName"] = domain

    resp = requests.post(f"{BASE_URL}/sessions", json=creds, timeout=10)
    resp.raise_for_status()
    token = resp.json()["token"]
    
    with _token_lock:
        _API_TOKEN_CACHE[key] = token
        
    return token

def get_auth_headers(role: str = None) -> dict:
    """Helper to get standardized headers for API requests."""
    return {"X-OS-API-TOKEN": get_token(role), "Content-Type": "application/json"}



# ── Shared API Revert & Cleanup Helpers ─────────────────────────────────────

def fetch_original_state(url: str, headers: dict) -> dict | None:
    """Fetches the current state of a resource via GET before it is modified."""
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.ok:
            return resp.json()
    except Exception as e:
        logger.warning(f"⚠️ Could not fetch original state at {url}: {e}")
    return None

def cleanup_or_revert_api_resource(operation: str, base_url: str, headers: dict, res_id: str | int = None, original_state: dict = None):
    """
    Common function to clean up created resources or revert updated ones.
    operation: "POST" or "PUT"
    base_url: The URL without the ID (e.g. /rest/ng/participants)
    headers: Request headers
    res_id: The ID of the resource created or updated
    original_state: The original dictionary to revert to for PUT
    """
    if not res_id:
        return

    cleanup_resources = os.getenv("CLEANUP_RESOURCES", "true").lower() == "true"
    revert_updates = os.getenv("REVERT_UPDATES", "true").lower() == "true"
    
    if operation.upper() == "POST" and cleanup_resources:
        try:
            delete_url = f"{str(base_url).rstrip('/')}/{res_id}?forceDelete=true"
            del_resp = requests.delete(delete_url, headers=headers, timeout=15)
            if not del_resp.ok:
                logger.warning(f"⚠️ Failed to cleanup resource at {delete_url}: HTTP {del_resp.status_code} - {del_resp.text}")
        except Exception as e:
            logger.warning(f"⚠️ Exception during resource deletion for {res_id}: {e}")
            
    elif operation.upper() == "PUT" and revert_updates and original_state:
        try:
            update_url = f"{str(base_url).rstrip('/')}/{res_id}"
            rev_resp = requests.put(update_url, headers=headers, json=original_state, timeout=15)
            if not rev_resp.ok:
                logger.warning(f"⚠️ Failed to revert resource {res_id}: HTTP {rev_resp.status_code} - {rev_resp.text}")
        except Exception as e:
            logger.warning(f"⚠️ Exception during resource revert for {res_id}: {e}")
