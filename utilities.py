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

# ── Dynamic Field Definitions ────────────────────────────────────────────────
# Field names are driven by .env to allow easy rename without script changes.
STATUS_FLD      = os.getenv("STATUS_FLD", "TC_Status")
VALID_STAT_FLD  = os.getenv("VALID_STAT_FLD", "Validation_Status")
ERR_FLD         = os.getenv("ERR_FLD", "Error_Received")
HTTP_CODE_FLD   = os.getenv("HTTP_CODE_FLD", "HTTP_Status_Code")
SEC_ASSERTION_FLD = os.getenv("SEC_ASSERTION_FLD", "Security_Assertion")
REFL_INPUT_FLD    = os.getenv("REFL_INPUT_FLD", "Reflected_Input_Found")

# ── Google Drive Download ────────────────────────────────────────────────────
def download_tc_data_from_gdrive():
    """Downloads the tc_data folder from Google Drive using gdown."""
    folder_id = SECURITY_TC_DATA_GDRIVE_FOLDER_ID
    if not folder_id:
        logger.info("SECURITY_TC_DATA_GDRIVE_FOLDER_ID not set — skipping Drive download and using local folder.")
        return

    # logger.info(f"Downloading tc_data folder from Google Drive (ID: {folder_id})...")
    
    # We download to a temporary folder name first
    temp_download_dir = "temp_tc_data_download"
    
    # Clean up previous temp dir if it exists
    if os.path.exists(temp_download_dir):
        shutil.rmtree(temp_download_dir)
        
    try:
        # gdown downloads the folder. Format required is a folder URL
        folder_url = f"https://drive.google.com/drive/folders/{folder_id}"
        
        # Download the folder directly into the temp directory
        downloaded_paths = gdown.download_folder(id=folder_id, output=temp_download_dir, quiet=True, use_cookies=True)
        
        if not downloaded_paths or not os.path.exists(temp_download_dir):
            raise Exception("Download completed but temp folder not found locally.")

        # Clean up existing old tc_data dir
        if os.path.exists(SECURITY_TC_DATA_DIR):
            # logger.info(f"Removing old local directory: {SECURITY_TC_DATA_DIR}")
            shutil.rmtree(SECURITY_TC_DATA_DIR)
            
        # Ensure parent directories exist
        os.makedirs(os.path.dirname(SECURITY_TC_DATA_DIR), exist_ok=True)

        # Move the downloaded folder to the target directory
        shutil.move(temp_download_dir, SECURITY_TC_DATA_DIR)
        
        # logger.info(f"✅ tc_data successfully downloaded and placed at {SECURITY_TC_DATA_DIR}")

    except Exception as e:
        logger.error(f"❌ Failed to download from Google Drive: {e}")
        # logger.warning(f"Falling back to existing local folder if present: {SECURITY_TC_DATA_DIR}")
        if os.path.exists(temp_download_dir):
            shutil.rmtree(temp_download_dir)

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

# ── CSV Logging helper ────────────────────────────────────────────────────────
class CSVLogger:
    def __init__(self, filename: str, headers: list):
        self.filename = filename
        self.headers = headers
        self.lock = threading.Lock()
        self.initialized = False
        
    def init_file(self):
        with self.lock:
            if not self.initialized:
                with open(self.filename, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=self.headers, extrasaction="ignore")
                    writer.writeheader()
                self.initialized = True
                
    def write_row(self, row: dict):
        if not self.initialized:
            self.init_file()
        with self.lock:
            with open(self.filename, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.headers, extrasaction="ignore")
                writer.writerow(row)

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
