import os
import json
import logging
import io
import pandas as pd
import requests
from utilities import logger, BASE_URL

# OpenSpecimen query export CSVs typically contain 3 rows of metadata before the header.
SKIP_ROWS = 3

def validate_export(df_ref: pd.DataFrame, df_export: pd.DataFrame) -> tuple[str, str]:
    """Compares the exported DataFrame to the reference DataFrame."""
    try: 
        
        # Compare schemas (column names)
        if set(df_export.columns) != set(df_ref.columns):
            missing = set(df_ref.columns) - set(df_export.columns)
            extra = set(df_export.columns) - set(df_ref.columns)
            msg = []
            if missing: msg.append(f"Missing cols: {missing}")
            if extra: msg.append(f"Extra cols: {extra}")
            return "FAIL", " | ".join(msg)
            
        # Sort both dataframes to ignore row order completely
        df_export_sorted = df_export.sort_values(by=list(df_export.columns)).reset_index(drop=True)
        df_ref_sorted = df_ref.sort_values(by=list(df_ref.columns)).reset_index(drop=True)
        
        # Check row count
        if len(df_export_sorted) != len(df_ref_sorted):
            return "FAIL", f"Row count mismatch: Expected {len(df_ref_sorted)}, but got {len(df_export_sorted)}"
            
        # Compare data row-by-row (fill NaNs, convert to string, and strip invisible whitespaces)
        df_export_filled = df_export_sorted.fillna("").astype(str).apply(lambda x: x.str.strip() if hasattr(x, 'str') else x)
        df_ref_filled = df_ref_sorted.fillna("").astype(str).apply(lambda x: x.str.strip() if hasattr(x, 'str') else x)
        
        try:
            pd.testing.assert_frame_equal(df_ref_filled, df_export_filled, check_dtype=False)
            return "PASS", ""
        except AssertionError as e:
            err_str = str(e).splitlines()[0] if str(e) else "Data mismatch"
            return "FAIL", f"Data mismatch: {err_str}"
            
    except Exception as e:
        return "ERROR", f"CSV comparison error: {e}"

def execute_query_workflow(tc_id: str, saved_query_id: str, headers: dict, reference_csv_path: str) -> tuple[str, str, dict]:
    """Fetches query results directly and validates against reference CSV."""
    metrics = {"Passed": 0, "Failed": 0, "Warnings": 0}
    try:
        url = f"{BASE_URL}/query/{saved_query_id}"
        logger.info(f"[{tc_id}] Executing query via POST to {url}...")
        
        # Using the specific payload structure required by OpenSpecimen
        payload = {
            "drivingForm": "Participant",
            "joinNodes": [],
            "wideRowMode": "DEEP",
            "startAt": 0,
            "maxResults": 3000
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        
        # Extract JSON rather than expecting a raw CSV string
        data = resp.json()
        
        column_labels = data.get("columnLabels", [])
        rows = data.get("rows", [])
        
        # OpenSpecimen's CSV generator natively replaces "# " with "_" in column headers.
        # Since we are fetching the raw JSON, we replicate that normalization here.
        normalized_labels = [label.replace("# ", "_") for label in column_labels]
        
        # Build pandas DataFrame for the exported data from the JSON response
        df_export = pd.DataFrame(rows, columns=normalized_labels)
        
        # Load reference data from file
        try:
            df_ref = pd.read_csv(reference_csv_path, skiprows=SKIP_ROWS)
        except Exception as e:
            return "FAIL", f"CSV comparison error: Reference file empty or invalid - {e}", metrics
            
        status, message = validate_export(df_ref, df_export)
        
        if status != "PASS":
            metrics["Failed"] += 1
            return "FAIL", message, metrics
            
        metrics["Passed"] += 1
        return "PASS", "Data match", metrics
        
    except requests.exceptions.RequestException as e:
        status_code = getattr(e.response, "status_code", "N/A")
        server_response = getattr(e.response, "text", "")
        return "FAIL", f"API Error (HTTP {status_code}): {e} | Response: {server_response}", metrics
    except json.JSONDecodeError:
        return "FAIL", f"API Error: Expected JSON response but received raw text.", metrics
    except Exception as e:
        return "ERROR", f"Workflow Error: {e}", metrics