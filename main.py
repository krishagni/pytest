import pytest
import os
from dotenv import load_dotenv

# Import the renamed test framework script
import os_test_framework

load_dotenv()

BASE_URL = os.getenv("OS_BASE_URL", "").rstrip("/")
ENABLE_BREAKPOINTS = os.getenv("ENABLE_BREAKPOINTS", "false").lower() == "true"

# Participant Config
PARTICIPANT_API_URL = f"{BASE_URL}/collection-protocol-registrations/"
PARTICIPANT_CSV_URL = os.getenv("GSHEET_CSV_URL")

# Visit Config
VISIT_API_URL = f"{BASE_URL}/visits/"
VISIT_CSV_URL = os.getenv("VISIT_GSHEET_CSV_URL")

# Future resources:
# SPECIMEN_API_URL = f"{BASE_URL}/specimens/"
# SPECIMEN_CSV_URL = os.getenv("SPECIMEN_GSHEET_CSV_URL")


def pytest_generate_tests(metafunc):
    if "tc_row" in metafunc.fixturenames:
        all_cases = []
        
        # We append to all_cases (instead of letting run_tc parametrize immediately)
        all_cases.extend(os_test_framework.run_tc(PARTICIPANT_API_URL, PARTICIPANT_CSV_URL, metafunc))
        all_cases.extend(os_test_framework.run_tc(VISIT_API_URL, VISIT_CSV_URL, metafunc))        
        # Safely parametrize everything at once
        metafunc.parametrize("tc_row", all_cases, ids=[f"{r.get('TC_ID', 'TC')}" for r in all_cases])


@pytest.fixture(scope="session", autouse=True)
def save_combined_results():
    """Trigger generic CSV saving logic after all tests run"""
    yield
    os_test_framework.save_results()


def test_resource(tc_row, record_property):
    """Generic test executing the payload against the dynamic URL"""
    os_test_framework.execute_and_record_test(tc_row, record_property)
