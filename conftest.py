import os
import shutil
import pytest
import logging
import allure
import os_test_framework
import security_test_framework
import utilities
from datetime import datetime
from utilities import STATUS_FLD, VALID_STAT_FLD, ERR_FLD, HTTP_CODE_FLD, SEC_ASSERTION_FLD, BASE_URL

logger = logging.getLogger(__name__)

def pytest_addoption(parser):
    parser.addoption(
        "--gid",
        action="store",
        default=None,
        help="Filter and download only the sheet matching this GID or resource name",
    )

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "security: mark test as part of the OpenSpecimen Security Test Suite",
    )

def pytest_sessionstart(session):
    """
    Populate the Allure results dir with environment.properties and
    categories.json. Runs in sessionstart (after all plugins' pytest_configure
    have run) so allure-pytest's --clean-alluredir has already wiped the
    directory before we write into it.
    """
    alluredir = session.config.getoption("--alluredir", default=None)
    if not alluredir:
        return
    os.makedirs(alluredir, exist_ok=True)

    with open(os.path.join(alluredir, "environment.properties"), "w", encoding="utf-8") as f:
        f.write(f"Base_URL={BASE_URL}\n")
        f.write(f"Run_Timestamp={datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    categories_src = os.path.join(os.path.dirname(__file__), "categories.json")
    if os.path.exists(categories_src):
        shutil.copy(categories_src, os.path.join(alluredir, "categories.json"))

def _selected_gdrive_data_needs(session):
    """
    Inspect the already-collected & filtered test items (post -k/-m filtering)
    to determine whether this run actually needs the security tc_data folder
    and/or the query tc_data folder, so we don't pull both full Gdrive
    folders for e.g. a single unrelated test case.
    """
    needs_security = False
    needs_query = False

    for item in session.items:
        if not needs_security and item.get_closest_marker("security"):
            needs_security = True

        if not needs_query:
            callspec = getattr(item, "callspec", None)
            os_tc_key = callspec.params.get("os_tc_row") if callspec else None
            if os_tc_key:
                row = os_test_framework.OS_TC_ROWS.get(os_tc_key, {})
                if str(row.get("File_info", "")).strip():
                    needs_query = True

        if needs_security and needs_query:
            break

    return needs_security, needs_query

@pytest.fixture(scope="session", autouse=True)
def global_session_setup(request):
    """Global setup and teardown for the entire test session."""
    needs_security, needs_query = _selected_gdrive_data_needs(request.session)

    if needs_security:
        utilities.download_tc_data_from_gdrive()
    else:
        logger.info("No security test cases selected -- skipping security tc_data Gdrive download.")

    if needs_query:
        utilities.download_query_tc_data_from_gdrive()
    else:
        logger.info("No selected test cases need query reference files -- skipping query tc_data Gdrive download.")

    yield
    # logger.info("Test Suite -- session ended")
    os_test_framework.cleanup_temp_data()

def pytest_generate_tests(metafunc):
    # ── OS Test Framework Parametrization ──
    # NOTE: we parametrize by a short cache-key string (not the full row dict).
    # allure-pytest auto-captures every parametrize value as a test "parameter";
    # passing the whole dict made that unreadable (huge blob in the report UI).
    # The actual row is looked up from OS_TC_ROWS inside the test.
    if "os_tc_row" in metafunc.fixturenames:
        target_gid = metafunc.config.getoption("--gid")
        all_cases = []
        # get_resources will be defined in main.py or conftest
        from main import get_resources
        for resource in get_resources(gid=target_gid):
             resource_cases = os_test_framework.run_tc(
                 resource["api_url"], resource["csv_url"], metafunc,
                 items_url_template=resource.get("validation_url", "")
             )
             for tc in resource_cases:
                 tc["_resource_name_"] = resource["resource_name"]
             all_cases.extend(resource_cases)
        if all_cases:
            display_ids = [f"{r.get('TC_ID', 'TC')}" for r in all_cases]
            cache_keys = [f"{tc_id}#{i}" for i, tc_id in enumerate(display_ids)]
            for cache_key, row in zip(cache_keys, all_cases):
                os_test_framework.OS_TC_ROWS[cache_key] = row
            metafunc.parametrize("os_tc_row", cache_keys, ids=display_ids)

    # ── Security Test Framework Parametrization ──
    if "sec_tc_row" in metafunc.fixturenames:
        try:
            cases = security_test_framework.load_security_cases()
        except EnvironmentError as env_err:
            logger.warning(f"Security sheet not configured -- skipping: {env_err}")
            metafunc.parametrize("sec_tc_row", [], ids=[])
            cases = None
        except Exception as exc:
            pytest.exit(f"Failed to load security test cases: {exc}")
            cases = None

        if cases is not None:
            if not cases:
                logger.warning("No security test cases found in the sheet.")
                metafunc.parametrize("sec_tc_row", [], ids=[])
            else:
                display_ids = [r.get("TC_ID", f"TC_{i}") for i, r in enumerate(cases)]
                cache_keys = [f"{tc_id}#{i}" for i, tc_id in enumerate(display_ids)]
                for cache_key, row in zip(cache_keys, cases):
                    security_test_framework.SEC_TC_ROWS[cache_key] = row
                metafunc.parametrize("sec_tc_row", cache_keys, ids=display_ids)

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """
    Remove the 'Captured stderr call' and 'Captured log call' 
    sections from the pytest HTML report to reduce noise.
    Also inject test execution data into report details so it 
    remains visible even for passed test cases.
    """
    outcome = yield
    report = outcome.get_result()
    if hasattr(report, "sections"):
        report.sections = [
            section for section in report.sections 
            if section[0] not in ["Captured stderr call", "Captured log call"]
        ]

    if call.when == "call" and hasattr(report, "sections"):
        props = dict(item.user_properties)
        lines = []
        # Standardized error details mapping
        ERR_DETAILS_FLD   = ERR_FLD 
        
        for key in [HTTP_CODE_FLD, SEC_ASSERTION_FLD, VALID_STAT_FLD, ERR_DETAILS_FLD, ERR_FLD]:
            val = props.get(key)
            if val and str(val).strip() and str(val).strip() != "None":
                lines.append(f"{key.replace('_', ' ')}: {val}")
                
        if lines:
            report.sections.append(("Execution Information", "\n".join(lines)))
