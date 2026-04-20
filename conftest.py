import pytest
import logging
import os_test_framework
import security_test_framework
import utilities

logger = logging.getLogger(__name__)

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "security: mark test as part of the OpenSpecimen Security Test Suite",
    )

@pytest.fixture(scope="session", autouse=True)
def global_session_setup():
    """Global setup and teardown for the entire test session."""
    logger.info("Test Suite -- session started")
    utilities.download_tc_data_from_gdrive()
    yield
    logger.info("Test Suite -- session ended")
    os_test_framework.cleanup_temp_data()

def pytest_generate_tests(metafunc):
    # ── OS Test Framework Parametrization ──
    if "os_tc_row" in metafunc.fixturenames:
        all_cases = []
        # get_resources will be defined in main.py or conftest
        from main import get_resources
        for resource in get_resources():
             all_cases.extend(
                 os_test_framework.run_tc(
                     resource["api_url"], resource["csv_url"], metafunc,
                     items_url_template=resource.get("validation_url", "")
                 )
             )
        if all_cases:
            metafunc.parametrize(
                "os_tc_row",
                all_cases,
                ids=[f"{r.get('TC_ID', 'TC')}" for r in all_cases],
            )

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
                metafunc.parametrize(
                    "sec_tc_row",
                    cases,
                    ids=[r.get("TC_ID", f"TC_{i}") for i, r in enumerate(cases)],
                )
