import sys
import os
import json
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from main import run_pipeline


BASE_DIR = os.path.dirname(__file__)
TEST_FILE = os.path.join(BASE_DIR, "regression_test_cases.json")

with open(TEST_FILE) as f:
    TEST_CASES = json.load(f)["test_cases"]


@pytest.mark.parametrize(
    "case",
    [pytest.param(case, id=case["test_id"]) for case in TEST_CASES]
)
def test_vendor_pipeline(case):
    result = run_pipeline(
        vendor=case["vendor"],
        product=case["product"],
        base_version=case["base_version"],
        fix_version=case["fix_version"]
    )

    expected = case["expected"]

    assert result["severity"] == expected["severity"]
    assert result["source_id"] == expected["source_id"]
    assert result["published_date"] == expected["published_date"]
    assert set(result["cve_id"]) == set(expected["cve_id"])