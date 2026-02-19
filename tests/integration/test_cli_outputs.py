import sys
import json
import pytest
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAIN_FILE = PROJECT_ROOT / "main.py"
EXPECTED_JSON = PROJECT_ROOT / "validation.json"


def load_expected():
    with open(EXPECTED_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def run_cli(vendor, product, base_version, fix_version):
    result = subprocess.run(
        [
            sys.executable,
            str(MAIN_FILE),
            "--vendor", vendor,
            "--product", product,
            "--base-version", base_version,
            "--fix-version", fix_version,
        ],
        capture_output=True,
        text=True,
        timeout=60
    )

    assert result.returncode == 0, f"\nSTDERR:\n{result.stderr}"

    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        pytest.fail(f"Invalid JSON output:\n{result.stdout}")


def test_cli_output_matches_expected_fields():
    expected_data = load_expected()

    print("--- outputs:")
    for vendor, products in expected_data.items():
        for product, versions in products.items():
            for base_version, expected in versions.items():

                fix_version = expected["product_fix_version"]

                output = run_cli(
                    vendor,
                    product,
                    base_version,
                    fix_version
                )

                assert output["severity"] == expected["severity"], \
                    f"{vendor}-{product}-{base_version}: severity mismatch"

                assert output["source_id"] == expected["source_id"], \
                    f"{vendor}-{product}-{base_version}: source_id mismatch"

                assert output["published_date"] == expected["published_date"], \
                    f"{vendor}-{product}-{base_version}: published_date mismatch"

                # Order-independent CVE comparison
                assert sorted(output["cve_id"]) == sorted(expected["cve_id"]), \
                    f"{vendor}-{product}-{base_version}: CVE mismatch"
                print(f"Passed {vendor} - {product} - {base_version}")