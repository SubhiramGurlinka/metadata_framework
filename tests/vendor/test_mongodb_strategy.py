import pytest
from unittest.mock import Mock
from strategies.vendor.mongodb import MongoDbVendorStrategy
from strategies.parsers.mongodb_parser import MongoDbParser
from models import Vulnerability


# ==========================================================
#                   process()
# ==========================================================

def test_process_success_returns_parser_result():
    # Arrange
    mock_parser = Mock(spec=MongoDbParser)

    expected_vulnerability = Vulnerability(
        cve_id=["CVE-2024-1234"],
        severity="High",
        vendor="MongoDB",
        product="MongoDB",
        product_base_version="6.0",
        product_fix_version="6.0.1",
        source_id=["6.0.1"],
        published_date="2024-01-10"
    )

    mock_parser.parse.return_value = expected_vulnerability
    software_cfg = {
        "display_name": "MongoDB"
    }
    vendor_cfg = {}

    strategy = MongoDbVendorStrategy(
        parser=mock_parser,
        software_cfg=software_cfg,
        vendor_cfg=vendor_cfg
    )
    strategy.get_url = Mock(return_value="http://mongodb-url/")

    # Act
    result = strategy.process(
        product="mongodb",
        base_version="6.0",
        fix_version="6.0.1"
    )

    # Assert
    assert result == expected_vulnerability
    strategy.get_url.assert_called_once_with("6.0")
    mock_parser.parse.assert_called_once()
    called_url, context = mock_parser.parse.call_args[0]

    assert called_url == "http://mongodb-url/6.0"
    assert context == {
        "url": "http://mongodb-url/6.0",
        "product": "mongodb",
        "base_version": "6.0",
        "product_fix_version": "6.0.1",
        "sw_display_name": "MongoDB"
    }


def test_process_raises_if_get_url_fails():
    # Arrange
    mock_parser = Mock(spec=MongoDbParser)

    strategy = MongoDbVendorStrategy(
        parser=mock_parser,
        software_cfg={"display_name": "MongoDB"},
        vendor_cfg={}
    )

    strategy.get_url = Mock(side_effect=Exception("URL generation failed"))

    # Act + Assert
    with pytest.raises(Exception, match="URL generation failed"):
        strategy.process(
            product="mongodb",
            base_version="6.0",
            fix_version="6.0.1"
        )

    mock_parser.parse.assert_not_called()