# Metadata Framework

A flexible, extensible Python framework for scraping and extracting vulnerability metadata (CVEs, severity, published dates) from multiple vendor security advisory pages.

## Overview

The Metadata Framework provides a unified interface to collect security vulnerability information from various software vendors including IBM, Apache, Oracle, Red Hat, MariaDB, MongoDB, and PostgreSQL. It uses a strategy pattern architecture to handle vendor-specific parsing logic while maintaining a consistent API.

## Features

- **Multi-Vendor Support**: Supports 7+ major software vendors
- **Extensible Architecture**: Easy to add new vendors and products via configuration
- **Type-Safe Models**: Uses Pydantic for data validation and type safety
- **Comprehensive Testing**: Includes unit, integration, and end-to-end tests
- **AutoPkg Integration**: Includes processor for AutoPkg workflow integration
- **Flexible Configuration**: JSON-based registry for vendor/product configuration

## Supported Vendors & Products

| Vendor | Products | Versions |
|--------|----------|----------|
| **IBM** | MQ, WebSphere, DB2 | 9.1-9.4 (MQ), 8.5.5-9.0.5 (WebSphere), 12.1 (DB2) |
| **Apache** | Tomcat | 9.0, 10.1, 11.0 |
| **Red Hat** | JBoss EAP | 7.3, 7.4, 8.0 |
| **Oracle** | MySQL, WebLogic, Java SE, Database | Multiple versions |
| **MariaDB** | MariaDB Server | 10.11, 11.4, 11.8 |
| **MongoDB** | MongoDB | 7.0, 8.0 |
| **PostgreSQL** | PostgreSQL | 15, 16, 17, 18 |

## Installation

### Prerequisites

- Python 3.7+
- pip

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd metadata_framework

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Command Line Usage

```bash
python main.py --vendor ibm --product mq --base-version 9.3 --fix-version 9.3.0.22
```

### Multiple Version Processing

```bash
python main.py --vendor ibm --product mq \
  --base-version 9.1 9.2 9.3 \
  --fix-version 9.1.0.25 9.2.0.18 9.3.0.22
```

### Example Output

```json
{
    "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
    "severity": "High",
    "published_date": "2024-03-15",
    "vendor": "ibm",
    "product": "mq",
    "product_base_version": "9.3",
    "product_fix_version": "9.3.0.22",
    "source_id": ["9.3.0.22-WS-MQ-APAR-IT12345"]
}
```

## Project Structure

```
metadata_framework/
├── main.py                    # CLI entry point
├── factory.py                 # Strategy factory for vendor/parser selection
├── models.py                  # Pydantic data models
├── registry.py                # Registry loader
├── registry.json              # Vendor/product configuration
├── validation.json            # Test validation data
├── strategies/
│   ├── base.py               # Abstract base classes
│   ├── vendor/               # Vendor-specific strategies
│   │   ├── ibm.py
│   │   ├── apache.py
│   │   ├── oracle.py
│   │   └── ...
│   └── parsers/              # Product-specific parsers
│       ├── ibm_mq_parsers.py
│       ├── apache_tomcat_parser.py
│       └── ...
├── utils/                     # Utility functions
├── Processors/               # AutoPkg processor integration
│   └── CveMetadataFetcher.py
└── tests/                    # Test suite
    ├── unit/
    ├── integration/
    ├── parsers/
    ├── vendor/
    └── e2e/
```

## Architecture

The framework uses a **Strategy Pattern** with two main abstraction layers:

1. **VendorStrategy**: Handles vendor-specific request logic and URL construction
2. **PageParser**: Handles product-specific HTML/JSON parsing logic

This separation allows for flexible combinations of vendors and products while minimizing code duplication.

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

## Configuration

Products and vendors are configured in `registry.json`. Each entry specifies:

- Display names
- Parser types
- Supported versions
- Base URLs for security advisories
- Optional date URLs for additional metadata

Example:
```json
{
  "vendors": {
    "ibm": {
      "display_name": "IBM",
      "software": {
        "mq": {
          "parser_type": "IBM_mq_fixpack_parser",
          "supported_versions": ["9.1", "9.2", "9.3", "9.4"],
          "base_urls": {
            "9.1": "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-91-lts"
          }
        }
      }
    }
  }
}
```

## Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/e2e/

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/unit/test_factory.py
```

## AutoPkg Integration

The framework includes a processor for AutoPkg workflows:

```xml
<dict>
    <key>Processor</key>
    <string>CveMetadataFetcher</string>
    <key>Arguments</key>
    <dict>
        <key>vendor</key>
        <string>ibm</string>
        <key>product</key>
        <string>mq</string>
        <key>base_version</key>
        <string>9.3</string>
        <key>fix_version</key>
        <string>9.3.0.22</string>
    </dict>
</dict>
```

## Adding New Vendors/Products

1. **Add configuration** to `registry.json`
2. **Create vendor strategy** (if new vendor) in `strategies/vendor/`
3. **Create parser** in `strategies/parsers/`
4. **Register in factory** (`factory.py`)
5. **Add tests** in appropriate test directory

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## API Reference

See [API_REFERENCE.md](API_REFERENCE.md) for complete API documentation.

## Examples

See [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md) for more usage examples and patterns.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[Add your license information here]

## Support

[Add support/contact information here]