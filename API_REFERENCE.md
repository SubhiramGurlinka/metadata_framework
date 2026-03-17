# API Reference

Complete API documentation for the Metadata Framework.

## Table of Contents

- [Core Models](#core-models)
- [Base Classes](#base-classes)
- [Vendor Strategies](#vendor-strategies)
- [Parsers](#parsers)
- [Factory](#factory)
- [Registry](#registry)
- [CLI Interface](#cli-interface)
- [AutoPkg Processor](#autopkg-processor)
- [Utility Functions](#utility-functions)

---

## Core Models

### `models.Vulnerability`

Immutable Pydantic model representing a security vulnerability.

**Module:** `models.py`

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `cve_id` | `List[str]` | List of CVE identifiers (e.g., ["CVE-2024-1234"]) |
| `severity` | `str` | Severity level: "Critical", "High", "Medium", "Low", or "None" |
| `published_date` | `Optional[str]` | Publication date in YYYY-MM-DD format |
| `vendor` | `str` | Vendor name (lowercase) |
| `product` | `str` | Product name (lowercase) |
| `product_base_version` | `str` | Base version (e.g., "9.3") |
| `product_fix_version` | `str` | Fix/patch version (e.g., "9.3.0.22") |
| `source_id` | `List[str]` | Vendor-specific identifiers (e.g., APAR numbers) |

#### Validators

**`validate_date_format(v)`**
- Validates `published_date` is in YYYY-MM-DD format
- Checks that date is a valid calendar date
- Returns `None` if input is `None`
- Raises `ValueError` for invalid formats

**`validate_cve_format(v)`**
- Validates CVE IDs match pattern: `CVE-YYYY-NNNNN` (4-7 digits)
- Returns empty list if input is empty
- Raises `ValueError` for invalid CVE format

#### Methods

**`model_dump()`**
- Returns dictionary representation of the model
- Inherited from Pydantic BaseModel

**`model_dump_json(indent=None)`**
- Returns JSON string representation
- Optional `indent` parameter for pretty printing

#### Example

```python
from models import Vulnerability

vuln = Vulnerability(
    cve_id=["CVE-2024-1234"],
    severity="High",
    published_date="2024-03-15",
    vendor="ibm",
    product="mq",
    product_base_version="9.3",
    product_fix_version="9.3.0.22",
    source_id=["9.3.0.22-WS-MQ-APAR-IT12345"]
)

# Export to JSON
json_output = vuln.model_dump_json(indent=4)
```

---

## Base Classes

### `strategies.base.PageParser`

Abstract base class for product-specific parsers.

**Module:** `strategies/base.py`

#### Methods

**`parse(content: str, context: dict) -> List[Vulnerability]`** *(abstract)*
- **Parameters:**
  - `content`: Raw HTML or JSON content from vendor page
  - `context`: Dictionary with metadata (product, version, URL, etc.)
- **Returns:** List of `Vulnerability` objects
- **Raises:** Implementation-specific exceptions

#### Context Dictionary Keys

Common keys passed in `context`:
- `product`: Product name
- `base_version`: Base version string
- `product_fix_version`: Fix version string
- `url`: Source URL
- `date_url`: Optional URL for date information

#### Implementation Example

```python
from strategies.base import PageParser
from models import Vulnerability
from typing import List

class MyProductParser(PageParser):
    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        # Parse content and extract vulnerability data
        # Return list of Vulnerability objects
        pass
```

---

### `strategies.base.VendorStrategy`

Abstract base class for vendor-specific strategies.

**Module:** `strategies/base.py`

#### Constructor

**`__init__(parser: PageParser, software_cfg: dict, vendor_cfg: dict)`**
- **Parameters:**
  - `parser`: PageParser instance for parsing content
  - `software_cfg`: Product-specific configuration from registry
  - `vendor_cfg`: Vendor-level configuration from registry

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `parser` | `PageParser` | Parser instance for content extraction |
| `software_cfg` | `dict` | Product configuration |
| `vendor_cfg` | `dict` | Vendor configuration |

#### Methods

**`get_config(key: str, default=None) -> Any`**
- Retrieves configuration value with shadowing
- Product-level config overrides vendor-level config
- **Parameters:**
  - `key`: Configuration key to retrieve
  - `default`: Default value if key not found
- **Returns:** Configuration value or default

**`get_url(base_version: str) -> str`**
- Constructs URL for specific product version
- **Parameters:**
  - `base_version`: Version string (e.g., "9.3")
- **Returns:** URL string
- Checks version-specific URL first, falls back to "all" URL

**`process(product: str, base_version: str, fix_version: str) -> Vulnerability`** *(abstract)*
- Main orchestration method for vulnerability extraction
- **Parameters:**
  - `product`: Product name
  - `base_version`: Base version
  - `fix_version`: Fix version
- **Returns:** `Vulnerability` object
- **Raises:** Implementation-specific exceptions

#### Implementation Example

```python
from strategies.base import VendorStrategy
import requests

class MyVendorStrategy(VendorStrategy):
    def process(self, product: str, base_version: str, fix_version: str):
        url = self.get_url(base_version)
        response = requests.get(url, timeout=15)
        
        context = {
            "product": product,
            "base_version": base_version,
            "product_fix_version": fix_version,
            "url": url
        }
        
        return self.parser.parse(response.text, context)
```

---

## Vendor Strategies

### `strategies.vendor.ibm.IBMVendorStrategy`

Handles IBM product security pages.

**Module:** `strategies/vendor/ibm.py`

#### Methods

**`process(product: str, base_version: str, fix_version: str) -> Vulnerability`**
- Fetches IBM fix list page
- Passes content to parser with context
- Supports optional `base_date_url` for date extraction

---

### `strategies.vendor.apache.ApacheVendorStrategy`

Handles Apache product security pages.

**Module:** `strategies/vendor/apache.py`

---

### `strategies.vendor.redhat.RedHatVendorStrategy`

Handles Red Hat security advisories via REST API.

**Module:** `strategies/vendor/redhat.py`

---

### `strategies.vendor.oracle.OracleVendorStrategy`

Handles Oracle Critical Patch Update (CPU) pages.

**Module:** `strategies/vendor/oracle.py`

---

### `strategies.vendor.mariadb.MariaDbVendorStrategy`

Handles MariaDB security documentation.

**Module:** `strategies/vendor/mariadb.py`

---

### `strategies.vendor.mongodb.MongoDbVendorStrategy`

Handles MongoDB release notes and security information.

**Module:** `strategies/vendor/mongodb.py`

---

### `strategies.vendor.postgresql.PostgreSqlVendorStrategy`

Handles PostgreSQL security pages.

**Module:** `strategies/vendor/postgresql.py`

---

## Parsers

### `strategies.parsers.ibm_mq_parsers.IBMMQTableParser`

Parses IBM MQ fix list HTML tables.

**Module:** `strategies/parsers/ibm_mq_parsers.py`

---

### `strategies.parsers.ibm_websphere_parser.IBMWebSphereTableParser`

Parses IBM WebSphere fix list HTML tables.

**Module:** `strategies/parsers/ibm_websphere_parser.py`

---

### `strategies.parsers.ibm_db2_parser.IBMDB2FixListParser`

Parses IBM DB2 fix list pages.

**Module:** `strategies/parsers/ibm_db2_parser.py`

---

### `strategies.parsers.apache_tomcat_parser.ApacheTomcatParser`

Parses Apache Tomcat security pages.

**Module:** `strategies/parsers/apache_tomcat_parser.py`

---

### `strategies.parsers.redhat_parser.RedHatUnifiedParser`

Parses Red Hat API responses.

**Module:** `strategies/parsers/redhat_parser.py`

---

### `strategies.parsers.oracle_cpu_parser.OracleCpuParser`

Parses Oracle CPU pages for multiple products.

**Module:** `strategies/parsers/oracle_cpu_parser.py`

---

### `strategies.parsers.mariadb_parser.MariaDbParser`

Parses MariaDB CVE documentation.

**Module:** `strategies/parsers/mariadb_parser.py`

---

### `strategies.parsers.mongodb_parser.MongoDbParser`

Parses MongoDB release notes.

**Module:** `strategies/parsers/mongodb_parser.py`

---

### `strategies.parsers.postgresql_parser.PostgreSqlParser`

Parses PostgreSQL security pages.

**Module:** `strategies/parsers/postgresql_parser.py`

---

## Factory

### `factory.StrategyFactory`

Factory class for creating vendor strategy instances.

**Module:** `factory.py`

#### Class Attributes

**`_PARSERS`**: `Dict[str, Type[PageParser]]`
- Maps parser type strings to parser classes

**`_VENDORS`**: `Dict[str, Type[VendorStrategy]]`
- Maps vendor names to vendor strategy classes

#### Methods

**`get_strategy(vendor_name: str, product_name: str, base_version: str) -> VendorStrategy`** *(classmethod)*
- Creates and returns configured vendor strategy
- **Parameters:**
  - `vendor_name`: Vendor identifier (lowercase)
  - `product_name`: Product identifier (lowercase)
  - `base_version`: Version string
- **Returns:** Configured `VendorStrategy` instance
- **Raises:**
  - `ValueError`: If vendor not supported
  - `ValueError`: If product not supported for vendor
  - `ValueError`: If version not supported for product

#### Example

```python
from factory import StrategyFactory

# Get strategy for IBM MQ 9.3
strategy = StrategyFactory.get_strategy(
    vendor_name="ibm",
    product_name="mq",
    base_version="9.3"
)

# Process vulnerability data
result = strategy.process(
    product="mq",
    base_version="9.3",
    fix_version="9.3.0.22"
)
```

---

## Registry

### `registry.load_registry(path: Path) -> Dict[str, Any]`

Loads registry configuration from JSON file.

**Module:** `registry.py`

#### Parameters

- `path`: Path to registry JSON file (default: `registry.json`)

#### Returns

Dictionary containing vendor/product configuration

#### Raises

- `FileNotFoundError`: If registry file not found
- `json.JSONDecodeError`: If JSON is invalid

---

### `registry.PRODUCT_REGISTRY`

Global registry dictionary loaded at module import.

**Module:** `registry.py`

#### Structure

```python
{
    "vendors": {
        "vendor_name": {
            "display_name": str,
            "default_parser_type": str,
            "software": {
                "product_name": {
                    "id": str,
                    "display_name": str,
                    "parser_type": str,
                    "supported_versions": List[str],
                    "base_urls": Dict[str, str],
                    "base_date_url": Optional[str]
                }
            }
        }
    }
}
```

---

## CLI Interface

### `main.run_pipeline(vendor: str, product: str, base_version: str, fix_version: str) -> dict`

Main pipeline function for processing vulnerability data.

**Module:** `main.py`

#### Parameters

- `vendor`: Vendor name
- `product`: Product name
- `base_version`: Base version string
- `fix_version`: Fix version string

#### Returns

Dictionary representation of `Vulnerability` object

#### Side Effects

- Prints JSON output to stdout
- Prints validation messages if validation data exists

#### Raises

- `ValueError`: Configuration errors
- `Exception`: Unexpected errors (exits with code 1)

#### Example

```python
from main import run_pipeline

result = run_pipeline(
    vendor="ibm",
    product="mq",
    base_version="9.3",
    fix_version="9.3.0.22"
)
```

---

### `main.verify_result(result: Vulnerability)`

Validates result against validation data.

**Module:** `main.py`

#### Parameters

- `result`: `Vulnerability` object to validate

#### Side Effects

- Prints validation results to stdout
- Compares against `validation.json` data

---

## AutoPkg Processor

### `Processors.CveMetadataFetcher.CveMetadataFetcher`

AutoPkg processor for vulnerability metadata extraction.

**Module:** `Processors/CveMetadataFetcher.py`

#### Input Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `vendor` | Yes | Vendor name |
| `product` | Yes | Product name |
| `base_version` | Yes | Product base version |
| `fix_version` | Yes | Product fix version |

#### Output Variables

| Variable | Description |
|----------|-------------|
| `dictionary_name` | Name of appended dictionary |
| `dictionary_appended` | Dictionary with vulnerability data |

#### Output Dictionary Keys

- `severity`: Severity level
- `cve_id`: Semicolon-separated CVE IDs
- `source_id`: Semicolon-separated source IDs
- `published_date`: Publication date

#### Example Usage

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

---

## Utility Functions

### `utils.cvss_to_severity`

Converts CVSS scores to severity levels.

**Module:** `utils/cvss_to_severity.py`

---

### `utils.format_date`

Normalizes date formats to YYYY-MM-DD.

**Module:** `utils/format_date.py`

---

### `utils.get_json`

JSON extraction utilities.

**Module:** `utils/get_json.py`

---

### `utils.get_severity`

Determines severity from various inputs.

**Module:** `utils/get_severity.py`

---

### `utils.get_soup`

BeautifulSoup initialization helper.

**Module:** `utils/get_soup.py`

---

### `utils.get_text`

Text extraction utilities.

**Module:** `utils/get_text.py`

---

### `utils.session_logic`

HTTP session management.

**Module:** `utils/session_logic.py`

---

### `utils.severity_rank`

Severity ranking and comparison.

**Module:** `utils/severity_rank.py`

---

## Error Handling

### Common Exceptions

**`ValueError`**
- Raised for configuration errors
- Raised for unsupported vendors/products/versions
- Raised for validation failures

**`requests.RequestException`**
- Raised for HTTP request failures
- Includes timeout errors

**`json.JSONDecodeError`**
- Raised for invalid JSON in registry or responses

**`pydantic.ValidationError`**
- Raised for invalid data in Vulnerability model

### Best Practices

1. Always catch `ValueError` when using `StrategyFactory.get_strategy()`
2. Set appropriate timeouts on HTTP requests (default: 15 seconds)
3. Validate input data before creating `Vulnerability` objects
4. Handle parser-specific exceptions in parser implementations

---

## Type Hints

The framework uses Python type hints throughout:

```python
from typing import List, Optional, Dict, Any
from models import Vulnerability
from strategies.base import PageParser, VendorStrategy
```

All public APIs include type annotations for better IDE support and type checking.
