# Architecture Documentation

## Overview

The Metadata Framework is built on a **Strategy Pattern** architecture that separates vendor-specific logic from product-specific parsing logic. This design enables flexible combinations of vendors and products while maintaining clean separation of concerns.

## Design Principles

1. **Separation of Concerns**: Vendor strategies handle HTTP requests and URL construction; parsers handle content extraction
2. **Open/Closed Principle**: Easy to extend with new vendors/products without modifying existing code
3. **Configuration-Driven**: Product/vendor relationships defined in JSON, not hardcoded
4. **Type Safety**: Pydantic models ensure data validation and type correctness
5. **Testability**: Abstract base classes enable easy mocking and testing

## Core Components

### 1. Data Models (`models.py`)

#### Vulnerability Model

The central data structure representing a security vulnerability:

```python
class Vulnerability(BaseModel):
    cve_id: List[str]              # CVE identifiers
    severity: str                   # Severity level (Critical, High, Medium, Low)
    published_date: Optional[str]   # Publication date (YYYY-MM-DD)
    vendor: str                     # Vendor name
    product: str                    # Product name
    product_base_version: str       # Base version (e.g., "9.3")
    product_fix_version: str        # Fix/patch version (e.g., "9.3.0.22")
    source_id: List[str]            # Vendor-specific identifiers
```

**Validation Features:**
- CVE format validation (CVE-YYYY-NNNNN pattern)
- Date format validation (YYYY-MM-DD)
- Immutable (frozen) after creation

### 2. Strategy Pattern Implementation

#### Base Classes (`strategies/base.py`)

**PageParser (Abstract)**
```python
class PageParser(ABC):
    @abstractmethod
    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        """Parse raw HTML/JSON into Vulnerability objects"""
        pass
```

**VendorStrategy (Abstract)**
```python
class VendorStrategy(ABC):
    def __init__(self, parser: PageParser, software_cfg: dict, vendor_cfg: dict):
        self.parser = parser
        self.software_cfg = software_cfg
        self.vendor_cfg = vendor_cfg
    
    def get_config(self, key: str, default=None):
        """Configuration shadowing: software overrides vendor defaults"""
        pass
    
    def get_url(self, base_version: str) -> str:
        """Construct URL for specific version"""
        pass
    
    @abstractmethod
    def process(self, product: str, base_version: str) -> List[Vulnerability]:
        """Main orchestration logic"""
        pass
```

#### Vendor Strategies (`strategies/vendor/`)

Each vendor implements `VendorStrategy` with vendor-specific logic:

- **IBMVendorStrategy**: Handles IBM's fix list pages
- **ApacheVendorStrategy**: Handles Apache security pages
- **RedHatVendorStrategy**: Interacts with Red Hat's REST API
- **OracleVendorStrategy**: Processes Oracle CPU pages
- **MariaDbVendorStrategy**: Handles MariaDB documentation
- **MongoDbVendorStrategy**: Processes MongoDB release notes
- **PostgreSqlVendorStrategy**: Handles PostgreSQL security pages

**Example: IBM Strategy**
```python
class IBMVendorStrategy(VendorStrategy):
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

#### Product Parsers (`strategies/parsers/`)

Each parser implements `PageParser` for specific product page structures:

- **IBMMQTableParser**: Parses IBM MQ fix list tables
- **IBMWebSphereTableParser**: Parses WebSphere fix lists
- **IBMDB2FixListParser**: Parses DB2 fix lists
- **ApacheTomcatParser**: Parses Tomcat security pages
- **RedHatUnifiedParser**: Handles Red Hat API responses
- **OracleCpuParser**: Parses Oracle CPU pages
- **MariaDbParser**: Extracts from MariaDB docs
- **MongoDbParser**: Parses MongoDB release notes
- **PostgreSqlParser**: Handles PostgreSQL security data

### 3. Factory Pattern (`factory.py`)

The `StrategyFactory` creates appropriate strategy/parser combinations:

```python
class StrategyFactory:
    _PARSERS = {
        "IBM_mq_fixpack_parser": IBMMQTableParser,
        "Apache_tomcat_parser": ApacheTomcatParser,
        # ... more parsers
    }
    
    _VENDORS = {
        "ibm": IBMVendorStrategy,
        "apache": ApacheVendorStrategy,
        # ... more vendors
    }
    
    @classmethod
    def get_strategy(cls, vendor_name: str, product_name: str, base_version: str):
        # 1. Validate vendor exists
        # 2. Validate product exists for vendor
        # 3. Validate version is supported
        # 4. Instantiate appropriate vendor strategy with correct parser
        # 5. Return configured strategy
```

**Responsibilities:**
- Vendor/product validation
- Version validation
- Parser selection
- Strategy instantiation with configuration

### 4. Registry System (`registry.py` + `registry.json`)

Configuration-driven approach for vendor/product definitions:

**Registry Structure:**
```json
{
  "vendors": {
    "vendor_name": {
      "display_name": "Human-readable name",
      "default_parser_type": "Default parser for vendor",
      "software": {
        "product_name": {
          "id": "product_id",
          "display_name": "Product Display Name",
          "parser_type": "Specific parser override",
          "supported_versions": ["1.0", "2.0"],
          "base_urls": {
            "1.0": "https://...",
            "all": "https://..."  // Fallback URL
          },
          "base_date_url": "https://..."  // Optional
        }
      }
    }
  }
}
```

**Configuration Shadowing:**
Product-level settings override vendor-level defaults, enabling:
- Vendor-wide defaults
- Product-specific overrides
- Flexible URL patterns

### 5. Utility Modules (`utils/`)

Helper functions for common operations:

- **cvss_to_severity.py**: Convert CVSS scores to severity levels
- **format_date.py**: Normalize date formats
- **get_json.py**: JSON extraction utilities
- **get_severity.py**: Severity determination logic
- **get_soup.py**: BeautifulSoup initialization
- **get_text.py**: Text extraction utilities
- **session_logic.py**: HTTP session management
- **severity_rank.py**: Severity ranking/comparison

### 6. CLI Interface (`main.py`)

Command-line interface for the framework:

```python
def run_pipeline(vendor: str, product: str, base_version: str, fix_version: str):
    # 1. Get strategy from factory
    strategy = StrategyFactory.get_strategy(vendor, product, base_version)
    
    # 2. Get URL for version
    url = strategy.get_url(base_version)
    
    # 3. Process and extract vulnerabilities
    results = strategy.process(product, base_version, fix_version)
    
    # 4. Output JSON
    print(results.model_dump_json(indent=4))
    return results.model_dump()
```

**Features:**
- Argument parsing
- Multiple version batch processing
- JSON output
- Error handling

### 7. AutoPkg Processor (`Processors/CveMetadataFetcher.py`)

Integration with AutoPkg workflow automation:

```python
class CveMetadataFetcher(Processor):
    input_variables = {
        "vendor": {"required": True},
        "product": {"required": True},
        "base_version": {"required": True},
        "fix_version": {"required": True}
    }
    
    output_variables = {
        "dictionary_name": {...},
        "dictionary_appended": {...}
    }
    
    def main(self):
        # Call framework and append results to AutoPkg dictionary
```

## Data Flow

```
┌─────────────────┐
│   CLI / AutoPkg │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  StrategyFactory│ ◄─── registry.json
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ VendorStrategy  │
│   + Parser      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  HTTP Request   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Parse Content  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Vulnerability  │ (Pydantic validation)
│     Model       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   JSON Output   │
└─────────────────┘
```

## Extension Points

### Adding a New Vendor

1. **Create vendor strategy** in `strategies/vendor/new_vendor.py`:
```python
class NewVendorStrategy(VendorStrategy):
    def process(self, product: str, base_version: str, fix_version: str):
        # Implement vendor-specific logic
        pass
```

2. **Register in factory** (`factory.py`):
```python
_VENDORS = {
    "newvendor": NewVendorStrategy,
    # ...
}
```

3. **Add to registry** (`registry.json`):
```json
{
  "vendors": {
    "newvendor": {
      "display_name": "New Vendor",
      "software": { ... }
    }
  }
}
```

### Adding a New Product

1. **Create parser** in `strategies/parsers/new_product_parser.py`:
```python
class NewProductParser(PageParser):
    def parse(self, content: str, context: dict) -> List[Vulnerability]:
        # Implement parsing logic
        pass
```

2. **Register parser** in `factory.py`:
```python
_PARSERS = {
    "NewProduct_parser": NewProductParser,
    # ...
}
```

3. **Add to registry** under appropriate vendor:
```json
{
  "vendors": {
    "vendor_name": {
      "software": {
        "newproduct": {
          "parser_type": "NewProduct_parser",
          "supported_versions": ["1.0"],
          "base_urls": { ... }
        }
      }
    }
  }
}
```

## Testing Architecture

### Test Layers

1. **Unit Tests** (`tests/unit/`):
   - Test individual components in isolation
   - Mock external dependencies
   - Test models, factory, registry

2. **Parser Tests** (`tests/parsers/`):
   - Test parser logic with sample HTML/JSON
   - Verify data extraction accuracy
   - Test edge cases

3. **Vendor Tests** (`tests/vendor/`):
   - Test vendor strategy logic
   - Mock HTTP responses
   - Test URL construction

4. **Integration Tests** (`tests/integration/`):
   - Test component interactions
   - Test CLI outputs
   - Test configuration loading

5. **End-to-End Tests** (`tests/e2e/`):
   - Test complete workflows
   - May require network access
   - Test real vendor pages (with caution)

## Design Patterns Used

1. **Strategy Pattern**: VendorStrategy and PageParser abstractions
2. **Factory Pattern**: StrategyFactory for object creation
3. **Template Method**: VendorStrategy.process() defines workflow
4. **Registry Pattern**: JSON-based configuration registry
5. **Dependency Injection**: Parsers injected into strategies

## Performance Considerations

- **HTTP Timeouts**: 15-second timeout on requests
- **Lazy Loading**: Registry loaded once at module import
- **Immutable Models**: Pydantic frozen models prevent accidental mutation
- **Batch Processing**: Support for multiple versions in single run

## Security Considerations

- **Input Validation**: Pydantic models validate all data
- **URL Validation**: Only configured URLs are accessed
- **Timeout Protection**: Prevents hanging on slow responses
- **Error Handling**: Graceful degradation on parsing failures

## Future Enhancements

Potential areas for expansion:

1. **Caching Layer**: Cache HTTP responses to reduce network calls
2. **Async Support**: Use asyncio for concurrent vendor requests
3. **Database Backend**: Store historical vulnerability data
4. **API Server**: REST API wrapper around framework
5. **Webhook Support**: Notify on new vulnerabilities
6. **Rate Limiting**: Respect vendor rate limits
7. **Retry Logic**: Automatic retry on transient failures
8. **Metrics/Logging**: Enhanced observability
