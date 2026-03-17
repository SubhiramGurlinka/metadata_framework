# Contributing to Metadata Framework

Thank you for your interest in contributing to the Metadata Framework! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding New Vendors](#adding-new-vendors)
- [Adding New Products](#adding-new-products)
- [Testing Guidelines](#testing-guidelines)
- [Code Style](#code-style)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

Be respectful, professional, and constructive in all interactions. We aim to maintain a welcoming and inclusive environment for all contributors.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch
4. Make your changes
5. Test thoroughly
6. Submit a pull request

## Development Setup

### Prerequisites

- Python 3.7 or higher
- pip package manager
- Git

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/metadata_framework.git
cd metadata_framework

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies (if available)
pip install pytest pytest-cov black flake8 mypy
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/unit/test_factory.py

# Run with verbose output
pytest -v
```

## Project Structure

```
metadata_framework/
├── main.py                    # CLI entry point
├── factory.py                 # Strategy factory
├── models.py                  # Data models
├── registry.py                # Registry loader
├── registry.json              # Configuration
├── strategies/
│   ├── base.py               # Abstract base classes
│   ├── vendor/               # Vendor strategies
│   └── parsers/              # Product parsers
├── utils/                     # Utility functions
├── Processors/               # AutoPkg integration
└── tests/                    # Test suite
```

## Adding New Vendors

### Step 1: Create Vendor Strategy

Create a new file in `strategies/vendor/`:

```python
# strategies/vendor/newvendor.py

from strategies.base import VendorStrategy
import requests

class NewVendorStrategy(VendorStrategy):
    """Strategy for New Vendor security pages."""
    
    def process(self, product: str, base_version: str, fix_version: str):
        """
        Process New Vendor security advisory page.
        
        Args:
            product: Product name
            base_version: Base version string
            fix_version: Fix version string
            
        Returns:
            Vulnerability object with extracted data
        """
        # Get URL from configuration
        url = self.get_url(base_version)
        
        # Fetch content (add error handling)
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
        except requests.RequestException as e:
            raise ValueError(f"Failed to fetch {url}: {e}")
        
        # Build context for parser
        context = {
            "product": product,
            "base_version": base_version,
            "product_fix_version": fix_version,
            "url": url
        }
        
        # Optional: Add vendor-specific context
        if self.software_cfg.get("api_key"):
            context["api_key"] = self.software_cfg["api_key"]
        
        # Parse and return
        return self.parser.parse(response.text, context)
```

### Step 2: Register in Factory

Add to `factory.py`:

```python
from strategies.vendor.newvendor import NewVendorStrategy

class StrategyFactory:
    _VENDORS = {
        "newvendor": NewVendorStrategy,
        # ... existing vendors
    }
```

### Step 3: Add to Registry

Add to `registry.json`:

```json
{
  "vendors": {
    "newvendor": {
      "display_name": "New Vendor",
      "default_parser_type": "NewVendor_default_parser",
      "software": {
        "product1": {
          "id": "product1",
          "display_name": "Product One",
          "parser_type": "NewVendor_product1_parser",
          "supported_versions": ["1.0", "2.0"],
          "base_urls": {
            "1.0": "https://newvendor.com/security/v1",
            "2.0": "https://newvendor.com/security/v2"
          }
        }
      }
    }
  }
}
```

### Step 4: Add Tests

Create `tests/vendor/test_newvendor_strategy.py`:

```python
import pytest
from strategies.vendor.newvendor import NewVendorStrategy
from strategies.base import PageParser
from models import Vulnerability

class MockParser(PageParser):
    def parse(self, content, context):
        return Vulnerability(
            cve_id=["CVE-2024-0001"],
            severity="High",
            published_date="2024-01-01",
            vendor="newvendor",
            product=context["product"],
            product_base_version=context["base_version"],
            product_fix_version=context["product_fix_version"],
            source_id=["TEST-001"]
        )

def test_newvendor_strategy():
    software_cfg = {
        "base_urls": {"1.0": "https://example.com"}
    }
    vendor_cfg = {}
    
    strategy = NewVendorStrategy(
        parser=MockParser(),
        software_cfg=software_cfg,
        vendor_cfg=vendor_cfg
    )
    
    # Add assertions
    assert strategy is not None
```

## Adding New Products

### Step 1: Create Parser

Create a new file in `strategies/parsers/`:

```python
# strategies/parsers/newproduct_parser.py

from strategies.base import PageParser
from models import Vulnerability
from typing import List
from bs4 import BeautifulSoup

class NewProductParser(PageParser):
    """Parser for New Product security pages."""
    
    def parse(self, content: str, context: dict) -> Vulnerability:
        """
        Parse New Product security advisory page.
        
        Args:
            content: Raw HTML/JSON content
            context: Dictionary with product, version, URL info
            
        Returns:
            Vulnerability object
        """
        soup = BeautifulSoup(content, 'html.parser')
        
        # Extract CVE IDs
        cve_ids = self._extract_cves(soup)
        
        # Extract severity
        severity = self._extract_severity(soup)
        
        # Extract published date
        published_date = self._extract_date(soup)
        
        # Extract source IDs
        source_ids = self._extract_source_ids(soup)
        
        return Vulnerability(
            cve_id=cve_ids,
            severity=severity,
            published_date=published_date,
            vendor=context.get("vendor", "unknown"),
            product=context["product"],
            product_base_version=context["base_version"],
            product_fix_version=context["product_fix_version"],
            source_id=source_ids
        )
    
    def _extract_cves(self, soup: BeautifulSoup) -> List[str]:
        """Extract CVE IDs from page."""
        # Implementation here
        pass
    
    def _extract_severity(self, soup: BeautifulSoup) -> str:
        """Extract severity level."""
        # Implementation here
        pass
    
    def _extract_date(self, soup: BeautifulSoup) -> str:
        """Extract published date."""
        # Implementation here
        pass
    
    def _extract_source_ids(self, soup: BeautifulSoup) -> List[str]:
        """Extract vendor-specific identifiers."""
        # Implementation here
        pass
```

### Step 2: Register Parser

Add to `factory.py`:

```python
from strategies.parsers.newproduct_parser import NewProductParser

class StrategyFactory:
    _PARSERS = {
        "NewProduct_parser": NewProductParser,
        # ... existing parsers
    }
```

### Step 3: Add to Registry

Add product under appropriate vendor in `registry.json`:

```json
{
  "vendors": {
    "existingvendor": {
      "software": {
        "newproduct": {
          "id": "newproduct",
          "display_name": "New Product",
          "parser_type": "NewProduct_parser",
          "supported_versions": ["1.0", "2.0"],
          "base_urls": {
            "1.0": "https://vendor.com/newproduct/v1/security",
            "2.0": "https://vendor.com/newproduct/v2/security"
          }
        }
      }
    }
  }
}
```

### Step 4: Add Tests

Create `tests/parsers/test_newproduct_parser.py`:

```python
import pytest
from strategies.parsers.newproduct_parser import NewProductParser

def test_newproduct_parser():
    parser = NewProductParser()
    
    # Sample HTML content
    content = """
    <html>
        <body>
            <div class="cve">CVE-2024-0001</div>
            <div class="severity">High</div>
        </body>
    </html>
    """
    
    context = {
        "product": "newproduct",
        "base_version": "1.0",
        "product_fix_version": "1.0.1",
        "url": "https://example.com"
    }
    
    result = parser.parse(content, context)
    
    assert result.cve_id == ["CVE-2024-0001"]
    assert result.severity == "High"
    assert result.product == "newproduct"
```

## Testing Guidelines

### Test Structure

- **Unit Tests** (`tests/unit/`): Test individual components in isolation
- **Parser Tests** (`tests/parsers/`): Test parser logic with sample data
- **Vendor Tests** (`tests/vendor/`): Test vendor strategy logic
- **Integration Tests** (`tests/integration/`): Test component interactions
- **E2E Tests** (`tests/e2e/`): Test complete workflows

### Writing Tests

```python
import pytest
from models import Vulnerability

def test_vulnerability_model_validation():
    """Test that Vulnerability model validates CVE format."""
    with pytest.raises(ValueError):
        Vulnerability(
            cve_id=["INVALID-CVE"],  # Should fail validation
            severity="High",
            published_date="2024-01-01",
            vendor="test",
            product="test",
            product_base_version="1.0",
            product_fix_version="1.0.1",
            source_id=["TEST-001"]
        )

def test_vulnerability_model_valid():
    """Test that valid Vulnerability model is created."""
    vuln = Vulnerability(
        cve_id=["CVE-2024-0001"],
        severity="High",
        published_date="2024-01-01",
        vendor="test",
        product="test",
        product_base_version="1.0",
        product_fix_version="1.0.1",
        source_id=["TEST-001"]
    )
    
    assert vuln.cve_id == ["CVE-2024-0001"]
    assert vuln.severity == "High"
```

### Test Best Practices

1. **Use descriptive test names** that explain what is being tested
2. **Mock external dependencies** (HTTP requests, file I/O)
3. **Test edge cases** (empty data, malformed input, missing fields)
4. **Use fixtures** for common test data
5. **Keep tests independent** - no test should depend on another
6. **Test both success and failure paths**

### Mocking HTTP Requests

```python
from unittest.mock import patch, Mock

@patch('requests.get')
def test_vendor_strategy_with_mock(mock_get):
    """Test vendor strategy with mocked HTTP request."""
    mock_response = Mock()
    mock_response.text = "<html>Sample content</html>"
    mock_response.status_code = 200
    mock_get.return_value = mock_response
    
    # Test your strategy here
```

## Code Style

### Python Style Guide

Follow PEP 8 guidelines:

- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use snake_case for functions and variables
- Use PascalCase for classes
- Add docstrings to all public functions and classes

### Type Hints

Use type hints for all function signatures:

```python
from typing import List, Optional, Dict, Any
from models import Vulnerability

def process_data(
    vendor: str,
    product: str,
    version: str
) -> Optional[Vulnerability]:
    """Process vulnerability data."""
    pass
```

### Docstrings

Use Google-style docstrings:

```python
def extract_cves(content: str) -> List[str]:
    """
    Extract CVE identifiers from content.
    
    Args:
        content: Raw HTML or text content
        
    Returns:
        List of CVE identifiers (e.g., ["CVE-2024-0001"])
        
    Raises:
        ValueError: If content is empty or invalid
    """
    pass
```

### Code Formatting

Use `black` for automatic formatting:

```bash
# Format all Python files
black .

# Check formatting without changes
black --check .
```

### Linting

Use `flake8` for linting:

```bash
# Run linter
flake8 .

# Ignore specific rules
flake8 --ignore=E501,W503 .
```

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, no logic change)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks

### Examples

```
feat(parsers): add MongoDB parser

Implement parser for MongoDB release notes to extract CVE
information from security advisories.

Closes #123
```

```
fix(factory): handle missing parser configuration

Add validation to check if parser_type exists before
attempting to instantiate parser class.

Fixes #456
```

## Pull Request Process

### Before Submitting

1. **Run all tests** and ensure they pass
2. **Add tests** for new functionality
3. **Update documentation** if needed
4. **Follow code style** guidelines
5. **Write clear commit messages**

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring

## Testing
- [ ] All existing tests pass
- [ ] New tests added
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
- [ ] Registry updated if needed
```

### Review Process

1. Submit PR with clear description
2. Address reviewer feedback
3. Ensure CI/CD checks pass
4. Obtain approval from maintainer
5. Squash and merge

## Additional Resources

- [Python PEP 8 Style Guide](https://pep8.org/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [pytest Documentation](https://docs.pytest.org/)
- [BeautifulSoup Documentation](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)

## Questions?

If you have questions or need help, please:
- Open an issue on GitHub
- Contact the maintainers
- Check existing documentation

Thank you for contributing to the Metadata Framework!
