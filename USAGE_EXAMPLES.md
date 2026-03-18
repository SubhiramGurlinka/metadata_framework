# Usage Examples

Practical examples and common use cases for the Metadata Framework.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Batch Processing](#batch-processing)
- [Programmatic Usage](#programmatic-usage)
- [AutoPkg Integration](#autopkg-integration)
- [Advanced Scenarios](#advanced-scenarios)
- [Error Handling](#error-handling)
- [Output Formats](#output-formats)

---

## Basic Usage

### Single Product Query

Query vulnerability information for a specific product version:

```bash
python main.py \
  --vendor ibm \
  --product mq \
  --base-version 9.3 \
  --fix-version 9.3.0.22
```

**Output:**
```json
{
    "cve_id": [
        "CVE-2024-1234",
        "CVE-2024-5678"
    ],
    "severity": "High",
    "published_date": "2024-03-15",
    "vendor": "ibm",
    "product": "mq",
    "product_base_version": "9.3",
    "product_fix_version": "9.3.0.22",
    "source_id": [
        "9.3.0.22-WS-MQ-APAR-IT12345"
    ]
}
```

### Different Vendors

#### IBM WebSphere

```bash
python main.py \
  --vendor ibm \
  --product websphere \
  --base-version 9.0.5 \
  --fix-version 9.0.5.18
```

#### Apache Tomcat

```bash
python main.py \
  --vendor apache \
  --product tomcat \
  --base-version 10.1 \
  --fix-version 10.1.28
```

#### Red Hat JBoss

```bash
python main.py \
  --vendor redhat \
  --product jboss \
  --base-version 7.4 \
  --fix-version 7.4.18
```

#### Oracle MySQL

```bash
python main.py \
  --vendor oracle \
  --product "mysql server" \
  --base-version 8.0 \
  --fix-version 8.0.40
```

#### PostgreSQL

```bash
python main.py \
  --vendor postgresql \
  --product postgresql \
  --base-version 16 \
  --fix-version 16.4
```

#### MariaDB

```bash
python main.py \
  --vendor mariadb \
  --product mariadb \
  --base-version 11.4 \
  --fix-version 11.4.3
```

#### MongoDB

```bash
python main.py \
  --vendor mongodb \
  --product mongodb \
  --base-version 8.0 \
  --fix-version 8.0.3
```

---

## Batch Processing

### Multiple Versions of Same Product

Process multiple versions in a single command:

```bash
python main.py \
  --vendor ibm \
  --product mq \
  --base-version 9.1 9.2 9.3 9.4 \
  --fix-version 9.1.0.25 9.2.0.18 9.3.0.22 9.4.0.5
```

This will output JSON for each version sequentially.

### Processing Multiple Products

Use a shell script to process multiple products:

```bash
#!/bin/bash

# Process IBM products
python main.py --vendor ibm --product mq --base-version 9.3 --fix-version 9.3.0.22
python main.py --vendor ibm --product websphere --base-version 9.0.5 --fix-version 9.0.5.18
python main.py --vendor ibm --product db2 --base-version 12.1 --fix-version 12.1.0.2

# Process Apache products
python main.py --vendor apache --product tomcat --base-version 10.1 --fix-version 10.1.28

# Process Oracle products
python main.py --vendor oracle --product "mysql server" --base-version 8.0 --fix-version 8.0.40
```

### Saving Output to Files

```bash
# Save to individual files
python main.py \
  --vendor ibm \
  --product mq \
  --base-version 9.3 \
  --fix-version 9.3.0.22 \
  > ibm_mq_9.3.json

# Append to a combined file
python main.py \
  --vendor ibm \
  --product mq \
  --base-version 9.3 \
  --fix-version 9.3.0.22 \
  >> all_vulnerabilities.json
```

---

## Programmatic Usage

### Using as a Python Module

```python
from main import run_pipeline

# Query vulnerability data
result = run_pipeline(
    vendor="ibm",
    product="mq",
    base_version="9.3",
    fix_version="9.3.0.22"
)

# Access result fields
print(f"CVEs: {result['cve_id']}")
print(f"Severity: {result['severity']}")
print(f"Published: {result['published_date']}")
```

### Using Factory Directly

```python
from factory import StrategyFactory

# Get strategy for specific vendor/product
strategy = StrategyFactory.get_strategy(
    vendor_name="ibm",
    product_name="mq",
    base_version="9.3"
)

# Process vulnerability data
vulnerability = strategy.process(
    product="mq",
    base_version="9.3",
    fix_version="9.3.0.22"
)

# Access Vulnerability object
print(vulnerability.cve_id)
print(vulnerability.severity)
print(vulnerability.model_dump_json(indent=2))
```

### Custom Processing Pipeline

```python
from factory import StrategyFactory
from models import Vulnerability
import json

def get_vulnerabilities_for_versions(vendor, product, versions):
    """Get vulnerabilities for multiple versions."""
    results = []
    
    for base_version, fix_version in versions:
        try:
            strategy = StrategyFactory.get_strategy(
                vendor_name=vendor,
                product_name=product,
                base_version=base_version
            )
            
            vuln = strategy.process(
                product=product,
                base_version=base_version,
                fix_version=fix_version
            )
            
            results.append(vuln.model_dump())
            
        except ValueError as e:
            print(f"Error processing {base_version}: {e}")
            continue
    
    return results

# Usage
versions = [
    ("9.1", "9.1.0.25"),
    ("9.2", "9.2.0.18"),
    ("9.3", "9.3.0.22")
]

vulnerabilities = get_vulnerabilities_for_versions(
    vendor="ibm",
    product="mq",
    versions=versions
)

# Save to file
with open("mq_vulnerabilities.json", "w") as f:
    json.dump(vulnerabilities, f, indent=2)
```

### Filtering by Severity

```python
from factory import StrategyFactory

def get_high_severity_vulns(vendor, product, base_version, fix_version):
    """Get only high/critical severity vulnerabilities."""
    strategy = StrategyFactory.get_strategy(vendor, product, base_version)
    vuln = strategy.process(product, base_version, fix_version)
    
    if vuln.severity in ["Critical", "High"]:
        return vuln
    return None

# Usage
vuln = get_high_severity_vulns("ibm", "mq", "9.3", "9.3.0.22")
if vuln:
    print(f"High severity vulnerability found: {vuln.cve_id}")
```

---

## AutoPkg Integration

### Basic AutoPkg Recipe

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
    <string>Fetch CVE metadata for IBM MQ</string>
    
    <key>Identifier</key>
    <string>com.example.ibm.mq.metadata</string>
    
    <key>Input</key>
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
    
    <key>Process</key>
    <array>
        <dict>
            <key>Processor</key>
            <string>CveMetadataFetcher</string>
            <key>Arguments</key>
            <dict>
                <key>vendor</key>
                <string>%vendor%</string>
                <key>product</key>
                <string>%product%</string>
                <key>base_version</key>
                <string>%base_version%</string>
                <key>fix_version</key>
                <string>%fix_version%</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>
```

### Using with Other Processors

```xml
<key>Process</key>
<array>
    <!-- Download software -->
    <dict>
        <key>Processor</key>
        <string>URLDownloader</string>
        <key>Arguments</key>
        <dict>
            <key>url</key>
            <string>https://example.com/software.zip</string>
        </dict>
    </dict>
    
    <!-- Fetch CVE metadata -->
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
    
    <!-- Use metadata in subsequent processors -->
    <dict>
        <key>Processor</key>
        <string>SomeOtherProcessor</string>
        <key>Arguments</key>
        <dict>
            <key>cve_info</key>
            <string>%cve_id%</string>
            <key>severity</key>
            <string>%severity%</string>
        </dict>
    </dict>
</array>
```

---

## Advanced Scenarios

### Custom Parser Implementation

```python
from strategies.base import PageParser
from models import Vulnerability
from bs4 import BeautifulSoup
from typing import List
import re

class CustomProductParser(PageParser):
    """Custom parser for a specific product."""
    
    def parse(self, content: str, context: dict) -> Vulnerability:
        soup = BeautifulSoup(content, 'html.parser')
        
        # Extract CVEs using regex
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
        cve_ids = list(set(cve_pattern.findall(content)))
        
        # Extract severity from specific element
        severity_elem = soup.find('span', class_='severity')
        severity = severity_elem.text.strip() if severity_elem else "Unknown"
        
        # Extract date
        date_elem = soup.find('time', class_='published')
        published_date = date_elem.get('datetime') if date_elem else None
        
        # Build source IDs
        fix_version = context['product_fix_version']
        source_ids = [f"{fix_version}-{cve}" for cve in cve_ids]
        
        return Vulnerability(
            cve_id=cve_ids,
            severity=severity,
            published_date=published_date,
            vendor=context.get('vendor', 'unknown'),
            product=context['product'],
            product_base_version=context['base_version'],
            product_fix_version=fix_version,
            source_id=source_ids
        )

# Register and use
from factory import StrategyFactory
StrategyFactory._PARSERS['Custom_parser'] = CustomProductParser
```

### Handling Multiple CVEs

```python
from factory import StrategyFactory

def get_all_cves_for_product(vendor, product, versions):
    """Collect all CVEs across multiple versions."""
    all_cves = set()
    
    for base_version, fix_version in versions:
        strategy = StrategyFactory.get_strategy(vendor, product, base_version)
        vuln = strategy.process(product, base_version, fix_version)
        all_cves.update(vuln.cve_id)
    
    return sorted(all_cves)

# Usage
versions = [("9.1", "9.1.0.25"), ("9.2", "9.2.0.18"), ("9.3", "9.3.0.22")]
cves = get_all_cves_for_product("ibm", "mq", versions)
print(f"Total unique CVEs: {len(cves)}")
print(f"CVEs: {', '.join(cves)}")
```

### Comparing Versions

```python
from factory import StrategyFactory

def compare_versions(vendor, product, version_pairs):
    """Compare vulnerabilities between versions."""
    for base_version, fix_version in version_pairs:
        strategy = StrategyFactory.get_strategy(vendor, product, base_version)
        vuln = strategy.process(product, base_version, fix_version)
        
        print(f"\n{product} {base_version} -> {fix_version}")
        print(f"  CVEs: {len(vuln.cve_id)}")
        print(f"  Severity: {vuln.severity}")
        print(f"  Published: {vuln.published_date}")

# Usage
compare_versions("ibm", "mq", [
    ("9.1", "9.1.0.25"),
    ("9.2", "9.2.0.18"),
    ("9.3", "9.3.0.22")
])
```

---

## Error Handling

### Handling Unsupported Vendors

```python
from factory import StrategyFactory

try:
    strategy = StrategyFactory.get_strategy(
        vendor_name="unsupported_vendor",
        product_name="some_product",
        base_version="1.0"
    )
except ValueError as e:
    print(f"Error: {e}")
    # Output: Error: Vendor 'unsupported_vendor' is not supported.
```

### Handling Unsupported Versions

```python
try:
    strategy = StrategyFactory.get_strategy(
        vendor_name="ibm",
        product_name="mq",
        base_version="8.0"  # Not supported
    )
except ValueError as e:
    print(f"Error: {e}")
    # Output: Error: Version 8.0 is not supported for mq. 
    #         Supported versions are: 9.1, 9.2, 9.3, 9.4
```

### Graceful Error Handling

```python
from factory import StrategyFactory
import sys

def safe_process(vendor, product, base_version, fix_version):
    """Process with comprehensive error handling."""
    try:
        strategy = StrategyFactory.get_strategy(vendor, product, base_version)
        vuln = strategy.process(product, base_version, fix_version)
        return vuln.model_dump()
        
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return None
        
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return None

# Usage
result = safe_process("ibm", "mq", "9.3", "9.3.0.22")
if result:
    print("Success:", result)
else:
    print("Failed to process")
```

---

## Output Formats

### JSON Output (Default)

```bash
python main.py --vendor ibm --product mq --base-version 9.3 --fix-version 9.3.0.22
```

### Pretty-Printed JSON

```python
from main import run_pipeline
import json

result = run_pipeline("ibm", "mq", "9.3", "9.3.0.22")
print(json.dumps(result, indent=2, sort_keys=True))
```

### CSV Output

```python
from factory import StrategyFactory
import csv

def export_to_csv(vendor, product, versions, filename):
    """Export vulnerabilities to CSV."""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Vendor', 'Product', 'Base Version', 'Fix Version',
            'CVE IDs', 'Severity', 'Published Date', 'Source IDs'
        ])
        
        for base_version, fix_version in versions:
            strategy = StrategyFactory.get_strategy(vendor, product, base_version)
            vuln = strategy.process(product, base_version, fix_version)
            
            writer.writerow([
                vuln.vendor,
                vuln.product,
                vuln.product_base_version,
                vuln.product_fix_version,
                '; '.join(vuln.cve_id),
                vuln.severity,
                vuln.published_date or 'N/A',
                '; '.join(vuln.source_id)
            ])

# Usage
versions = [("9.1", "9.1.0.25"), ("9.2", "9.2.0.18"), ("9.3", "9.3.0.22")]
export_to_csv("ibm", "mq", versions, "mq_vulnerabilities.csv")
```

### Markdown Report

```python
from factory import StrategyFactory

def generate_markdown_report(vendor, product, versions):
    """Generate a markdown report."""
    report = f"# Vulnerability Report: {vendor.upper()} {product.upper()}\n\n"
    
    for base_version, fix_version in versions:
        strategy = StrategyFactory.get_strategy(vendor, product, base_version)
        vuln = strategy.process(product, base_version, fix_version)
        
        report += f"## Version {base_version} → {fix_version}\n\n"
        report += f"- **Severity**: {vuln.severity}\n"
        report += f"- **Published**: {vuln.published_date or 'N/A'}\n"
        report += f"- **CVEs**: {', '.join(vuln.cve_id)}\n"
        report += f"- **Source IDs**: {', '.join(vuln.source_id)}\n\n"
    
    return report

# Usage
versions = [("9.3", "9.3.0.22")]
report = generate_markdown_report("ibm", "mq", versions)
print(report)

# Save to file
with open("vulnerability_report.md", "w") as f:
    f.write(report)
```

---

## Tips and Best Practices

### 1. Check Supported Versions First

```python
from registry import PRODUCT_REGISTRY

vendor = "ibm"
product = "mq"

supported = PRODUCT_REGISTRY['vendors'][vendor]['software'][product]['supported_versions']
print(f"Supported versions for {vendor} {product}: {', '.join(supported)}")
```

### 2. Use Timeouts for Network Requests

The framework uses 15-second timeouts by default. Adjust if needed in vendor strategies.

### 3. Cache Results

```python
import json
from pathlib import Path

def cached_query(vendor, product, base_version, fix_version, cache_dir="cache"):
    """Query with file-based caching."""
    cache_path = Path(cache_dir)
    cache_path.mkdir(exist_ok=True)
    
    cache_file = cache_path / f"{vendor}_{product}_{base_version}_{fix_version}.json"
    
    if cache_file.exists():
        with open(cache_file) as f:
            return json.load(f)
    
    from main import run_pipeline
    result = run_pipeline(vendor, product, base_version, fix_version)
    
    with open(cache_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    return result
```

### 4. Validate Output

```python
from models import Vulnerability

def validate_result(result_dict):
    """Validate result dictionary."""
    try:
        vuln = Vulnerability(**result_dict)
        return True, "Valid"
    except Exception as e:
        return False, str(e)

# Usage
from main import run_pipeline
result = run_pipeline("ibm", "mq", "9.3", "9.3.0.22")
is_valid, message = validate_result(result)
print(f"Validation: {message}")
```

---

For more examples and use cases, see the test suite in the `tests/` directory.
