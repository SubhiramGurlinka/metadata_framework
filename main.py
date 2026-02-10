# main.py
import argparse
import sys
from factory import StrategyFactory
from models import Vulnerability
from typing import List

def run_pipeline(vendor: str, product: str, base_version: str, fix_version: str):
    try:
        # Pass both vendor and product to factory
        strategy = StrategyFactory.get_strategy(vendor, product, base_version)
        url = StrategyFactory.get_url(vendor, product, base_version)
        
        print(f"[*] Scraping {vendor} {product} via {url}...")

        results: List[Vulnerability] = strategy.process(
            product=product, 
            base_version=base_version,
            fix_version=args.fix_version
        )
        print(results)
    
    except ValueError as ve:
        print(f"[!] Configuration Error: {ve}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability Metadata Scraper Framework")
    
    parser.add_argument("--product", required=True, help="Name of the product (e.g., mq, websphere)")
    parser.add_argument("--vendor", required=True, help="Name of the vendor (e.g., ibm, redhat)")
    parser.add_argument("--base-version", required=True, help="Product base version (e.g., 9.1, 8.5.5)")
    parser.add_argument("--fix-version", required=True, help="Specific fix version to target")

    args = parser.parse_args()

    run_pipeline(
        product=args.product,
        base_version=args.base_version,
        fix_version=args.fix_version,
        vendor=args.vendor
    )