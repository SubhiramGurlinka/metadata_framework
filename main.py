# main.py
import argparse
import sys
from factory import StrategyFactory
from models import Vulnerability
from typing import List

# def run_pipeline(product: str, base_version: str, fix_version: str):
#     """
#     Orchestrates the scraping workflow for a specific product.
#     """
#     try:
#         print(f"[*] Initializing pipeline for {product} (Base: {base_version}, Fix: {fix_version})...")
        
#         # 1. Get the appropriate Strategy from the Factory
#         strategy = StrategyFactory.get_strategy(product)
#         print("The stratergy is ", strategy)
#         # 2. Get the target URL for this specific version
#         url = StrategyFactory.get_urls(product, base_version)
        
#         print(f"[*] Fetching data from: {url}")

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
        
        # Filter for the specific fix version if requested
        # This assumes your scrapers return all vulnerabilities for that base version
        # filtered_results = [
        #     v for v in results if v.product_fix_version == fix_version
        # ]
        # print(f"[+] Successfully found {len(filtered_results)} entries.")
        # for vuln in filtered_results:
        #     print(f" - {vuln.cve_id}: {vuln.severity} (Source: {vuln.source_id})")

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