# main.py

import argparse
import sys
import json
from factory import StrategyFactory
from models import Vulnerability


def verify_result(result: Vulnerability):
    match, error = [], []
    with open("./validation.json", "r") as f:
        validation_data = json.load(f)
    
    vendor = result.vendor.lower()
    product = result.product.lower()
    product_details = validation_data[vendor][product][result.product_base_version]

    for item, value in product_details.items():
        if set(getattr(result,item)) == set(value):
            match.append(item)
        else:
            error.append(item)
    if error:
        print(f"[!] Mismatch in {error}")
    else:
        print("[*] Output Validation Complete")

def run_pipeline(vendor: str, product: str, base_version: str, fix_version: str):
    try:
        # Pass both vendor and product to factory
        strategy = StrategyFactory.get_strategy(vendor, product, base_version)
        url = strategy.get_url(base_version)
        
        # print(f"[*] Scraping {vendor} {product} via {url}...")

        results = strategy.process(
            product=product, 
            base_version=base_version,
            fix_version=fix_version
        )

        # if results:
        #     verify_result(results)
        print(results.model_dump_json(indent=4))

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
    # parser.add_argument("--base-version", required=True, help="Product base version (e.g., 9.1, 8.5.5)")
    # parser.add_argument("--fix-version", required=True, help="Specific fix version to target")
    parser.add_argument("--base-version", nargs="+", required=True, help="Product base version (e.g., 9.1, 8.5.5)")
    parser.add_argument("--fix-version", nargs="+", required=True, help="Specific fix version to target")

    args = parser.parse_args()

    for index in range(len(args.base_version)):
        run_pipeline(
            vendor=args.vendor,
            product=args.product,
            base_version=args.base_version[index],
            fix_version=args.fix_version[index]
        )