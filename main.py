#!/usr/bin/env python3
"""
Vulnerability Framework - Main Entry Point

This script orchestrates the vulnerability extraction pipeline:
1. Query the registry for product metadata
2. Get the appropriate vendor strategy from the factory
3. Process the product page to extract vulnerabilities
4. Save the results to the repository
"""

import sys
from typing import List

from registry import ProductRegistry
from factory import VendorStrategyFactory
from repository import VulnerabilityRepository
from models import Vulnerability


class VulnerabilityPipeline:
    """Main pipeline for processing vulnerability data"""
    
    def __init__(self):
        self.registry = ProductRegistry()
        self.factory = VendorStrategyFactory()
        self.repository = VulnerabilityRepository()
    
    def process_product(self, product_key: str, version: str, custom_url: str = None) -> List[Vulnerability]:
        """
        Process a product and extract vulnerabilities
        
        Args:
            product_key: Product identifier in the registry
            version: Product version to process
            custom_url: Optional custom URL (overrides registry URL)
            
        Returns:
            List of extracted Vulnerability objects
        """
        print(f"\n{'=' * 60}")
        print(f"Processing: {product_key} version {version}")
        print(f"{'=' * 60}\n")
        
        # Step 1: Get product metadata from registry
        print(f"[1/4] Querying registry for {product_key}...")
        metadata = self.registry.get(product_key)
        if not metadata:
            raise ValueError(f"Product '{product_key}' not found in registry")
        
        print(f"      Vendor: {metadata.vendor}")
        print(f"      Product: {metadata.product}")
        print(f"      Page Type: {metadata.page_type}")
        
        # Step 2: Get vendor strategy from factory
        print(f"\n[2/4] Getting vendor strategy for '{metadata.vendor}'...")
        vendor_strategy = self.factory.get_strategy(metadata.vendor)
        print(f"      Strategy: {vendor_strategy.__class__.__name__}")
        
        # Step 3: Process the product page
        print(f"\n[3/4] Processing product page...")
        url = custom_url or metadata.get_url(version)
        if not url:
            raise ValueError(f"No URL available for {product_key}")
        
        print(f"      URL: {url}")
        vulnerabilities = vendor_strategy.process(metadata.product, version, url)
        print(f"      Found {len(vulnerabilities)} vulnerabilities")
        
        # Step 4: Save results
        print(f"\n[4/4] Saving results...")
        filename = f"{product_key}_{version}".replace(".", "_")
        self.repository.save(vulnerabilities, filename)
        self.repository.save_summary(vulnerabilities, filename)
        
        print(f"\n{'=' * 60}")
        print(f"✓ Processing complete!")
        print(f"{'=' * 60}\n")
        
        return vulnerabilities
    
    def list_products(self):
        """List all available products in the registry"""
        print("\nAvailable Products:")
        print("=" * 60)
        
        for vendor in self.factory.list_vendors():
            products = self.registry.list_by_vendor(vendor)
            if products:
                print(f"\n{vendor.upper()}:")
                for product_key in products:
                    metadata = self.registry.get(product_key)
                    versions = metadata.supported_versions or ["all"]
                    print(f"  - {product_key} (versions: {', '.join(versions)})")
        
        print()


def main():
    """Main entry point"""
    pipeline = VulnerabilityPipeline()
    
    # Example usage: Process multiple products
    examples = [
        ("tomcat-9", "9.0.109"),
        ("ibm-mq", "9.1.0.33"),
        ("websphere", "8.5.5.28"),
        ("db2", "12.1.2"),
    ]
    
    print("\n" + "=" * 60)
    print("Vulnerability Framework - Processing Pipeline")
    print("=" * 60)
    
    # Show available products
    pipeline.list_products()
    
    # Process each example
    for product_key, version in examples:
        try:
            vulnerabilities = pipeline.process_product(product_key, version)
        except Exception as e:
            print(f"✗ Error processing {product_key}: {e}\n")
            continue


if __name__ == "__main__":
    main()