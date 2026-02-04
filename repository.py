import json
from typing import List
from pathlib import Path
from models import Vulnerability


class VulnerabilityRepository:
    """Repository for storing vulnerability data"""
    
    def __init__(self, output_dir: str = "output"):
        """
        Initialize the repository
        
        Args:
            output_dir: Directory to store output files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def save(self, vulnerabilities: List[Vulnerability], filename: str):
        """
        Save vulnerabilities to a JSON file
        
        Args:
            vulnerabilities: List of Vulnerability objects
            filename: Output filename (without extension)
        """
        filepath = self.output_dir / f"{filename}.json"
        
        # Convert to dictionaries
        data = [self._to_dict(v) for v in vulnerabilities]
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"Saved {len(vulnerabilities)} vulnerabilities to {filepath}")
    
    def _to_dict(self, vuln: Vulnerability) -> dict:
        """Convert Vulnerability to dictionary"""
        return {
            "cve_id": vuln.cve_id,
            "severity": vuln.severity,
            "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
            "vendor": vuln.vendor,
            "product": vuln.product,
            "source_id": vuln.source_id,
            "cvss": vuln.cvss
        }
    
    def save_summary(self, vulnerabilities: List[Vulnerability], filename: str):
        """
        Save a summary report of vulnerabilities
        
        Args:
            vulnerabilities: List of Vulnerability objects
            filename: Output filename (without extension)
        """
        filepath = self.output_dir / f"{filename}_summary.txt"
        
        # Calculate statistics
        severity_counts = {}
        for v in vulnerabilities:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
        
        with open(filepath, 'w') as f:
            f.write(f"Vulnerability Summary Report\n")
            f.write(f"{'=' * 50}\n\n")
            f.write(f"Total Vulnerabilities: {len(vulnerabilities)}\n\n")
            
            if vulnerabilities:
                f.write(f"Product: {vulnerabilities[0].product}\n")
                f.write(f"Vendor: {vulnerabilities[0].vendor}\n")
                if vulnerabilities[0].source_id:
                    f.write(f"Version: {vulnerabilities[0].source_id}\n")
                f.write(f"\n")
            
            f.write(f"Severity Breakdown:\n")
            for severity, count in sorted(severity_counts.items()):
                f.write(f"  {severity}: {count}\n")
            
            f.write(f"\n{'=' * 50}\n\n")
            f.write(f"CVE List:\n")
            for v in vulnerabilities:
                for cve in v.cve_id:
                    cvss_str = f" (CVSS: {v.cvss})" if v.cvss else ""
                    f.write(f"  {cve} - {v.severity}{cvss_str}\n")
        
        print(f"Saved summary to {filepath}")