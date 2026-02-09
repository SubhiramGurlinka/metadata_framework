from strategies.vendor.apache import ApacheVendorStrategy
from strategies.vendor.ibm import IBMVendorStrategy
# from strategies.vendor.redhat import RedHatVendorStrategy
from strategies.parsers.ibm_mq_parsers import IBMMQTableParser
from strategies.parsers.ibm_websphere_parser import IBMWebSphereTableParser
from strategies.parsers.apache_tomcat_parser import ApacheTomcatParser
# from strategies.parsers.redhat_parsers import RedHatUnifiedParser
from registry import PRODUCT_REGISTRY

class StrategyFactory:
    _PARSERS = {
        "IBM_mq_fixpack_parser": IBMMQTableParser, # Mapping specific IDs to classes
        "IBM_websphere_fixpack_parser": IBMWebSphereTableParser,
        "Apache_tomcat_parser": ApacheTomcatParser,
        # "RedHatUnifiedParser": RedHatUnifiedParser
    }

    _VENDORS = {
        "ibm": IBMVendorStrategy,
        "apache": ApacheVendorStrategy,
        # "redhat": RedHatVendorStrategy
    }

    @classmethod
    def get_strategy(cls, vendor_name: str, product_name: str, base_version: str):
        vendor_cfg = PRODUCT_REGISTRY['vendors'].get(vendor_name.lower())
        if not vendor_cfg:
            raise ValueError(f"Vendor '{vendor_name}' is not supported.")

        software_cfg = vendor_cfg['software'].get(product_name.lower())
        if not software_cfg:
            raise ValueError(f"Product '{product_name}' is not supported for {vendor_name}.")

        # --- Version Validation ---
        if base_version not in software_cfg.get("supported_versions", []):
            supported = ", ".join(software_cfg.get("supported_versions", []))
            raise ValueError(
                f"Version {base_version} is not supported for {product_name}. "
                f"Supported versions are: {supported}"
            )

        parser_key = software_cfg.get("parser_type") or vendor_cfg.get("default_parser_type")
        return cls._VENDORS[vendor_name.lower()](parser=cls._PARSERS[parser_key]())

    @classmethod
    def get_url(cls, vendor_name: str, product_name: str, base_version: str) -> str:
        # Assumes validation was already done by get_strategy
        software_cfg = PRODUCT_REGISTRY['vendors'][vendor_name]['software'][product_name]
        return software_cfg['base_urls'].get(base_version)