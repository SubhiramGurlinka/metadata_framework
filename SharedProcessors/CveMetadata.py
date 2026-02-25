from autopkglib import Processor, ProcessorError

import os
import sys

# PROCESSOR_DIR = os.path.dirname(os.path.abspath(__file__))
# if PROCESSOR_DIR not in sys.path:
    # sys.path.insert(0, PROCESSOR_DIR)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

FRAMEWORK_DIR = os.path.abspath(
    os.path.join(CURRENT_DIR, "..", "..", "com.github.metadata")
)

if FRAMEWORK_DIR not in sys.path:
    sys.path.insert(0, FRAMEWORK_DIR)

from meta.main import run_pipeline

__all__ = ["CveMetadata"]

class CveMetadata(Processor):
    description = "Process cve metadata framework & adds to template dictionary."

    input_variables = {
        "vendor": {
            "required": True,
            "description": "Provide the vendor name",
        },
        "product": {
            "required": True,
            "description": "Provide the product name",
        },
        "base_version": {
            "required": True,
            "description": "Provide the product base version",
        },
        "fix_version": {
            "required": True,
            "description": "Provide the product latest patch/fix version",
        }
    }

    output_variables = {
        "dictionary_name": {"description": ("The appended dictionary name")},
        "dictionary_appended": {"description": ("The appended dictionary")},
    }

    def main(self):
        """Execution starts here"""

        # get the current dictionary
        dictionary_name = self.env.get("dictionary_name", "template_dictionary")
        dictionary_to_append = self.env.get(dictionary_name, {})

        self.output(f"dictionary_to_append: {dictionary_to_append}", 2)

        vendor = self.env.get("vendor")
        product = self.env.get("product")
        base_version = self.env.get("base_version")
        fix_version = self.env.get("fix_version")

        print("calling {vendor} - {product} - {base_version} - {fix_version}")
        # calling framework here
        result = run_pipeline(
            vendor=vendor,
            product=product,
            base_version=base_version,
            fix_version=fix_version
        )

        # ensure it is a dict
        dictionary_to_append = dict(dictionary_to_append)

        dictionary_to_append["severity"] = result["severity"]
        dictionary_to_append["cve_id"] = result["cve_id"]
        dictionary_to_append["source_id"] = result["source_id"]

        # write back the dict to itself
        self.env[dictionary_name] = dictionary_to_append
        self.env["dictionary_appended"] = dictionary_to_append

if __name__ == "__main__":
    PROCESSOR = CveMetadata()
    PROCESSOR.execute_shell()
