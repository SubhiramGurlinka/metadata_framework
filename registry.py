# # registry.py
# from typing import Dict, Any

# # This could eventually be moved to a YAML/JSON file
# PRODUCT_REGISTRY: Dict[str, Dict[str, Any]] = {
#     "mq": {
#         "vendor": "ibm",
#         "parser_type": "IBMTableParser",
#         "base_urls": {
#             "9.1": "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-91-lts",
#             "9.2": "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-92-lts",
#             "9.3": "https://www.ibm.com/support/pages/fix-list-ibm-mq-version-93-lts"
#         }
#     },
#     "websphere": {
#         "vendor": "ibm",
#         "parser_type": "IBMTableParser",
#         "base_urls": {
#             "8.5.5": "https://www.ibm.com/support/pages/fix-list-ibm-websphere-application-server-v85",
#             "9.0.5": "https://www.ibm.com/support/pages/fix-list-ibm-websphere-application-server-traditional-v9-0"
#         }
#     },
#     "rhel": {
#         "vendor": "redhat",
#         "parser_type": "RedHatUnifiedParser",
#         "base_urls": {
#             "all": "https://access.redhat.com/errata-search/"
#         }
#     }
# }
import json
from pathlib import Path
from typing import Dict, Any

REGISTRY_PATH = Path(__file__).parent / "registry.json"

def load_registry(path: Path = REGISTRY_PATH) -> Dict[str, Any]:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise e

with open(REGISTRY_PATH) as f:
    PRODUCT_REGISTRY: Dict[str, Any] = load_registry(REGISTRY_PATH)