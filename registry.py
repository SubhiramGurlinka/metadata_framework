# registry.py

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