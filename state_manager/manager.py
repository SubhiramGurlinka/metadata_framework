# state_manager/manager.py

import json
import os
import tempfile
from typing import Dict, Any

from state_manager.models import StateVulnerability


class StateManager:
    def __init__(self, state_file: str = "pre_state.json"):
        self.state_file = state_file

    # ================================
    # PUBLIC API
    # ================================

    def process(self, framework_output: dict):

        new_state = StateVulnerability.from_framework_output(framework_output)

        state = self._load_state()

        previous_state = self._get_previous_state(
            state,
            new_state.vendor,
            new_state.product,
            new_state.product_base_version,
            new_state.product_fix_version,
        )

        diff = self._calculate_diff(previous_state, new_state)

        self._update_state(state, new_state)

        self._enforce_retention(
            state,
            new_state.vendor,
            new_state.product,
            new_state.product_base_version,
        )

        self._save_state(state)

        return diff

    # ================================
    # INTERNAL
    # ================================

    def _load_state(self) -> Dict[str, Any]:
        if not os.path.exists(self.state_file):
            return {}

        with open(self.state_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_state(self, state: Dict[str, Any]) -> None:
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            encoding="utf-8",
            dir=os.path.dirname(self.state_file) or ".",
        ) as tmp:
            json.dump(state, tmp, indent=4)
            temp_name = tmp.name

        os.replace(temp_name, self.state_file)

    def _get_previous_state(
        self,
        state: Dict[str, Any],
        vendor: str,
        product: str,
        base_version: str,
        fix_version: str,
    ):

        try:
            data = state[vendor][product][base_version][fix_version]

            # IMPORTANT FIX: use model_validate instead of from_dict
            return StateVulnerability.model_validate({
                "vendor": vendor,
                "product": product,
                "product_base_version": base_version,
                "product_fix_version": fix_version,
                **data
            })

        except KeyError:
            return None

    def _calculate_diff(
        self,
        old: StateVulnerability | None,
        new: StateVulnerability,
    ):

        if old is None:
            return {"is_new": True, "changes": {}}

        changes = {}

        if old.severity != new.severity:
            changes["severity"] = {
                "old": old.severity,
                "new": new.severity,
            }

        old_cves = set(old.cve_id)
        new_cves = set(new.cve_id)

        added = list(new_cves - old_cves)
        removed = list(old_cves - new_cves)

        if added or removed:
            changes["cve_id"] = {
                "added": added,
                "removed": removed,
            }

        if old.published_date != new.published_date:
            changes["published_date"] = {
                "old": old.published_date,
                "new": new.published_date,
            }

        return {
            "is_new": False,
            "changes": changes,
        }

    def _update_state(
    self,
    state: dict,
    new_state: StateVulnerability,
    ):

        vendor = new_state.vendor
        product = new_state.product
        base_version = new_state.product_base_version
        fix_version = new_state.product_fix_version

        state.setdefault(vendor, {})
        state[vendor].setdefault(product, {})
        state[vendor][product].setdefault(base_version, {})

        # Persist only stored fields (not redundant version info)
        state[vendor][product][base_version][fix_version] = (
            new_state.to_state_dict()
        )

    # ================================
    # RETENTION POLICY (MAX 3 FIX VERSIONS)
    # ================================

    def _enforce_retention(
    self,
    state: dict,
    vendor: str,
    product: str,
    base_version: str,
    ):
        """
        Ensure that only the latest 3 fix_versions (n, n-1, n-2)
        are kept for each base_version.
        Older entries are automatically removed.
        """

        try:
            versions = state[vendor][product][base_version]
        except KeyError:
            return

        if len(versions) <= 3:
            return

        # Sort versions descending (latest first)
        sorted_versions = sorted(
            versions.keys(),
            key=lambda v: tuple(int(x) for x in v.split(".")),
            reverse=True,
        )

        # Keep only first 3
        keep = set(sorted_versions[:3])

        for fix_version in list(versions.keys()):
            if fix_version not in keep:
                del versions[fix_version]