# state_manager/models.py

from typing import Dict, Any

from models import Vulnerability

class StateVulnerability(Vulnerability):
    """
    Thin wrapper around the canonical Vulnerability model.

    This ensures:
    - Same validation rules
    - Same normalization
    - No model drift
    - Single source of truth
    """

    def to_state_dict(self) -> Dict[str, Any]:
        """
        Return only the fields that are persisted in pre_state.json.
        The fix_version is stored as the key in the state tree,
        so it is not duplicated in the stored payload.
        """

        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "published_date": self.published_date,
            "source_id": self.source_id,
        }

    @classmethod
    def from_framework_output(cls, data: Dict[str, Any]) -> "StateVulnerability":
        """
        Validate and normalize framework output using
        the canonical Vulnerability model.
        """

        return cls.model_validate(data)