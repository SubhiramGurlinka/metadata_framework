from pydantic import BaseModel, Field, HttpUrl, field_validator
from datetime import datetime
from typing import List, Optional
import re

class Vulnerability(BaseModel):
    cve_id: List[str] = Field(..., description="List of CVE identifiers")
    severity: str
    published_date: Optional[str] = None
    vendor: str
    product: str
    product_base_version: str
    product_fix_version: str
    source_id: Optional[str] = None

    @field_validator("published_date")
    @classmethod
    def validate_date_format(cls, v):
        if v is None:
            return v

        # Step 1 — exact format check
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            raise ValueError("published_date must be in YYYY-MM-DD format")

        # Step 2 — real date check
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError("published_date is not a valid calendar date")

        return v
    class Config:
        frozen = True  # Makes instances immutable