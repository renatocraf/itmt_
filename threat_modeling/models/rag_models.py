"""Pydantic models for RAG enhancement responses (NIST control selection)."""
from pydantic import BaseModel, Field
from typing import List


class RAGResponse(BaseModel):
    """
    Structured RAG LLM response: list of NIST control titles for a threat.

    Used with invoke_with_structure to ensure consistent output across providers.
    """
    nist_controls: List[str] = Field(
        ...,
        description="List of NIST control titles recommended for the threat",
        min_length=0
    )

    class Config:
        """Pydantic model configuration (json_schema_extra)."""
        json_schema_extra = {
            "example": {
                "nist_controls": [
                    "AC-3 Access Enforcement",
                    "AC-4 Information Flow Enforcement",
                    "SC-7 Boundary Protection"
                ]
            }
        }

