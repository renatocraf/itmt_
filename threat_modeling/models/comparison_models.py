"""Pydantic models for threat comparison responses (TMT vs AI)."""
from pydantic import BaseModel, Field
from typing import Optional


class ThreatComparisonResponse(BaseModel):
    """
    Structured LLM response when comparing two threat descriptions (similarity + explanation).

    Used with invoke_with_structure for consistent comparison output across providers.
    """
    is_similar: bool = Field(
        ...,
        description="Whether the two threat descriptions are similar (True) or different (False)"
    )
    similarity_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Similarity score between 0.0 (completely different) and 1.0 (identical)"
    )
    explanation: str = Field(
        ...,
        description="Explanation of why the threats are considered similar or different"
    )

    class Config:
        """Pydantic model configuration (json_schema_extra)."""
        json_schema_extra = {
            "example": {
                "is_similar": True,
                "similarity_score": 0.85,
                "explanation": "Both threats describe unauthorized access attempts. The TMT threat focuses on credential theft, while the AI threat emphasizes privilege escalation, but they address the same core security concern."
            }
        }

