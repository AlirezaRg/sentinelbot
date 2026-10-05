"""Output contract for an analysis. Anything a model returns must validate against these models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AnalysisDraft(BaseModel):
    """What the model is asked to produce. Strict: unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=800)
    why_suspicious: list[str] = Field(default_factory=list, max_length=10)
    severity_assessment: str = Field(min_length=1, max_length=400)
    evidence: list[str] = Field(default_factory=list, max_length=20)
    false_positive_explanations: list[str] = Field(default_factory=list, max_length=10)
    investigation_steps: list[str] = Field(default_factory=list, max_length=10)
    remediation: list[str] = Field(default_factory=list, max_length=10)
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_note: str = Field(min_length=1, max_length=400)


class AnalysisResult(AnalysisDraft):
    """The draft after the server checked it: the provider used and whether it fell back."""

    provider: Literal["rules", "anthropic"]
    fallback_reason: str | None = None
