"""
AdaptiveShield Internal Malicious Insider Threat Detection Module.

Exports the active 35-feature universal behavioral telemetry dataset extractor,
rule fallback logic, ML Random Forest inference pipeline, live reinforcement
feedback loop, and the AdaptiveInsiderDetector runtime bridge.
"""

from .internal_insider_dataset import (
    FEATURE_COLUMNS,
    extract_features,
    determine_label,
)
from .internal_insider_inference import (
    load_internal_insider_model,
    predict_session_risk,
    record_live_feedback,
)
from .insider_adapter import AdaptiveInsiderDetector
from .corporate_directory import CorporateDirectory

__all__ = [
    # Feature engineering & decision rules
    "FEATURE_COLUMNS",
    "extract_features",
    "determine_label",

    # Model loading & inference
    "load_internal_insider_model",
    "predict_session_risk",
    "record_live_feedback",

    # Runtime bridge
    "AdaptiveInsiderDetector",
    "CorporateDirectory",
]
