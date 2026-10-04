"""
CloudGuard prioritization scoring.

The scores defined here are deterministic
prioritization weights used to order security
findings and attack paths. They are NOT
statistical probabilities and do not claim to
represent real-world breach likelihood.

Keeping the values in one module ensures the
finding engine, attack-path explanations, and
remediation simulation all describe the same
condition with the same score.
"""


ATTACK_PATH_TO_SENSITIVE_SCORE = 95
"""
Score for an internet-originated relationship
chain that reaches a resource classified as
sensitive.
"""

INTERNET_EXPOSED_WORKLOAD_SCORE = 80
"""
Score for a workload that is directly reachable
from the public internet.
"""


def severity_from_score(
    score: int,
) -> str:
    if score >= 90:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "INFO"
