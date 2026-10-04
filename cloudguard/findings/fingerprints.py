"""
Deterministic finding fingerprints.

A fingerprint identifies a finding by its
meaningful security properties so the same
condition can be recognized across scans.
Fingerprints deliberately exclude volatile
data such as timestamps, scan IDs, and
enumeration order.

Inputs per finding type:

- network exposure:
    finding kind + affected workload identity

- attack path to sensitive resource:
    finding kind + ordered node identities
    (the same structural identity used for
    attack paths themselves)
"""

import hashlib


def _digest(kind: str, *parts: str) -> str:
    raw = "|".join((kind, *parts))

    return hashlib.sha1(
        raw.encode("utf-8")
    ).hexdigest()[:16]


def network_exposure_fingerprint(
    asset_id: str,
) -> str:
    return _digest(
        "network_exposure",
        asset_id,
    )


def attack_path_fingerprint(
    nodes: list[str],
) -> str:
    return _digest(
        "attack_path",
        ">".join(nodes),
    )
