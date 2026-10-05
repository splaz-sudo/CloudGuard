"""
CloudGuard configuration.

Configuration is read from environment variables
with documented defaults. No credentials are
stored in code. See .env.example for the
supported variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173,"
    "http://127.0.0.1:5173,"
    "http://localhost:5174,"
    "http://127.0.0.1:5174"
)


@dataclass(frozen=True)
class Settings:
    # development | test | production
    environment: str = "development"

    # SQLite file path, or :memory:
    database_path: str = "cloudguard.db"

    cors_origins: tuple[str, ...] = field(
        default=(
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
        )
    )

    # When set, API requests must present this
    # token via the X-API-Key header. Empty
    # means open local mode (development only).
    api_key: str = ""

    aws_profile: str = ""
    aws_regions: tuple[str, ...] = ()

    # Cross-account scanning configuration
    # Format: "account_id:role_arn:external_id:session_name"
    # Multiple accounts separated by semicolons
    aws_cross_account_roles: str = ""

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def parse_cross_account_roles(self) -> list[dict]:
        """Parse cross-account role configuration string."""
        if not self.aws_cross_account_roles:
            return []

        roles = []
        for entry in self.aws_cross_account_roles.split(";"):
            entry = entry.strip()
            if not entry:
                continue

            parts = entry.split(":")
            if len(parts) < 2:
                continue

            roles.append({
                "account_id": parts[0].strip(),
                "role_arn": parts[1].strip(),
                "external_id": parts[2].strip() if len(parts) > 2 else None,
                "session_name": parts[3].strip() if len(parts) > 3 else "CloudGuardScan",
            })

        return roles


def load_settings() -> Settings:
    cors_raw = os.getenv(
        "CLOUDGUARD_CORS_ORIGINS",
        DEFAULT_CORS_ORIGINS,
    )

    cors_origins = tuple(
        origin.strip()
        for origin in cors_raw.split(",")
        if origin.strip()
    )

    regions_raw = os.getenv(
        "CLOUDGUARD_AWS_REGIONS",
        "",
    )

    aws_regions = tuple(
        region.strip()
        for region in regions_raw.split(",")
        if region.strip()
    )

    return Settings(
        environment=os.getenv(
            "CLOUDGUARD_ENV",
            "development",
        ),
        database_path=os.getenv(
            "CLOUDGUARD_DATABASE_PATH",
            "cloudguard.db",
        ),
        cors_origins=cors_origins,
        api_key=os.getenv(
            "CLOUDGUARD_API_KEY",
            "",
        ),
        aws_profile=os.getenv(
            "CLOUDGUARD_AWS_PROFILE",
            "",
        ),
        aws_regions=aws_regions,
    )
