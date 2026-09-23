from cloudguard.models.assets import (
    AssetType,
    CloudAsset,
)


class ResourceClassifier:
    """
    Classifies cloud resources for security analysis.

    Explicit security metadata takes precedence over
    heuristic name-based classification.
    """

    SENSITIVE_KEYWORDS = {
        "backup",
        "backups",
        "customer",
        "customers",
        "database",
        "db",
        "finance",
        "financial",
        "payroll",
        "private",
        "prod",
        "production",
        "secret",
        "secrets",
    }

    TRUE_VALUES = {
        "true",
        "yes",
        "1",
        "sensitive",
    }

    def classify(
        self,
        assets: list[CloudAsset],
    ) -> list[CloudAsset]:
        for asset in assets:
            asset.sensitive = (
                self._is_sensitive(asset)
            )

        return assets

    def _is_sensitive(
        self,
        asset: CloudAsset,
    ) -> bool:
        if asset.sensitive:
            return True

        explicit_classification = (
            self._explicit_classification(
                asset
            )
        )

        if explicit_classification is not None:
            return explicit_classification

        if asset.asset_type == (
            AssetType.SECRET
        ):
            return True

        if asset.asset_type == (
            AssetType.S3_BUCKET
        ):
            return self._s3_name_is_sensitive(
                asset
            )

        return False

    def _explicit_classification(
        self,
        asset: CloudAsset,
    ) -> bool | None:
        sensitive_tag = (
            self._get_tag_value(
                asset,
                "CloudGuardSensitive",
            )
        )

        if sensitive_tag is not None:
            return (
                sensitive_tag
                .strip()
                .lower()
                in self.TRUE_VALUES
            )

        classification_tag = (
            self._get_tag_value(
                asset,
                "DataClassification",
            )
        )

        if classification_tag is not None:
            value = (
                classification_tag
                .strip()
                .lower()
            )

            if value in {
                "confidential",
                "restricted",
                "sensitive",
                "secret",
            }:
                return True

            if value in {
                "public",
                "internal",
            }:
                return False

        return None

    def _get_tag_value(
        self,
        asset: CloudAsset,
        tag_name: str,
    ) -> str | None:
        expected_key = (
            f"tag:{tag_name}"
            .lower()
        )

        for key, value in (
            asset.metadata.items()
        ):
            if key.lower() == expected_key:
                return value

        return None

    def _s3_name_is_sensitive(
        self,
        asset: CloudAsset,
    ) -> bool:
        name = asset.name.lower()

        normalized_name = (
            name.replace("-", " ")
            .replace("_", " ")
            .replace(".", " ")
        )

        words = set(
            normalized_name.split()
        )

        return bool(
            words
            & self.SENSITIVE_KEYWORDS
        )
