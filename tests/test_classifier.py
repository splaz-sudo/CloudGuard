from cloudguard.findings.classifier import (
    ResourceClassifier,
)
from cloudguard.models.assets import (
    AssetType,
    CloudAsset,
)


def test_customer_backup_bucket_is_sensitive():
    classifier = ResourceClassifier()

    assets = [
        CloudAsset(
            id="s3:customer-backups",
            name="customer-backups",
            asset_type=AssetType.S3_BUCKET,
        )
    ]

    classifier.classify(assets)

    assert assets[0].sensitive is True


def test_generic_bucket_is_not_sensitive():
    classifier = ResourceClassifier()

    assets = [
        CloudAsset(
            id="s3:website-assets",
            name="website-assets",
            asset_type=AssetType.S3_BUCKET,
        )
    ]

    classifier.classify(assets)

    assert assets[0].sensitive is False


def test_secret_is_sensitive():
    classifier = ResourceClassifier()

    assets = [
        CloudAsset(
            id="secret:database-password",
            name="database-password",
            asset_type=AssetType.SECRET,
        )
    ]

    classifier.classify(assets)

    assert assets[0].sensitive is True
