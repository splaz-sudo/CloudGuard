"""
Performance benchmarks for CloudGuard components.

Tests measure execution time for key operations at various
asset scales to detect performance regressions.
"""

import time
import statistics
from dataclasses import dataclass

import pytest

from cloudguard.collectors.ec2 import EC2Instance, SecurityGroup, SecurityGroupRule
from cloudguard.collectors.iam import IAMRole, IAMPolicy, IAMPolicyStatement, InstanceProfile
from cloudguard.collectors.s3 import S3Bucket
from cloudguard.findings.classifier import ResourceClassifier
from cloudguard.findings.engine import FindingEngine
from cloudguard.graph.attack_paths import AttackPathEngine
from cloudguard.graph.aws_graph import AWSGraphBuilder
from cloudguard.graph.security_graph import SecurityGraph
from cloudguard.local_lab import LocalAWSLab
from cloudguard.normalizers.aws import AWSNormalizer
from cloudguard.remediation.engine import RemediationEngine
from cloudguard.remediation.simulator import RemediationSimulator
from cloudguard.remediation.service import RemediationService
from cloudguard.services.analysis import AnalysisService
from cloudguard.models.assets import AssetType, CloudAsset


@dataclass
class BenchmarkResult:
    name: str
    asset_count: int
    iterations: int
    mean_ms: float
    stdev_ms: float
    min_ms: float
    max_ms: float
    ops_per_second: float


def benchmark(
    name: str,
    func,
    asset_count: int,
    iterations: int = 10,
    warmup: int = 2,
) -> BenchmarkResult:
    """Run a benchmark multiple times and collect statistics."""
    # Warmup runs
    for _ in range(warmup):
        func()

    durations = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        durations.append((time.perf_counter() - start) * 1000)

    return BenchmarkResult(
        name=name,
        asset_count=asset_count,
        iterations=iterations,
        mean_ms=statistics.mean(durations),
        stdev_ms=statistics.stdev(durations) if len(durations) > 1 else 0.0,
        min_ms=min(durations),
        max_ms=max(durations),
        ops_per_second=(asset_count / statistics.mean(durations) * 1000)
        if statistics.mean(durations) > 0
        else 0,
    )


def create_test_environment(asset_count: int):
    """Create a test environment with the specified number of assets."""
    instances = []
    security_groups = []
    buckets = []
    roles = []
    instance_profiles = []

    # Distribute assets roughly evenly
    ec2_count = max(1, asset_count // 4)
    s3_count = max(1, asset_count // 4)
    iam_count = max(1, asset_count // 4)
    sg_count = max(1, asset_count // 8)

    for i in range(ec2_count):
        instances.append(EC2Instance(
            instance_id=f"i-{i:08d}",
            instance_type="t3.micro",
            state="running",
            region="us-east-1",
            public_ip=f"203.0.113.{i+1}" if i < 50 else None,
            private_ip=f"10.0.1.{i+1}",
            iam_instance_profile_arn=f"arn:aws:iam::123456789012:instance-profile/profile-{i}" if i < iam_count else None,
            security_group_ids=[f"sg-{i:08d}"],
        ))

    for i in range(sg_count):
        security_groups.append(SecurityGroup(
            group_id=f"sg-{i:08d}",
            group_name=f"sg-{i}",
            vpc_id="vpc-test",
            inbound_rules=[
                SecurityGroupRule(
                    protocol="tcp",
                    from_port=80,
                    to_port=80,
                    sources=["0.0.0.0/0"],
                ),
                SecurityGroupRule(
                    protocol="tcp",
                    from_port=443,
                    to_port=443,
                    sources=["0.0.0.0/0"],
                ),
            ],
        ))

    for i in range(s3_count):
        buckets.append(S3Bucket(
            name=f"bucket-{i}",
            region="us-east-1",
            public_access_block_enabled=True,
            policy_public=False,
            tags={"Name": f"bucket-{i}"},
        ))

    for i in range(iam_count):
        roles.append(IAMRole(
            name=f"role-{i}",
            arn=f"arn:aws:iam::123456789012:role/role-{i}",
            role_id=f"AROA{i:012d}",
            attached_policies=[],
        ))

    for i in range(min(iam_count, ec2_count)):
        instance_profiles.append(InstanceProfile(
            name=f"profile-{i}",
            arn=f"arn:aws:iam::123456789012:instance-profile/profile-{i}",
            role_names=[f"role-{i}"],
        ))

    return {
        "instances": instances,
        "security_groups": security_groups,
        "buckets": buckets,
        "roles": roles,
        "instance_profiles": instance_profiles,
    }


class TestNormalizationPerformance:
    """Benchmark asset normalization performance."""

    def test_normalization_10_assets(self):
        result = benchmark(
            "normalization",
            lambda: self._run_normalization(10),
            asset_count=10,
            iterations=20,
            warmup=5,
        )
        assert result.mean_ms < 10  # Should be very fast for 10 assets
        print(f"\nNormalization (10 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms, {result.ops_per_second:.0f} ops/sec")

    def test_normalization_100_assets(self):
        result = benchmark(
            "normalization",
            lambda: self._run_normalization(100),
            asset_count=100,
            iterations=10,
            warmup=3,
        )
        assert result.mean_ms < 50
        print(f"\nNormalization (100 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms, {result.ops_per_second:.0f} ops/sec")

    def test_normalization_1000_assets(self):
        result = benchmark(
            "normalization",
            lambda: self._run_normalization(1000),
            asset_count=1000,
            iterations=5,
            warmup=2,
        )
        assert result.mean_ms < 500
        print(f"\nNormalization (1000 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms, {result.ops_per_second:.0f} ops/sec")

    def _run_normalization(self, asset_count: int):
        env = create_test_environment(asset_count)
        normalizer = AWSNormalizer()
        classifier = ResourceClassifier()

        assets = []
        assets.extend(normalizer.normalize_ec2(env["instances"], "123456789012"))
        assets.extend(normalizer.normalize_s3(env["buckets"], "123456789012"))
        assets.extend(normalizer.normalize_roles(env["roles"], "123456789012"))
        assets.extend(normalizer.normalize_ec2(env["instances"], "123456789012"))  # duplicate for more assets
        assets = classifier.classify(assets)
        return assets


class TestGraphBuildingPerformance:
    """Benchmark security graph construction performance."""

    def test_graph_building_10_assets(self):
        result = benchmark(
            "graph_building",
            lambda: self._build_graph(10),
            asset_count=10,
            iterations=20,
            warmup=5,
        )
        assert result.mean_ms < 10
        print(f"\nGraph Building (10 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms")

    def test_graph_building_100_assets(self):
        result = benchmark(
            "graph_building",
            lambda: self._build_graph(100),
            asset_count=100,
            iterations=10,
            warmup=3,
        )
        assert result.mean_ms < 50
        print(f"\nGraph Building (100 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms")

    def test_graph_building_1000_assets(self):
        result = benchmark(
            "graph_building",
            lambda: self._build_graph(1000),
            asset_count=1000,
            iterations=5,
            warmup=2,
        )
        assert result.mean_ms < 1000
        print(f"\nGraph Building (1000 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms")

    def _build_graph(self, asset_count: int):
        env = create_test_environment(asset_count)
        normalizer = AWSNormalizer()
        classifier = ResourceClassifier()

        assets = []
        assets.extend(normalizer.normalize_ec2(env["instances"], "123456789012"))
        assets.extend(normalizer.normalize_s3(env["buckets"], "123456789012"))
        assets.extend(normalizer.normalize_roles(env["roles"], "123456789012"))
        assets = classifier.classify(assets)

        builder = AWSGraphBuilder()
        return builder.build(
            assets=assets,
            instances=env["instances"],
            security_groups=env["security_groups"],
            roles=env["roles"],
            instance_profiles=env["instance_profiles"],
        )


class TestAttackPathPerformance:
    """Benchmark attack path discovery performance."""

    def test_attack_path_10_assets(self):
        result = benchmark(
            "attack_path",
            lambda: self._find_attack_paths(10),
            asset_count=10,
            iterations=20,
            warmup=5,
        )
        assert result.mean_ms < 20
        print(f"\nAttack Path (10 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms")

    def test_attack_path_100_assets(self):
        result = benchmark(
            "attack_path",
            lambda: self._find_attack_paths(100),
            asset_count=100,
            iterations=10,
            warmup=3,
        )
        assert result.mean_ms < 100
        print(f"\nAttack Path (100 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms")

    def _find_attack_paths(self, asset_count: int):
        env = create_test_environment(asset_count)
        normalizer = AWSNormalizer()
        classifier = ResourceClassifier()

        assets = []
        assets.extend(normalizer.normalize_ec2(env["instances"], "123456789012"))
        assets.extend(normalizer.normalize_s3(env["buckets"], "123456789012"))
        assets.extend(normalizer.normalize_roles(env["roles"], "123456789012"))
        assets = classifier.classify(assets)

        builder = AWSGraphBuilder()
        graph = builder.build(
            assets=assets,
            instances=env["instances"],
            security_groups=env["security_groups"],
            roles=env["roles"],
            instance_profiles=env["instance_profiles"],
        )

        engine = AttackPathEngine(graph)
        return engine.find_paths_to_sensitive_assets()


class TestSimulationPerformance:
    """Benchmark remediation simulation performance."""

    def test_simulation_10_assets(self):
        result = benchmark(
            "simulation",
            lambda: self._run_simulation(10),
            asset_count=10,
            iterations=20,
            warmup=5,
        )
        assert result.mean_ms < 50
        print(f"\nSimulation (10 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms")

    def test_simulation_100_assets(self):
        result = benchmark(
            "simulation",
            lambda: self._run_simulation(100),
            asset_count=100,
            iterations=10,
            warmup=3,
        )
        assert result.mean_ms < 200
        print(f"\nSimulation (100 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms")

    def _run_simulation(self, asset_count: int):
        env = create_test_environment(asset_count)
        normalizer = AWSNormalizer()
        classifier = ResourceClassifier()

        assets = []
        assets.extend(normalizer.normalize_ec2(env["instances"], "123456789012"))
        assets.extend(normalizer.normalize_s3(env["buckets"], "123456789012"))
        assets.extend(normalizer.normalize_roles(env["roles"], "123456789012"))
        assets = classifier.classify(assets)

        builder = AWSGraphBuilder()
        graph = builder.build(
            assets=assets,
            instances=env["instances"],
            security_groups=env["security_groups"],
            roles=env["roles"],
            instance_profiles=env["instance_profiles"],
        )

        analysis = AnalysisService().analyze_environment(
            instances=env["instances"],
            security_groups=env["security_groups"],
            buckets=env["buckets"],
            roles=env["roles"],
            instance_profiles=env["instance_profiles"],
            account_id="123456789012",
        )

        engine = RemediationEngine()
        simulator = RemediationSimulator()
        remediations = engine.generate(analysis)

        if remediations:
            simulator.simulate(analysis, remediations[0])

        return remediations


class TestFindingEnginePerformance:
    """Benchmark finding generation performance."""

    def test_findings_10_assets(self):
        result = benchmark(
            "finding_generation",
            lambda: self._generate_findings(10),
            asset_count=10,
            iterations=20,
            warmup=5,
        )
        assert result.mean_ms < 10
        print(f"\nFinding Generation (10 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms")

    def test_findings_100_assets(self):
        result = benchmark(
            "finding_generation",
            lambda: self._generate_findings(100),
            asset_count=100,
            iterations=10,
            warmup=3,
        )
        assert result.mean_ms < 50
        print(f"\nFinding Generation (100 assets): {result.mean_ms:.2f}ms ± {result.stdev_ms:.2f}ms")

    def _generate_findings(self, asset_count: int):
        env = create_test_environment(asset_count)
        normalizer = AWSNormalizer()
        classifier = ResourceClassifier()

        assets = []
        assets.extend(normalizer.normalize_ec2(env["instances"], "123456789012"))
        assets.extend(normalizer.normalize_s3(env["buckets"], "123456789012"))
        assets.extend(normalizer.normalize_roles(env["roles"], "123456789012"))
        assets = classifier.classify(assets)

        builder = AWSGraphBuilder()
        graph = builder.build(
            assets=assets,
            instances=env["instances"],
            security_groups=env["security_groups"],
            roles=env["roles"],
            instance_profiles=env["instance_profiles"],
        )

        engine = FindingEngine()
        return engine.analyze(graph)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])