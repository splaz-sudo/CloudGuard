"""
Performance benchmarks and concurrency utilities.

Provides:
- Synthetic benchmark runner for various asset counts
- Bounded concurrency control for AWS collection
- Performance measurement utilities
"""

from __future__ import annotations

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from contextlib import contextmanager
import statistics


@dataclass
class BenchmarkResult:
    """Result of a benchmark run."""
    name: str
    asset_count: int
    duration_ms: float
    operations_per_second: float
    memory_mb: Optional[float] = None
    metadata: dict = field(default_factory=dict)


class PerformanceTimer:
    """Context manager for measuring execution time."""

    def __init__(self, name: str = ""):
        self.name = name
        self.start_time = None
        self.end_time = None

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()

    @property
    def duration_ms(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0

    @property
    def duration_seconds(self) -> float:
        return self.duration_ms / 1000


@contextmanager
def measure_time(name: str = ""):
    """Context manager for measuring execution time."""
    timer = PerformanceTimer(name)
    timer.__enter__()
    try:
        yield timer
    finally:
        timer.__exit__(None, None, None)


class BoundedExecutor:
    """
    Thread pool executor with bounded concurrency and timeout support.

    Prevents unbounded thread creation and provides timeout handling.
    """

    def __init__(
        self,
        max_workers: int = 10,
        default_timeout: float = 30.0,
    ):
        self.max_workers = max_workers
        self.default_timeout = default_timeout
        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock = threading.Lock()
        self._shutdown = False

    def __enter__(self):
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    def submit(
        self,
        fn: Callable,
        *args,
        timeout: Optional[float] = None,
        **kwargs,
    ):
        """Submit a task with optional timeout."""
        if self._shutdown:
            raise RuntimeError("Executor has been shutdown")

        timeout = timeout or self.default_timeout

        def wrapped():
            return fn(*args, **kwargs)

        future = self._executor.submit(wrapped)

        def result_with_timeout():
            try:
                return future.result(timeout=timeout)
            except TimeoutError:
                future.cancel()
                raise TimeoutError(f"Task timed out after {timeout}s")

        return self._executor.submit(result_with_timeout)

    def map(self, fn: Callable, *iterables, timeout: Optional[float] = None):
        """Map function over iterables with timeout."""
        timeout = timeout or self.default_timeout
        futures = [self.submit(fn, *args, timeout=timeout) for args in zip(*iterables)]
        results = []
        for future in as_completed(futures, timeout=timeout):
            results.append(future.result())
        return results

    def shutdown(self, wait: bool = True):
        """Shutdown the executor."""
        with self._lock:
            if not self._shutdown:
                self._shutdown = True
                if self._executor:
                    self._executor.shutdown(wait=wait)


class BenchmarkRunner:
    """
    Runs performance benchmarks for CloudGuard components.
    """

    def __init__(self):
        self.results: list[BenchmarkResult] = []

    def run_benchmark(
        self,
        name: str,
        func: Callable,
        asset_count: int,
        iterations: int = 1,
        warmup: int = 1,
        **kwargs,
    ) -> BenchmarkResult:
        """
        Run a benchmark multiple times and collect statistics.

        Args:
            name: Benchmark name
            func: Function to benchmark
            asset_count: Number of assets in test
            iterations: Number of iterations to run
            warmup: Number of warmup runs (not counted)
            **kwargs: Arguments to pass to func

        Returns:
            BenchmarkResult with aggregated statistics
        """
        # Warmup runs
        for _ in range(warmup):
            func(**kwargs)

        durations = []

        for _ in range(iterations):
            with measure_time() as timer:
                func(**kwargs)
            durations.append(timer.duration_ms)

        if durations:
            avg_duration = statistics.mean(durations)
            ops_per_sec = (asset_count / avg_duration) * 1000 if avg_duration > 0 else 0
        else:
            avg_duration = 0
            ops_per_sec = 0

        result = BenchmarkResult(
            name=name,
            asset_count=asset_count,
            duration_ms=avg_duration,
            operations_per_second=ops_per_sec,
            metadata={
                "iterations": iterations,
                "warmup": warmup,
                "min_ms": min(durations) if durations else 0,
                "max_ms": max(durations) if durations else 0,
                "stdev_ms": statistics.stdev(durations) if len(durations) > 1 else 0,
            },
        )

        self.results.append(result)
        return result

    def benchmark_normalization(self, asset_counts: list[int] = None):
        """Benchmark asset normalization at various scales."""
        if asset_counts is None:
            asset_counts = [10, 100, 1000, 5000]

        from cloudguard.normalizers.aws import AWSNormalizer
        from cloudguard.collectors.ec2 import EC2Instance
        from cloudguard.collectors.s3 import S3Bucket
        from cloudguard.collectors.iam import IAMRole, InstanceProfile

        normalizer = AWSNormalizer()

        for count in asset_counts:
            # Generate test data
            instances = [
                EC2Instance(
                    instance_id=f"i-{i:08d}",
                    instance_type="t3.micro",
                    state="running",
                    region="us-east-1",
                    public_ip=f"10.0.0.{i}",
                    private_ip=f"192.168.1.{i}",
                    security_group_ids=["sg-test"],
                )
                for i in range(count // 3)
            ]
            buckets = [
                S3Bucket(
                    name=f"bucket-{i}",
                    region="us-east-1",
                    public_access_block_enabled=True,
                    policy_public=False,
                    tags={"Name": f"bucket-{i}"},
                )
                for i in range(count // 3)
            ]
            roles = [
                IAMRole(
                    name=f"role-{i}",
                    arn=f"arn:aws:iam::123456789012:role/role-{i}",
                    role_id=f"AROA{i:012d}",
                    attached_policies=[],
                )
                for i in range(count // 3)
            ]

            self.run_benchmark(
                name="normalization",
                func=lambda: normalizer.normalize_ec2(instances, "123456789012")
                       + normalizer.normalize_s3(buckets, "123456789012")
                       + normalizer.normalize_roles(roles, "123456789012"),
                asset_count=count,
                iterations=5,
                warmup=2,
            )

    def benchmark_graph_building(self, asset_counts: list[int] = None):
        """Benchmark graph building at various scales."""
        if asset_counts is None:
            asset_counts = [10, 100, 1000, 5000]

        from cloudguard.graph.aws_graph import AWSGraphBuilder
        from cloudguard.graph.security_graph import SecurityGraph
        from cloudguard.models.assets import CloudAsset, AssetType
        from cloudguard.models.relationships import Relationship, RelationshipType
        from cloudguard.collectors.ec2 import EC2Instance, SecurityGroup, SecurityGroupRule
        from cloudguard.collectors.iam import IAMRole, InstanceProfile
        from cloudguard.collectors.s3 import S3Bucket

        builder = AWSGraphBuilder()

        for count in asset_counts:
            # Generate test data
            instances = [EC2Instance(instance_id=f"i-{i}", instance_type="t3.micro",
                                     state="running", region="us-east-1", public_ip=f"10.0.0.{i}",
                                     iam_instance_profile_arn=f"arn:aws:iam::123456789012:instance-profile/profile-{i}",
                                     security_group_ids=["sg-test"]) for i in range(count // 3)]
            security_groups = [SecurityGroup(group_id="sg-test", group_name="test", vpc_id="vpc-test",
                                            inbound_rules=[SecurityGroupRule(protocol="tcp", from_port=80,
                                                                             to_port=80, sources=["0.0.0.0/0"])])]
            roles = [IAMRole(name=f"role-{i}", arn=f"arn:aws:iam::123456789012:role/role-{i}",
                            role_id=f"AROA{i:012d}", attached_policies=[]) for i in range(count // 3)]
            buckets = [S3Bucket(name=f"bucket-{i}", region="us-east-1",
                               public_access_block_enabled=True, policy_public=False, tags={})
                       for i in range(count // 3)]

            def build_graph():
                from cloudguard.normalizers.aws import AWSNormalizer
                from cloudguard.findings.classifier import ResourceClassifier

                normalizer = AWSNormalizer()
                classifier = ResourceClassifier()

                assets = []
                assets.extend(normalizer.normalize_ec2(instances, "123456789012"))
                assets.extend(normalizer.normalize_s3(buckets, "123456789012"))
                assets.extend(normalizer.normalize_roles(roles, "123456789012"))
                assets = classifier.classify(assets)

                profiles = [InstanceProfile(name=f"profile-{i}", arn=f"arn:aws:iam::123456789012:instance-profile/profile-{i}",
                                           role_names=[f"role-{i}"]) for i in range(count // 3)]

                return builder.build(
                    assets=assets,
                    instances=instances,
                    security_groups=security_groups,
                    roles=roles,
                    instance_profiles=profiles,
                )

            self.run_benchmark(
                name="graph_building",
                func=build_graph,
                asset_count=count,
                iterations=3,
                warmup=1,
            )

    def print_results(self):
        """Print benchmark results in a formatted table."""
        print("\n=== Benchmark Results ===")
        print(f"{'Name':<30} {'Assets':>8} {'Avg(ms)':>10} {'Ops/sec':>12} {'Min(ms)':>8} {'Max(ms)':>8} {'Stdev':>8}")
        print("-" * 100)
        for r in self.results:
            print(f"{r.name:<30} {r.asset_count:>8} {r.duration_ms:>10.2f} {r.operations_per_second:>12.2f} "
                  f"{r.metadata.get('min_ms', 0):>8.2f} {r.metadata.get('max_ms', 0):>8.2f} "
                  f"{r.metadata.get('stdev_ms', 0):>8.2f}")
        print()


# Convenience function for quick benchmarks
def quick_benchmark(
    name: str,
    func: Callable,
    asset_count: int,
    iterations: int = 5,
    warmup: int = 1,
    **kwargs,
) -> BenchmarkResult:
    """Quick benchmark with default settings."""
    runner = BenchmarkRunner()
    return runner.run_benchmark(name, func, asset_count, iterations, warmup, **kwargs)