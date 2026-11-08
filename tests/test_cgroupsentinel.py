"""
Program: Cgroup Resource Sentinel - Unit Test Suite
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Validate cgroup v2 parsing, PSI pressure metrics, systemd unit auditing, limit calculations, and CLI command execution.
"""

from __future__ import annotations

## In-memory string I/O stream for intercepting CLI stdout output
import io
## JSON serialization for validating CLI JSON outputs
import json
## Operating system interface
import os
## High-level file operations for recursive directory removal
import shutil
## System parameters and stdout/stderr references
import sys
## Temporary directory creation for clean test sandbox isolation
import tempfile
## Python standard unittest framework
import unittest
## Object-oriented path handling
from pathlib import Path
## Mocking utilities for patching standard streams
from unittest.mock import patch

## Auditor class under test
from cgroupsentinel.auditor import SystemdUnitAuditor
## CLI entrypoints and subcommand handlers under test
from cgroupsentinel.cli import (
    build_parser,
    cmd_audit,
    cmd_generate_override,
    cmd_inspect,
    cmd_pressure,
    cmd_report,
)
## Drop-in generator under test
from cgroupsentinel.generator import DropInGenerator
## Cgroup and /proc inspector under test
from cgroupsentinel.inspector import CgroupInspector
## Domain models and conversion utilities under test
from cgroupsentinel.models import (
    HostMemoryInfo,
    PSIMetric,
    PSISnapshot,
    ResourceLimits,
    ServiceAudit,
    format_bytes_human,
    parse_human_bytes,
)


class TestModelsAndUtilities(unittest.TestCase):
    """Tests byte parsing, formatting, and ResourceLimits serialization."""

    def test_parse_human_bytes_standard(self) -> None:
        """Verifies accurate conversion of human-readable byte strings to exact integers."""
        ## Explicit bytes
        self.assertEqual(parse_human_bytes("1024B"), 1024)
        ## Kilobytes
        self.assertEqual(parse_human_bytes("4K"), 4 * 1024)
        ## Kibibytes
        self.assertEqual(parse_human_bytes("16KiB"), 16 * 1024)
        ## Megabytes
        self.assertEqual(parse_human_bytes("512M"), 512 * 1024 * 1024)
        ## Gigabytes
        self.assertEqual(parse_human_bytes("2G"), 2 * 1024 * 1024 * 1024)
        ## Fractional gigabytes
        self.assertEqual(parse_human_bytes("1.5G"), int(1.5 * 1024 * 1024 * 1024))
        ## Terabytes
        self.assertEqual(parse_human_bytes("1T"), 1024**4)

    def test_parse_human_bytes_unlimited(self) -> None:
        """Verifies that keywords representing infinite or max boundaries return -1."""
        ## Kernel keyword 'max'
        self.assertEqual(parse_human_bytes("max"), -1)
        ## Keyword 'infinity'
        self.assertEqual(parse_human_bytes("infinity"), -1)
        ## Abbreviation 'inf'
        self.assertEqual(parse_human_bytes("inf"), -1)
        ## Numeric string '-1'
        self.assertEqual(parse_human_bytes("-1"), -1)

    def test_parse_human_bytes_invalid(self) -> None:
        """Verifies that invalid or malformed strings raise ValueError."""
        ## Nonsensical string
        with self.assertRaises(ValueError):
            parse_human_bytes("invalid_size")
        ## Invalid unit suffix
        with self.assertRaises(ValueError):
            parse_human_bytes("500X")

    def test_format_bytes_human(self) -> None:
        """Verifies conversion of raw byte counts to human-readable strings."""
        ## Sentinel unlimited value
        self.assertEqual(format_bytes_human(-1), "max")
        ## Raw byte format
        self.assertEqual(format_bytes_human(512), "512B")
        ## Kilobyte boundary
        self.assertEqual(format_bytes_human(1024), "1.0K")
        ## Megabyte scale
        self.assertEqual(format_bytes_human(1024 * 1024 * 512), "512.0M")
        ## Gigabyte scale
        self.assertEqual(format_bytes_human(1024 * 1024 * 1024 * 2), "2.0G")

    def test_resource_limits_to_systemd_conf(self) -> None:
        """Verifies synthesis of valid systemd INI configuration directives."""
        ## Instantiate comprehensive resource limits configuration
        limits = ResourceLimits(
            memory_max=2 * 1024 * 1024 * 1024,
            memory_high=int(1.8 * 1024 * 1024 * 1024),
            memory_swap_max=0,
            cpu_quota_percent=150.0,
            cpu_quota_period_sec=0.1,
            tasks_max=512,
            oom_policy="stop",
            oom_score_adjust=500,
        )
        ## Synthesize INI drop-in directives
        conf: str = limits.to_systemd_conf()

        ## Assert section header and accounting directives
        self.assertIn("[Service]", conf)
        self.assertIn("MemoryAccounting=yes", conf)
        self.assertIn("CPUAccounting=yes", conf)
        self.assertIn("TasksAccounting=yes", conf)
        ## Assert resource boundary values
        self.assertIn("MemoryMax=2.0G", conf)
        self.assertIn("MemorySwapMax=0B", conf)
        self.assertIn("CPUQuota=150%", conf)
        self.assertIn("CPUQuotaPeriodSec=0.1s", conf)
        self.assertIn("TasksMax=512", conf)
        self.assertIn("OOMPolicy=stop", conf)
        self.assertIn("OOMScoreAdjust=500", conf)

    def test_psi_pressure_levels(self) -> None:
        """Verifies categorization of Pressure Stall Information into threat tiers."""
        ## 1. Nominal pressure tier
        snap_nom = PSISnapshot(
            resource="memory",
            some=PSIMetric(avg10=0.0, avg60=0.0, avg300=0.0, total_us=0),
            full=PSIMetric(avg10=0.0, avg60=0.0, avg300=0.0, total_us=0),
        )
        self.assertEqual(snap_nom.pressure_level, "NOMINAL")

        ## 2. Moderate pressure tier
        snap_mod = PSISnapshot(
            resource="memory",
            some=PSIMetric(avg10=6.5, avg60=2.0, avg300=0.5, total_us=1000),
            full=PSIMetric(avg10=0.0, avg60=0.0, avg300=0.0, total_us=0),
        )
        self.assertEqual(snap_mod.pressure_level, "MODERATE")

        ## 3. High pressure tier
        snap_high = PSISnapshot(
            resource="memory",
            some=PSIMetric(avg10=22.0, avg60=10.0, avg300=5.0, total_us=5000),
            full=PSIMetric(avg10=3.0, avg60=1.0, avg300=0.0, total_us=1000),
        )
        self.assertEqual(snap_high.pressure_level, "HIGH")

        ## 4. Critical pressure tier
        snap_crit = PSISnapshot(
            resource="memory",
            some=PSIMetric(avg10=55.0, avg60=40.0, avg300=30.0, total_us=99999),
            full=PSIMetric(avg10=15.0, avg60=8.0, avg300=4.0, total_us=50000),
        )
        self.assertEqual(snap_crit.pressure_level, "CRITICAL")


class TestCgroupInspector(unittest.TestCase):
    """Tests cgroup hierarchy inspection, /proc/meminfo and PSI parsing."""

    def setUp(self) -> None:
        """Create isolated sandbox directories representing cgroup and proc filesystems."""
        self.test_dir = tempfile.mkdtemp()
        self.cgroup_root = Path(self.test_dir) / "cgroup"
        self.proc_root = Path(self.test_dir) / "proc"
        self.cgroup_root.mkdir(parents=True)
        self.proc_root.mkdir(parents=True)

        ## Instantiate inspector pointing to mock directories
        self.inspector = CgroupInspector(
            cgroup_root=str(self.cgroup_root),
            proc_root=str(self.proc_root),
        )

    def tearDown(self) -> None:
        """Clean up temporary sandbox files."""
        shutil.rmtree(self.test_dir)

    def test_cgroup_v2_availability(self) -> None:
        """Verifies detection of cgroup v2 unified hierarchy."""
        ## Initially false because marker doesn't exist
        self.assertFalse(self.inspector.is_cgroup_v2_available())

        ## Create cgroup.controllers marker file
        (self.cgroup_root / "cgroup.controllers").write_text("cpuset cpu io memory pids\n")
        self.assertTrue(self.inspector.is_cgroup_v2_available())

    def test_inspect_cgroup_node(self) -> None:
        """Verifies parsing of live cgroup controller files within a unit slice."""
        slice_dir = self.cgroup_root / "system.slice" / "myservice.service"
        slice_dir.mkdir(parents=True)

        ## Populate mock pseudofiles
        (slice_dir / "cgroup.controllers").write_text("memory cpu pids\n")
        (slice_dir / "cgroup.procs").write_text("1001\n1002\n")
        (slice_dir / "memory.current").write_text("104857600\n")  # 100MB
        (slice_dir / "memory.max").write_text("536870912\n")     # 512MB
        (slice_dir / "memory.high").write_text("429496729\n")
        (slice_dir / "memory.swap.current").write_text("0\n")
        (slice_dir / "memory.swap.max").write_text("0\n")
        (slice_dir / "cpu.max").write_text("50000 100000\n")     # 50% CPU
        (slice_dir / "pids.current").write_text("4\n")
        (slice_dir / "pids.max").write_text("256\n")

        ## Inspect node
        node = self.inspector.inspect_cgroup("system.slice/myservice.service")
        self.assertIsNotNone(node)
        assert node is not None
        self.assertEqual(node.memory_current, 104857600)
        self.assertEqual(node.memory_max, 536870912)
        self.assertEqual(node.memory_swap_max, 0)
        self.assertEqual(node.cpu_max_quota, 50000)
        self.assertEqual(node.cpu_max_period, 100000)
        self.assertEqual(node.pids_current, 4)
        self.assertEqual(node.pids_max, 256)
        self.assertEqual(node.pids, [1001, 1002])
        self.assertIn("memory", node.controllers)

    def test_read_proc_meminfo(self) -> None:
        """Verifies extraction and byte scaling from /proc/meminfo."""
        meminfo_content = (
            "MemTotal:       16384000 kB\n"
            "MemFree:         4096000 kB\n"
            "MemAvailable:    8192000 kB\n"
            "Cached:          3000000 kB\n"
            "SwapTotal:       4194304 kB\n"
            "SwapFree:        4194304 kB\n"
        )
        (self.proc_root / "meminfo").write_text(meminfo_content)

        mem: HostMemoryInfo = self.inspector.read_host_memory_info()
        self.assertEqual(mem.total_bytes, 16384000 * 1024)
        self.assertEqual(mem.available_bytes, 8192000 * 1024)
        self.assertEqual(mem.cached_bytes, 3000000 * 1024)
        self.assertEqual(mem.swap_total_bytes, 4194304 * 1024)
        self.assertEqual(mem.swap_free_bytes, 4194304 * 1024)
        self.assertEqual(mem.swap_used_bytes, 0)

    def test_read_psi_metrics(self) -> None:
        """Verifies parsing of Pressure Stall Information metrics."""
        pressure_dir = self.proc_root / "pressure"
        pressure_dir.mkdir(parents=True)

        psi_content = (
            "some avg10=2.50 avg60=1.10 avg300=0.45 total=1234567\n"
            "full avg10=0.15 avg60=0.05 avg300=0.00 total=23456\n"
        )
        (pressure_dir / "memory").write_text(psi_content)

        snapshot: Optional[PSISnapshot] = self.inspector.read_psi("memory")
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(snapshot.resource, "memory")
        self.assertIsNotNone(snapshot.some)
        self.assertIsNotNone(snapshot.full)
        assert snapshot.some is not None
        assert snapshot.full is not None
        self.assertEqual(snapshot.some.avg10, 2.50)
        self.assertEqual(snapshot.some.avg60, 1.10)
        self.assertEqual(snapshot.some.total_us, 1234567)
        self.assertEqual(snapshot.full.avg10, 0.15)
        self.assertEqual(snapshot.pressure_level, "NOMINAL")

    def test_find_process_cgroup_and_oom_score(self) -> None:
        """Verifies process cgroup lookup and OOM score adjustment inspection."""
        pid_dir = self.proc_root / "4242"
        pid_dir.mkdir(parents=True)

        (pid_dir / "cgroup").write_text("0::/system.slice/test-daemon.service\n")
        (pid_dir / "oom_score_adj").write_text("500\n")

        rel_path = self.inspector.find_process_cgroup(4242)
        self.assertEqual(rel_path, "system.slice/test-daemon.service")

        score = self.inspector.read_process_oom_score_adj(4242)
        self.assertEqual(score, 500)


class TestSystemdUnitAuditor(unittest.TestCase):
    """Tests systemd service file auditing and risk evaluation."""

    def setUp(self) -> None:
        """Initialize mock systemd directory."""
        self.test_dir = tempfile.mkdtemp()
        self.systemd_dir = Path(self.test_dir) / "system"
        self.systemd_dir.mkdir(parents=True)
        self.auditor = SystemdUnitAuditor(search_paths=[str(self.systemd_dir)])

    def tearDown(self) -> None:
        """Clean up temporary sandbox."""
        shutil.rmtree(self.test_dir)

    def test_audit_unbounded_hazardous_unit(self) -> None:
        """Verifies that an unconstrained service unit receives a CRITICAL risk score."""
        bad_service = (
            "[Unit]\n"
            "Description=Wild Unbounded Service\n\n"
            "[Service]\n"
            "ExecStart=/usr/bin/runaway-daemon\n"
            "Restart=always\n"
        )
        unit_file = self.systemd_dir / "wild.service"
        unit_file.write_text(bad_service)

        audit: ServiceAudit = self.auditor.audit_unit("wild.service")
        self.assertTrue(audit.is_present)
        self.assertFalse(audit.has_memory_max)
        self.assertFalse(audit.has_memory_swap_max)
        self.assertFalse(audit.has_cpu_quota)
        self.assertFalse(audit.has_tasks_max)
        self.assertFalse(audit.has_oom_policy)
        self.assertFalse(audit.has_oom_score_adjust)

        ## Risk score should be critical (>= 75)
        self.assertGreaterEqual(audit.risk_score, 75)
        self.assertEqual(audit.risk_level, "CRITICAL")
        self.assertFalse(audit.is_safe)
        self.assertGreater(len(audit.violations), 4)

    def test_audit_well_constrained_safe_unit(self) -> None:
        """Verifies that a fully constrained service receives a score of 0 (LOW risk)."""
        good_service = (
            "[Unit]\n"
            "Description=Well Constrained Protected Service\n\n"
            "[Service]\n"
            "ExecStart=/usr/bin/safe-daemon\n"
            "MemoryAccounting=yes\n"
            "CPUAccounting=yes\n"
            "TasksAccounting=yes\n"
            "MemoryMax=1G\n"
            "MemorySwapMax=0\n"
            "CPUQuota=100%\n"
            "TasksMax=256\n"
            "OOMPolicy=stop\n"
            "OOMScoreAdjust=500\n"
        )
        unit_file = self.systemd_dir / "safe.service"
        unit_file.write_text(good_service)

        audit: ServiceAudit = self.auditor.audit_unit("safe.service")
        self.assertTrue(audit.is_present)
        self.assertTrue(audit.has_memory_max)
        self.assertTrue(audit.has_memory_swap_max)
        self.assertTrue(audit.has_cpu_quota)
        self.assertTrue(audit.has_tasks_max)
        self.assertTrue(audit.has_oom_policy)
        self.assertTrue(audit.has_oom_score_adjust)

        self.assertEqual(audit.risk_score, 0)
        self.assertEqual(audit.risk_level, "LOW")
        self.assertTrue(audit.is_safe)
        self.assertEqual(len(audit.violations), 0)

    def test_audit_drop_in_override_merging(self) -> None:
        """Verifies that drop-in override files correctly satisfy resource boundaries."""
        base_service = (
            "[Unit]\n"
            "Description=Vendor Service Without Limits\n\n"
            "[Service]\n"
            "ExecStart=/usr/bin/vendor-daemon\n"
        )
        unit_file = self.systemd_dir / "vendor.service"
        unit_file.write_text(base_service)

        ## Create drop-in directory and override file
        drop_in_dir = self.systemd_dir / "vendor.service.d"
        drop_in_dir.mkdir()
        drop_in_file = drop_in_dir / "50-cgroup-sentinel.conf"
        drop_in_file.write_text(
            "[Service]\n"
            "MemoryMax=2G\n"
            "MemorySwapMax=0\n"
            "CPUQuota=80%\n"
            "TasksMax=512\n"
            "OOMPolicy=stop\n"
            "OOMScoreAdjust=400\n"
        )

        audit: ServiceAudit = self.auditor.audit_unit("vendor.service")
        self.assertTrue(audit.has_memory_max)
        self.assertTrue(audit.has_memory_swap_max)
        self.assertTrue(audit.has_cpu_quota)
        self.assertEqual(audit.risk_score, 0)
        self.assertTrue(audit.is_safe)

    def test_audit_missing_unit(self) -> None:
        """Verifies behavior when the target service does not exist."""
        audit: ServiceAudit = self.auditor.audit_unit("nonexistent.service")
        self.assertFalse(audit.is_present)
        self.assertIn("not found", audit.violations[0])


class TestDropInGenerator(unittest.TestCase):
    """Tests drop-in configuration synthesis and profile heuristics."""

    def setUp(self) -> None:
        """Initialize mock environment."""
        self.test_dir = tempfile.mkdtemp()
        self.generator = DropInGenerator()

    def tearDown(self) -> None:
        """Clean up temporary sandbox."""
        shutil.rmtree(self.test_dir)

    def test_calculate_limits_conservative(self) -> None:
        """Verifies conservative profile boundary heuristics."""
        ram: int = 16 * (1024**3)  # 16 GB
        cpus: int = 8
        limits = self.generator.calculate_limits(
            profile="conservative",
            host_ram=ram,
            cpu_cores=cpus,
        )

        ## Conservative caps at 1GB max
        self.assertEqual(limits.memory_max, 1024**3)
        self.assertEqual(limits.memory_swap_max, 0)
        self.assertEqual(limits.cpu_quota_percent, 50.0)
        self.assertEqual(limits.tasks_max, 256)
        self.assertEqual(limits.oom_score_adjust, 500)

    def test_calculate_limits_standard(self) -> None:
        """Verifies standard profile boundary heuristics."""
        ram: int = 16 * (1024**3)  # 16 GB
        cpus: int = 8
        limits = self.generator.calculate_limits(
            profile="standard",
            host_ram=ram,
            cpu_cores=cpus,
        )

        ## 25% of 16GB is 4GB (which matches the 4GB cap)
        self.assertEqual(limits.memory_max, 4 * (1024**3))
        self.assertEqual(limits.cpu_quota_percent, 100.0)
        self.assertEqual(limits.tasks_max, 1024)
        self.assertEqual(limits.oom_score_adjust, 250)

    def test_calculate_limits_aggressive(self) -> None:
        """Verifies aggressive profile boundary heuristics."""
        ram: int = 32 * (1024**3)  # 32 GB
        cpus: int = 8
        limits = self.generator.calculate_limits(
            profile="aggressive",
            host_ram=ram,
            cpu_cores=cpus,
        )

        ## 50% of 32GB is 16GB
        self.assertEqual(limits.memory_max, 16 * (1024**3))
        ## (8 cpus - 1) * 100% = 700%
        self.assertEqual(limits.cpu_quota_percent, 700.0)
        self.assertEqual(limits.tasks_max, 4096)
        self.assertEqual(limits.oom_policy, "kill")

    def test_write_drop_in(self) -> None:
        """Verifies writing drop-in file to disk."""
        limits = ResourceLimits(
            memory_max=1024**3,
            cpu_quota_percent=100.0,
            tasks_max=512,
            oom_policy="stop",
        )
        dest = Path(self.test_dir) / "etc_systemd"

        target_file, content = self.generator.write_drop_in(
            unit_name="docker.service",
            limits=limits,
            destination_dir=dest,
            dry_run=False,
        )

        self.assertTrue(target_file.exists())
        self.assertIn("docker.service.d", str(target_file))
        self.assertIn("MemoryMax=1.0G", content)
        self.assertIn("CPUQuota=100%", content)


class TestCLICommands(unittest.TestCase):
    """Tests command-line interface execution and JSON output modes."""

    def setUp(self) -> None:
        """Initialize mock environment for CLI testing."""
        self.test_dir = tempfile.mkdtemp()
        self.systemd_dir = Path(self.test_dir) / "systemd"
        self.cgroup_dir = Path(self.test_dir) / "cgroup"
        self.proc_dir = Path(self.test_dir) / "proc"
        self.systemd_dir.mkdir(parents=True)
        self.cgroup_dir.mkdir(parents=True)
        self.proc_dir.mkdir(parents=True)

        ## Initialize minimal cgroup v2 marker
        (self.cgroup_dir / "cgroup.controllers").write_text("memory cpu pids\n")
        ## Initialize minimal meminfo
        (self.proc_dir / "meminfo").write_text("MemTotal: 8388608 kB\nMemAvailable: 4194304 kB\n")

    def tearDown(self) -> None:
        """Clean up temporary sandbox."""
        shutil.rmtree(self.test_dir)

    def test_cli_audit_json(self) -> None:
        """Verifies CLI audit subcommand with --json flag."""
        sample_unit = self.systemd_dir / "test.service"
        sample_unit.write_text("[Service]\nExecStart=/bin/true\n")

        parser = build_parser()
        args = parser.parse_args([
            "audit",
            str(sample_unit),
            "--json",
        ])

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = cmd_audit(args)

        self.assertEqual(code, 0)
        output = json.loads(buf.getvalue())
        self.assertIsInstance(output, list)
        self.assertEqual(len(output), 1)
        self.assertEqual(output[0]["unit_name"], "test.service")
        self.assertIn("Missing MemoryMax", output[0]["violations"][0])

    def test_cli_generate_override_json(self) -> None:
        """Verifies CLI generate-override subcommand with --json flag."""
        parser = build_parser()
        args = parser.parse_args([
            "generate-override",
            "ollama.service",
            "--profile", "conservative",
            "--memory-max", "2G",
            "--json",
        ])

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = cmd_generate_override(args)

        self.assertEqual(code, 0)
        output = json.loads(buf.getvalue())
        self.assertEqual(output["unit_name"], "ollama.service")
        self.assertEqual(output["limits"]["memory_max"], 2 * 1024**3)
        self.assertIn("MemoryMax=2.0G", output["content"])

    def test_cli_pressure_json(self) -> None:
        """Verifies CLI pressure subcommand with --json flag."""
        pressure_dir = self.proc_dir / "pressure"
        pressure_dir.mkdir(parents=True)
        (pressure_dir / "memory").write_text(
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
            "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
        )

        parser = build_parser()
        args = parser.parse_args([
            "--proc-root", str(self.proc_dir),
            "pressure",
            "--resource", "memory",
            "--json",
        ])

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = cmd_pressure(args)

        self.assertEqual(code, 0)
        output = json.loads(buf.getvalue())
        self.assertIn("memory", output)
        self.assertEqual(output["memory"]["pressure_level"], "NOMINAL")

    def test_cli_report_json(self) -> None:
        """Verifies CLI report subcommand with --json flag."""
        parser = build_parser()
        args = parser.parse_args([
            "--cgroup-root", str(self.cgroup_dir),
            "--proc-root", str(self.proc_dir),
            "report",
            "--json",
        ])

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = cmd_report(args)

        self.assertEqual(code, 0)
        output = json.loads(buf.getvalue())
        self.assertTrue(output["cgroup_v2_active"])
        self.assertIn("host_memory", output)
        self.assertEqual(output["host_memory"]["total_bytes"], 8388608 * 1024)


if __name__ == "__main__":
    ## Execute unit test suite with standard runner
    unittest.main()
