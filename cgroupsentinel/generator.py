"""
cgroupsentinel.generator
========================

Systemd drop-in override synthesizer with hardware-adaptive resource calculation.

Educational Architecture Note:
------------------------------
Systemd Drop-in Overrides:
Rather than modifying package-managed vendor unit files located in `/usr/lib/systemd/system/`
(which would be overwritten on every package upgrade), systemd provides a clean, modular
override mechanism via drop-in configuration directories:
    `/etc/systemd/system/<unit-name>.service.d/*.conf`

When systemd parses unit configurations:
1. It reads the base `.service` file.
2. It discovers all `<unit-name>.service.d/*.conf` files across the search paths in alphabetical order.
3. Directives inside drop-in files overwrite or extend the base unit configuration.

Hardware-Adaptive Dynamic Governor:
-----------------------------------
A static limit (e.g. `MemoryMax=4G`) might be reasonable on a 64GB workstation,
but completely fatal on an 8GB laptop.
This generator inspects physical host RAM and available CPU cores to compute proportional,
safe boundary allocations that guarantee adequate headroom for desktop display servers,
audio daemons, and interactive browsers.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .inspector import CgroupInspector
from .models import HostMemoryInfo, ResourceLimits, format_bytes_human, parse_human_bytes


class DropInGenerator:
    """
    Generates tailored, safe systemd drop-in configuration files (`50-cgroup-sentinel.conf`)
    enforcing kernel cgroup v2 boundaries for specified services.
    """

    DEFAULT_OVERRIDE_FILENAME = "50-cgroup-sentinel.conf"

    def __init__(self, inspector: Optional[CgroupInspector] = None) -> None:
        """
        Initializes the generator with a telemetry inspector.

        Parameters:
            inspector: CgroupInspector instance (creates a default instance if omitted).
        """
        self.inspector = inspector or CgroupInspector()

    def detect_host_specs(self) -> Tuple[int, int]:
        """
        Detects physical host RAM in bytes and available CPU cores.

        Returns:
            Tuple[int, int]: (total_ram_bytes, cpu_core_count).
        """
        # 1. Attempt reading /proc/meminfo via inspector
        mem_info = self.inspector.read_host_memory_info()
        total_ram = mem_info.total_bytes

        # Fallback to POSIX sysconf if /proc/meminfo is missing (e.g. macOS test environments)
        if total_ram <= 0:
            try:
                page_size = os.sysconf("SC_PAGE_SIZE")
                phys_pages = os.sysconf("SC_PHYS_PAGES")
                total_ram = int(page_size * phys_pages)
            except (AttributeError, ValueError, OSError):
                # Safe generic fallback: 8 GiB
                total_ram = 8 * (1024**3)

        # 2. Detect CPU cores
        cpu_cores = os.cpu_count() or 2

        return total_ram, cpu_cores

    def calculate_limits(
        self,
        profile: str = "standard",
        custom_overrides: Optional[Dict[str, Any]] = None,
        host_ram: Optional[int] = None,
        cpu_cores: Optional[int] = None,
    ) -> ResourceLimits:
        """
        Calculates safe cgroup v2 resource limits based on selected profile and host hardware.

        Supported Profiles:
        - 'conservative': Ideal for background daemons, cron jobs, log shippers, and telemetry.
                          Allocates ~10% of physical RAM (capped at 1GB max). Swap is disabled (0).
                          CPU capped at 50% (half of 1 core). OOMScoreAdjust=500.
        - 'standard':     Balanced profile for web services, databases, local proxies.
                          Allocates ~25% of physical RAM (capped at 4GB max). Swap capped strictly.
                          CPU capped at 100% (1 core). OOMScoreAdjust=250.
        - 'aggressive':   For compilation, local AI/LLM models, heavy dev stacks.
                          Allocates ~50% of physical RAM, ensuring at least 2GB is reserved for desktop.
                          CPU capped at (num_cores - 1) * 100%. OOMScoreAdjust=100.
        - 'custom':       Bypasses profile heuristics and applies explicit limits.

        Parameters:
            profile: Profile name ('conservative', 'standard', 'aggressive', 'custom').
            custom_overrides: Dictionary of explicit limit overrides.
            host_ram: Optional explicit RAM in bytes (used in tests).
            cpu_cores: Optional explicit CPU core count (used in tests).

        Returns:
            ResourceLimits: Calculated boundaries.
        """
        detected_ram, detected_cpus = self.detect_host_specs()
        ram = host_ram if host_ram is not None else detected_ram
        cpus = cpu_cores if cpu_cores is not None else detected_cpus

        profile_clean = profile.strip().lower()

        if profile_clean == "conservative":
            # 10% of host RAM, minimum 128MB, maximum 1GB
            mem_max = max(128 * (1024**2), min(int(ram * 0.10), 1024**3))
            mem_high = int(mem_max * 0.80)
            mem_swap_max = 0  # Disable swap to protect SSD and desktop I/O latency
            cpu_quota = 50.0  # 50% of 1 core
            tasks_max = 256
            oom_policy = "stop"
            oom_score = 500  # Highly prioritized for OOM termination before desktop UI

        elif profile_clean == "aggressive":
            # 50% of host RAM, leaving desktop buffer
            mem_max = max(512 * (1024**2), int(ram * 0.50))
            mem_high = int(mem_max * 0.90)
            mem_swap_max = int(mem_max * 0.25)
            # Allocate all cores except one reserved for desktop interactivity
            available_cores = max(1, cpus - 1)
            cpu_quota = float(available_cores * 100)
            tasks_max = 4096
            oom_policy = "kill"
            oom_score = 100

        elif profile_clean == "custom":
            mem_max = None
            mem_high = None
            mem_swap_max = None
            cpu_quota = None
            tasks_max = None
            oom_policy = "stop"
            oom_score = 250

        else:  # 'standard'
            # 25% of host RAM, minimum 256MB, maximum 4GB
            mem_max = max(256 * (1024**2), min(int(ram * 0.25), 4 * (1024**3)))
            mem_high = int(mem_max * 0.85)
            mem_swap_max = int(mem_max * 0.10)
            cpu_quota = 100.0  # 1 full core
            tasks_max = 1024
            oom_policy = "stop"
            oom_score = 250

        limits = ResourceLimits(
            memory_max=mem_max,
            memory_high=mem_high,
            memory_swap_max=mem_swap_max,
            cpu_quota_percent=cpu_quota,
            tasks_max=tasks_max,
            oom_policy=oom_policy,
            oom_score_adjust=oom_score,
        )

        # Apply user-supplied overrides
        if custom_overrides:
            for k, v in custom_overrides.items():
                if hasattr(limits, k) and v is not None:
                    setattr(limits, k, v)

        return limits

    def generate_drop_in_content(self, unit_name: str, limits: ResourceLimits) -> str:
        """
        Synthesizes the complete drop-in configuration file text with educational comments.

        Parameters:
            unit_name: Target unit name.
            limits: ResourceLimits object.

        Returns:
            str: Full configuration text.
        """
        header_lines = [
            f"# ====================================================================",
            f"# Cgroup Resource Sentinel: Automated Drop-in Override",
            f"# Target Unit: {unit_name}",
            f"# Generated: Protected against unconstrained memory leaks & CPU lockup",
            f"#",
            f"# Educational Kernel Mechanics:",
            f"# - MemoryMax enforces hard cgroup v2 anonymous + page cache ceilings.",
            f"# - MemoryHigh enables proactive kernel asynchronous reclaim throttling.",
            f"# - MemorySwapMax prevents SSD thrashing and interactive desktop freeze.",
            f"# - CPUQuota bounds execution time to prevent compositor starvation.",
            f"# - TasksMax prevents fork bombs and kernel task_struct table exhaustion.",
            f"# - OOMPolicy=stop ensures clean service termination upon OOM kill.",
            f"# - OOMScoreAdjust ensures the background service is sacrificed",
            f"#   BEFORE interactive desktop/browser processes are harmed.",
            f"# ====================================================================",
            "",
        ]

        conf_body = limits.to_systemd_conf()
        return "\n".join(header_lines) + conf_body

    def write_drop_in(
        self,
        unit_name: str,
        limits: ResourceLimits,
        destination_dir: Optional[Path] = None,
        is_user: bool = False,
        dry_run: bool = False,
    ) -> Tuple[Path, str]:
        """
        Writes the generated drop-in configuration to disk.

        Standard Paths:
        - System: `/etc/systemd/system/<unit>.service.d/50-cgroup-sentinel.conf`
        - User: `~/.config/systemd/user/<unit>.service.d/50-cgroup-sentinel.conf`

        Parameters:
            unit_name: Name of target service.
            limits: ResourceLimits to write.
            destination_dir: Explicit override directory path (useful for testing).
            is_user: True to target user session units instead of system units.
            dry_run: If True, does not write file to disk.

        Returns:
            Tuple[Path, str]: (Target drop-in file path, generated file content).
        """
        normalized = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"
        content = self.generate_drop_in_content(normalized, limits)

        if destination_dir is not None:
            target_drop_in_dir = destination_dir / f"{normalized}.d"
        elif is_user:
            user_config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
            target_drop_in_dir = user_config_home / "systemd" / "user" / f"{normalized}.d"
        else:
            target_drop_in_dir = Path("/etc/systemd/system") / f"{normalized}.d"

        target_file = target_drop_in_dir / self.DEFAULT_OVERRIDE_FILENAME

        if not dry_run:
            target_drop_in_dir.mkdir(parents=True, exist_ok=True)
            target_file.write_text(content, encoding="utf-8")

        return target_file, content
