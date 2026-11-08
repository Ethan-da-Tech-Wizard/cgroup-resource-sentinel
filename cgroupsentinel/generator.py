"""
Program: Cgroup Resource Sentinel - Drop-in Override Generator
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Calculate hardware-adaptive resource boundaries and generate systemd drop-in override configuration files.
"""

from __future__ import annotations

## Operating system interface for environment variables and sysconf
import os
## Object-oriented filesystem path operations
from pathlib import Path
## Type hinting annotations
from typing import Any, Dict, Optional, Tuple

## Import telemetry inspector and domain models
from .inspector import CgroupInspector
from .models import HostMemoryInfo, ResourceLimits, format_bytes_human, parse_human_bytes


class DropInGenerator:
    """
    Generates tailored, safe systemd drop-in configuration files (`50-cgroup-sentinel.conf`)
    enforcing kernel cgroup v2 boundaries for specified services.
    """

    ## Standardized filename for Sentinel-managed systemd drop-in configuration overrides
    DEFAULT_OVERRIDE_FILENAME: str = "50-cgroup-sentinel.conf"

    def __init__(self, inspector: Optional[CgroupInspector] = None) -> None:
        """
        Initializes the generator with a telemetry inspector.

        Parameters:
            inspector: CgroupInspector instance (creates a default instance if omitted).
        """
        ## Store provided inspector or instantiate a default inspector
        self.inspector: CgroupInspector = inspector or CgroupInspector()

    def detect_host_specs(self) -> Tuple[int, int]:
        """
        Detects physical host RAM in bytes and available CPU cores.

        Returns:
            Tuple[int, int]: (total_ram_bytes, cpu_core_count).
        """
        ## 1. Attempt reading /proc/meminfo via inspector
        mem_info: HostMemoryInfo = self.inspector.read_host_memory_info()
        total_ram: int = mem_info.total_bytes

        ## Fallback to POSIX sysconf if /proc/meminfo is missing (e.g. macOS test environments)
        if total_ram <= 0:
            try:
                ## Query hardware page size in bytes
                page_size: int = os.sysconf("SC_PAGE_SIZE")
                ## Query total number of physical memory pages
                phys_pages: int = os.sysconf("SC_PHYS_PAGES")
                ## Calculate total RAM in bytes
                total_ram = int(page_size * phys_pages)
            except (AttributeError, ValueError, OSError):
                ## Safe generic fallback: 8 GiB
                total_ram = 8 * (1024**3)

        ## 2. Detect CPU cores, defaulting to 2 if query returns None
        cpu_cores: int = os.cpu_count() or 2

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
        ## Detect host physical hardware specifications
        detected_ram, detected_cpus = self.detect_host_specs()
        ## Use caller-provided explicit values if specified (e.g. for testing)
        ram: int = host_ram if host_ram is not None else detected_ram
        cpus: int = cpu_cores if cpu_cores is not None else detected_cpus

        ## Clean and normalize the profile name
        profile_clean: str = profile.strip().lower()

        ## Branch 1: Conservative Profile (Background Daemons, Cron, Telemetry)
        if profile_clean == "conservative":
            ## 10% of host RAM, minimum 128MB, maximum 1GB
            mem_max = max(128 * (1024**2), min(int(ram * 0.10), 1024**3))
            ## Throttle at 80% of max limit
            mem_high = int(mem_max * 0.80)
            ## Disable swap completely to protect SSD endurance and avoid desktop I/O latency
            mem_swap_max = 0
            ## Cap CPU at 50% of one core
            cpu_quota = 50.0
            ## Limit concurrent tasks to 256
            tasks_max = 256
            ## Cleanly stop service if OOM triggered
            oom_policy = "stop"
            ## Highly prioritized for OOM termination before interactive desktop session
            oom_score = 500

        ## Branch 2: Aggressive Profile (Compilers, Local LLMs, Heavy Stacks)
        elif profile_clean == "aggressive":
            ## 50% of host RAM, leaving remaining 50% for desktop and page cache
            mem_max = max(512 * (1024**2), int(ram * 0.50))
            ## Throttle at 90% of max limit
            mem_high = int(mem_max * 0.90)
            ## Allow limited swap (25% of max)
            mem_swap_max = int(mem_max * 0.25)
            ## Allocate all cores except one reserved for desktop interactivity
            available_cores = max(1, cpus - 1)
            cpu_quota = float(available_cores * 100)
            ## Allow large thread pool (up to 4096 tasks)
            tasks_max = 4096
            ## Terminate offending tasks on OOM
            oom_policy = "kill"
            ## Modest sacrifice priority
            oom_score = 100

        ## Branch 3: Custom Profile (Direct Explicit Specification)
        elif profile_clean == "custom":
            mem_max = None
            mem_high = None
            mem_swap_max = None
            cpu_quota = None
            tasks_max = None
            oom_policy = "stop"
            oom_score = 250

        ## Branch 4: Standard Profile (Default: Web Services, Databases, Proxies)
        else:
            ## 25% of host RAM, minimum 256MB, maximum 4GB
            mem_max = max(256 * (1024**2), min(int(ram * 0.25), 4 * (1024**3)))
            ## Throttle at 85% of max limit
            mem_high = int(mem_max * 0.85)
            ## Strictly cap swap at 10% of memory max
            mem_swap_max = int(mem_max * 0.10)
            ## 1 full CPU core
            cpu_quota = 100.0
            ## Allow up to 1024 threads
            tasks_max = 1024
            oom_policy = "stop"
            oom_score = 250

        ## Instantiate calculated ResourceLimits
        limits = ResourceLimits(
            memory_max=mem_max,
            memory_high=mem_high,
            memory_swap_max=mem_swap_max,
            cpu_quota_percent=cpu_quota,
            tasks_max=tasks_max,
            oom_policy=oom_policy,
            oom_score_adjust=oom_score,
        )

        ## Apply caller-supplied explicit overrides if present
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
        ## Assemble descriptive educational header comments explaining cgroup v2 mechanics
        header_lines: List[str] = [
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

        ## Generate systemd INI directives from ResourceLimits object
        conf_body: str = limits.to_systemd_conf()
        ## Combine header comments and configuration body
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
        ## Normalize unit name with .service extension
        normalized: str = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"
        ## Generate full configuration file text
        content: str = self.generate_drop_in_content(normalized, limits)

        ## Determine destination directory based on arguments
        if destination_dir is not None:
            ## Use caller-provided custom directory (e.g. temporary directory during tests)
            target_drop_in_dir: Path = destination_dir / f"{normalized}.d"
        elif is_user:
            ## Target user session systemd configuration: ~/.config/systemd/user/<unit>.service.d/
            user_config_home: Path = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
            target_drop_in_dir = user_config_home / "systemd" / "user" / f"{normalized}.d"
        else:
            ## Target system-wide systemd configuration: /etc/systemd/system/<unit>.service.d/
            target_drop_in_dir = Path("/etc/systemd/system") / f"{normalized}.d"

        ## Full path to the override configuration file
        target_file: Path = target_drop_in_dir / self.DEFAULT_OVERRIDE_FILENAME

        ## If not in dry-run mode, create directory and write file
        if not dry_run:
            target_drop_in_dir.mkdir(parents=True, exist_ok=True)
            target_file.write_text(content, encoding="utf-8")

        ## Return target file path and written content string
        return target_file, content
