"""
cgroupsentinel.models
=====================

Core data representations and strongly-typed domain models for Linux cgroup v2
resource management, systemd unit inspection, Pressure Stall Information (PSI),
and resource boundary synthesis.

Educational Architecture Note:
------------------------------
Linux Control Groups version 2 (cgroup v2, merged in Linux 4.5 by Tejun Heo)
provides a unified single-hierarchy resource distribution model. Unlike cgroup v1,
which permitted processes to exist in conflicting orthogonal controller hierarchies,
cgroup v2 enforces the "no internal processes" rule: processes may only reside in leaf
nodes of the cgroup tree, and resources are governed hierarchically top-down.

This module models:
1. ResourceLimits: The mathematical bounds enforced by kernel controllers (memory, cpu, pids).
2. ServiceAudit: Quantitative risk assessment and gap analysis of systemd unit configurations.
3. PSISnapshot: Linux Pressure Stall Information metrics indicating real-time resource contention.
4. HostMemoryInfo: Physical hardware RAM and swap capacity from /proc/meminfo.
5. CgroupNode: Structural state of a node in the /sys/fs/cgroup unified filesystem.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


def parse_human_bytes(size_str: str) -> int:
    """
    Parses a human-readable storage string into an exact integer number of bytes.

    Supported suffixes:
      - B (Bytes)
      - K / KiB / KB (Kilobytes / Kibibytes, parsed as binary multiples: 1024)
      - M / MiB / MB (Megabytes / Mebibytes: 1024^2)
      - G / GiB / GB (Gigabytes / Gibibytes: 1024^3)
      - T / TiB / TB (Terabytes / Tebibytes: 1024^4)
      - "infinity" or "max": represented as -1 (unlimited in cgroup v2 semantics)

    Parameters:
        size_str: Raw configuration string, e.g., '512M', '2G', '4096B', 'max'.

    Returns:
        int: Value in bytes, or -1 if explicitly set to unlimited/max.

    Raises:
        ValueError: If size_str cannot be parsed into a recognized byte representation.
    """
    cleaned = size_str.strip().lower()

    # Kernel cgroup v2 uses the string "max" to denote no upper resource restriction.
    if cleaned in ("max", "infinity", "inf", "-1", "none"):
        return -1

    # Match numeric float/int prefix followed by optional SI/IEC unit suffix
    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([a-z]*)$", cleaned)
    if not match:
        raise ValueError(f"Invalid byte string specification: '{size_str}'")

    raw_val, unit = match.groups()
    val = float(raw_val)

    # Multipliers based on binary units (1024 standard used by systemd & Linux kernel)
    multipliers: Dict[str, int] = {
        "": 1,
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "mib": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "gib": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
        "tib": 1024**4,
    }

    if unit not in multipliers:
        raise ValueError(f"Unrecognized storage unit suffix '{unit}' in '{size_str}'")

    return int(val * multipliers[unit])


def format_bytes_human(byte_count: int) -> str:
    """
    Formats an integer byte count into a clean, human-readable IEC binary string.

    Parameters:
        byte_count: Integer bytes. If negative (-1), formats as 'max'.

    Returns:
        str: E.g., '512.0M', '2.0G', 'max'.
    """
    if byte_count < 0:
        return "max"

    units = ["B", "K", "M", "G", "T", "P"]
    value = float(byte_count)
    idx = 0

    while value >= 1024.0 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1

    if idx == 0:
        return f"{int(value)}B"
    return f"{value:.1f}{units[idx]}"


@dataclass
class ResourceLimits:
    """
    Encapsulates kernel cgroup v2 controller boundaries and systemd resource limits.

    Kernel Controller Mechanics:
    ----------------------------
    1. memory.max (MemoryMax=):
       The absolute hard memory ceiling. When anonymous memory + active page cache
       exceeds this threshold, the kernel aggressively attempts to reclaim page cache.
       If memory cannot be reclaimed and swap is exhausted, the kernel OOM killer
       is invoked specifically within this cgroup.
    2. memory.high (MemoryHigh=):
       The high watermark throttling boundary. When usage crosses this line, processes
       are throttled (delayed on return to userspace) and proactive asynchronous page
       reclaim runs in the background. Unlike memory.max, it does not trigger OOM kills.
    3. memory.swap.max (MemorySwapMax=):
       Caps anonymous page swapping. In desktop systems without strict swap caps,
       runaway daemons can swap gigabytes of memory, causing SSD write thrashing,
       extreme I/O latency spikes, and mouse/audio desktop stuttering.
    4. cpu.max (CPUQuota=):
       CPU bandwidth allocation. Composed of quota and period (e.g. 100000 100000 = 100% of 1 core).
       Prevents busy-wait loops from starving the compositor or browser threads.
    5. pids.max (TasksMax=):
       Limits concurrent thread and process count. Prevents fork bombs from exhausting
       kernel task_struct PID slots.
    6. OOMPolicy & OOMScoreAdjust:
       Dictates systemd and kernel response during memory exhaustion events.
    """

    memory_max: Optional[int] = None           # Bytes (-1 for max / unlimited)
    memory_high: Optional[int] = None          # Bytes (-1 for max / unlimited)
    memory_swap_max: Optional[int] = None     # Bytes (-1 for max / 0 to disable swap)
    cpu_quota_percent: Optional[float] = None  # e.g., 100.0% = 1 CPU core, 200.0% = 2 cores
    cpu_quota_period_sec: Optional[float] = None # Period in seconds (default 0.1s = 100ms)
    tasks_max: Optional[int] = None            # Max concurrent threads / PIDs
    oom_policy: Optional[str] = None           # 'stop', 'kill', or 'continue'
    oom_score_adjust: Optional[int] = None     # -1000 (never kill) to +1000 (kill first)

    def to_systemd_conf(self) -> str:
        """
        Synthesizes standard systemd drop-in configuration lines ([Service] section directives).

        Returns:
            str: INI formatted directives ready to place inside a 50-cgroup-sentinel.conf drop-in.
        """
        lines: List[str] = [
            "[Service]",
            "# Accounting directives activate cgroup v2 controllers in systemd slices",
            "MemoryAccounting=yes",
            "CPUAccounting=yes",
            "TasksAccounting=yes",
        ]

        if self.memory_max is not None:
            val_str = "infinity" if self.memory_max < 0 else format_bytes_human(self.memory_max)
            lines.append(f"MemoryMax={val_str}")

        if self.memory_high is not None:
            val_str = "infinity" if self.memory_high < 0 else format_bytes_human(self.memory_high)
            lines.append(f"MemoryHigh={val_str}")

        if self.memory_swap_max is not None:
            val_str = "infinity" if self.memory_swap_max < 0 else format_bytes_human(self.memory_swap_max)
            lines.append(f"MemorySwapMax={val_str}")

        if self.cpu_quota_percent is not None:
            lines.append(f"CPUQuota={int(self.cpu_quota_percent)}%")

        if self.cpu_quota_period_sec is not None:
            lines.append(f"CPUQuotaPeriodSec={self.cpu_quota_period_sec}s")

        if self.tasks_max is not None:
            val_str = "infinity" if self.tasks_max < 0 else str(self.tasks_max)
            lines.append(f"TasksMax={val_str}")

        if self.oom_policy is not None:
            lines.append(f"OOMPolicy={self.oom_policy}")

        if self.oom_score_adjust is not None:
            lines.append(f"OOMScoreAdjust={self.oom_score_adjust}")

        return "\n".join(lines) + "\n"


@dataclass
class ServiceAudit:
    """
    Results of an automated audit on a systemd service unit file.

    Evaluates whether the unit configures essential cgroup v2 boundaries
    to protect host stability against unconstrained memory leakage,
    CPU starvation, and kernel task exhaustion.
    """

    unit_name: str
    unit_path: Optional[str] = None
    is_present: bool = True
    has_memory_max: bool = False
    has_memory_swap_max: bool = False
    has_cpu_quota: bool = False
    has_tasks_max: bool = False
    has_oom_policy: bool = False
    has_oom_score_adjust: bool = False
    current_limits: ResourceLimits = field(default_factory=ResourceLimits)
    violations: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    risk_score: int = 0  # 0 (Completely Safe) to 100 (Extremely Hazardous)

    @property
    def risk_level(self) -> str:
        """
        Translates the quantitative risk score (0-100) into an actionable categorical threat level.
        """
        if self.risk_score >= 75:
            return "CRITICAL"
        if self.risk_score >= 50:
            return "HIGH"
        if self.risk_score >= 25:
            return "MEDIUM"
        return "LOW"

    @property
    def is_safe(self) -> bool:
        """
        True if the service has achieved a safe configuration score (risk score <= 25).
        """
        return self.risk_score <= 25


@dataclass
class PSIMetric:
    """
    Represents a Pressure Stall Information (PSI) line for a specific controller (memory/cpu/io).

    Linux Kernel PSI Mechanics:
    ---------------------------
    PSI quantifies resource shortages by tracking wall-clock time spent waiting
    for contended resources (CPU runqueue, paging/swapping, block I/O).
    - avg10: Exponentially decaying moving average over the last 10 seconds (in percent: 0.0 - 100.0).
    - avg60: 60-second moving average.
    - avg300: 300-second (5 minute) moving average.
    - total_us: Cumulative microseconds stalled since kernel boot.
    """

    avg10: float
    avg60: float
    avg300: float
    total_us: int


@dataclass
class PSISnapshot:
    """
    Snapshot of Pressure Stall Information across 'some' and 'full' contention models.

    'some': Percentage of time when at least ONE runnable task was delayed waiting for the resource.
    'full': Percentage of time when ALL non-idle runnable tasks were simultaneously delayed.
            'full' memory pressure is a catastrophic sign of system thrashing and imminent freeze.
    """

    resource: str                              # 'memory', 'cpu', or 'io'
    some: Optional[PSIMetric] = None
    full: Optional[PSIMetric] = None
    timestamp: float = 0.0

    @property
    def pressure_level(self) -> str:
        """
        Categorizes real-time pressure based on avg10 values:
        - CRITICAL: full > 10% or some > 40% (interactive desktop lockup imminent)
        - HIGH: full > 2% or some > 20% (audible audio pops, frame drops)
        - MODERATE: some > 5% (background paging under noticeable load)
        - NOMINAL: minimal or zero stall time
        """
        full_10 = self.full.avg10 if self.full else 0.0
        some_10 = self.some.avg10 if self.some else 0.0

        if full_10 > 10.0 or some_10 > 40.0:
            return "CRITICAL"
        if full_10 > 2.0 or some_10 > 20.0:
            return "HIGH"
        if some_10 > 5.0:
            return "MODERATE"
        return "NOMINAL"


@dataclass
class HostMemoryInfo:
    """
    Physical hardware memory and swap statistics parsed from /proc/meminfo.

    Used by the Sentinel Generator to calculate safe, proportional resource caps
    that leave sufficient headroom for the desktop environment (Xorg/Wayland, browser).
    """

    total_bytes: int
    available_bytes: int
    free_bytes: int
    cached_bytes: int
    swap_total_bytes: int
    swap_free_bytes: int

    @property
    def used_bytes(self) -> int:
        """Approximate active memory used by applications and kernel."""
        return max(0, self.total_bytes - self.available_bytes)

    @property
    def swap_used_bytes(self) -> int:
        """Active swap consumed."""
        return max(0, self.swap_total_bytes - self.swap_free_bytes)


@dataclass
class CgroupNode:
    """
    Represents an active cgroup directory node inside the /sys/fs/cgroup unified tree.

    Inspects live state directly from Linux virtual filesystem pseudofiles.
    """

    path: str
    relative_path: str
    controllers: List[str] = field(default_factory=list)
    memory_current: Optional[int] = None       # Bytes currently allocated
    memory_max: Optional[int] = None           # Hard limit (-1 for max)
    memory_high: Optional[int] = None          # High watermark (-1 for max)
    memory_swap_current: Optional[int] = None  # Bytes of swap currently used
    memory_swap_max: Optional[int] = None      # Max allowed swap (-1 for max)
    cpu_max_quota: Optional[int] = None        # Microseconds of CPU quota per period
    cpu_max_period: Optional[int] = None       # Microseconds of CPU period (typically 100000)
    pids_current: Optional[int] = None         # Currently active processes/threads
    pids_max: Optional[int] = None             # Hard PID ceiling (-1 for max)
    pids: List[int] = field(default_factory=list) # Member process PIDs from cgroup.procs
