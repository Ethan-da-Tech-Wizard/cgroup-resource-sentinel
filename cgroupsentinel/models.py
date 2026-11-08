"""
Program: Cgroup Resource Sentinel - Domain Models & Data Representations
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Define strongly-typed data structures, byte parsers, and systemd INI generators for Linux cgroup v2 boundaries and telemetry.
"""

from __future__ import annotations

## Standard library regular expression engine for parsing formatted byte strings
import re
## Dataclass decorator and field helper for concise, readable data container definitions
from dataclasses import dataclass, field
## Type annotations for static type verification and developer tooling
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
    ## Normalize whitespace and convert to lowercase for case-insensitive matching
    cleaned: str = size_str.strip().lower()

    ## In Linux cgroup v2 and systemd, "max" or "infinity" represents no boundary ceiling
    if cleaned in ("max", "infinity", "inf", "-1", "none"):
        ## Return -1 as our internal sentinel representation for unlimited resources
        return -1

    ## Regular expression pattern: capture digits (with optional decimal point) and letters
    match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([a-z]*)$", cleaned)
    ## If input doesn't match standard numeric + suffix format, raise a ValueError
    if not match:
        raise ValueError(f"Invalid byte string specification: '{size_str}'")

    ## Extract the numeric component string and the unit suffix string
    raw_val, unit = match.groups()
    ## Convert numeric portion to a floating-point number for unit calculation
    val: float = float(raw_val)

    ## Map of unit suffixes to binary power multipliers (1024-based standard)
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

    ## Ensure the supplied unit suffix exists in our lookup dictionary
    if unit not in multipliers:
        raise ValueError(f"Unrecognized storage unit suffix '{unit}' in '{size_str}'")

    ## Compute final total bytes and cast to exact integer
    return int(val * multipliers[unit])


def format_bytes_human(byte_count: int) -> str:
    """
    Formats an integer byte count into a clean, human-readable IEC binary string.

    Parameters:
        byte_count: Integer bytes. If negative (-1), formats as 'max'.

    Returns:
        str: E.g., '512.0M', '2.0G', 'max'.
    """
    ## Check for unlimited sentinel value (-1) and return standard kernel keyword
    if byte_count < 0:
        return "max"

    ## List of binary unit suffixes in ascending orders of magnitude
    units: List[str] = ["B", "K", "M", "G", "T", "P"]
    ## Convert byte count to float for progressive division
    value: float = float(byte_count)
    ## Index tracking the current unit magnitude
    idx: int = 0

    ## Repeatedly divide by 1024 until the value is under 1024 or max unit is reached
    while value >= 1024.0 and idx < len(units) - 1:
        ## Scale down by one kibibyte factor
        value /= 1024.0
        ## Advance to next higher unit (B -> K -> M -> G, etc.)
        idx += 1

    ## If the value remains in raw bytes (index 0), print as integer with 'B'
    if idx == 0:
        return f"{int(value)}B"
    ## Otherwise format with one decimal place of precision
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

    ## Hard memory ceiling in bytes (-1 represents unlimited/max)
    memory_max: Optional[int] = None
    ## High watermark throttling boundary in bytes (-1 represents unlimited/max)
    memory_high: Optional[int] = None
    ## Max allowed anonymous page swap consumption in bytes (-1 for max, 0 to forbid swap)
    memory_swap_max: Optional[int] = None
    ## Percentage CPU quota (e.g. 100.0% represents one full CPU core)
    cpu_quota_percent: Optional[float] = None
    ## CPU scheduling evaluation period in seconds (default is 0.1s / 100ms)
    cpu_quota_period_sec: Optional[float] = None
    ## Maximum total processes and threads permitted within the cgroup
    tasks_max: Optional[int] = None
    ## Behavior when OOM killer triggers: 'stop' (clean service exit), 'kill', or 'continue'
    oom_policy: Optional[str] = None
    ## Kernel badness bias score: -1000 (never kill) to +1000 (kill first)
    oom_score_adjust: Optional[int] = None

    def to_systemd_conf(self) -> str:
        """
        Synthesizes standard systemd drop-in configuration lines ([Service] section directives).

        Returns:
            str: INI formatted directives ready to place inside a 50-cgroup-sentinel.conf drop-in.
        """
        ## Start with the [Service] section header and prerequisite accounting flags
        lines: List[str] = [
            "[Service]",
            "# Accounting directives activate cgroup v2 controllers in systemd slices",
            "MemoryAccounting=yes",
            "CPUAccounting=yes",
            "TasksAccounting=yes",
        ]

        ## Check if MemoryMax is configured
        if self.memory_max is not None:
            ## Format -1 as 'infinity', otherwise convert bytes to human-readable string
            val_str = "infinity" if self.memory_max < 0 else format_bytes_human(self.memory_max)
            ## Append MemoryMax directive
            lines.append(f"MemoryMax={val_str}")

        ## Check if MemoryHigh is configured
        if self.memory_high is not None:
            ## Format -1 as 'infinity', otherwise convert bytes to human-readable string
            val_str = "infinity" if self.memory_high < 0 else format_bytes_human(self.memory_high)
            ## Append MemoryHigh directive
            lines.append(f"MemoryHigh={val_str}")

        ## Check if MemorySwapMax is configured
        if self.memory_swap_max is not None:
            ## Format -1 as 'infinity', otherwise convert bytes to human-readable string
            val_str = "infinity" if self.memory_swap_max < 0 else format_bytes_human(self.memory_swap_max)
            ## Append MemorySwapMax directive
            lines.append(f"MemorySwapMax={val_str}")

        ## Check if CPUQuota is configured
        if self.cpu_quota_percent is not None:
            ## Format integer percentage with % symbol
            lines.append(f"CPUQuota={int(self.cpu_quota_percent)}%")

        ## Check if custom CPU quota period is configured
        if self.cpu_quota_period_sec is not None:
            ## Format period in seconds with trailing 's'
            lines.append(f"CPUQuotaPeriodSec={self.cpu_quota_period_sec}s")

        ## Check if TasksMax is configured
        if self.tasks_max is not None:
            ## Format -1 as 'infinity', otherwise integer string
            val_str = "infinity" if self.tasks_max < 0 else str(self.tasks_max)
            ## Append TasksMax directive
            lines.append(f"TasksMax={val_str}")

        ## Check if OOMPolicy is configured
        if self.oom_policy is not None:
            ## Append OOMPolicy directive ('stop' or 'kill')
            lines.append(f"OOMPolicy={self.oom_policy}")

        ## Check if OOMScoreAdjust is configured
        if self.oom_score_adjust is not None:
            ## Append OOMScoreAdjust integer value
            lines.append(f"OOMScoreAdjust={self.oom_score_adjust}")

        ## Join all generated directives with newlines and ensure a trailing newline
        return "\n".join(lines) + "\n"


@dataclass
class ServiceAudit:
    """
    Results of an automated audit on a systemd service unit file.

    Evaluates whether the unit configures essential cgroup v2 boundaries
    to protect host stability against unconstrained memory leakage,
    CPU starvation, and kernel task exhaustion.
    """

    ## Name of the audited unit, e.g., 'docker.service'
    unit_name: str
    ## Filesystem path to the primary unit file on disk (or None if missing)
    unit_path: Optional[str] = None
    ## Flag indicating whether the service file was found on the host
    is_present: bool = True
    ## Flag indicating whether MemoryMax boundary is configured
    has_memory_max: bool = False
    ## Flag indicating whether MemorySwapMax boundary is configured
    has_memory_swap_max: bool = False
    ## Flag indicating whether CPUQuota bandwidth limit is configured
    has_cpu_quota: bool = False
    ## Flag indicating whether TasksMax PID limit is configured
    has_tasks_max: bool = False
    ## Flag indicating whether OOMPolicy action is configured
    has_oom_policy: bool = False
    ## Flag indicating whether OOMScoreAdjust priority is configured
    has_oom_score_adjust: bool = False
    ## Current effective limits parsed from combined unit and drop-ins
    current_limits: ResourceLimits = field(default_factory=ResourceLimits)
    ## List of detected risk findings and missing boundary descriptions
    violations: List[str] = field(default_factory=list)
    ## Actionable recommendations for remediating detected violations
    recommendations: List[str] = field(default_factory=list)
    ## Quantitative risk score between 0 (completely safe) and 100 (critical hazard)
    risk_score: int = 0

    @property
    def risk_level(self) -> str:
        """
        Translates the quantitative risk score (0-100) into an actionable categorical threat level.
        """
        ## High threat threshold: risk score 75 and above
        if self.risk_score >= 75:
            return "CRITICAL"
        ## Substantial threat threshold: risk score 50 to 74
        if self.risk_score >= 50:
            return "HIGH"
        ## Moderate threat threshold: risk score 25 to 49
        if self.risk_score >= 25:
            return "MEDIUM"
        ## Low threat threshold: risk score under 25
        return "LOW"

    @property
    def is_safe(self) -> bool:
        """
        True if the service has achieved a safe configuration score (risk score <= 25).
        """
        ## Service is safe if its risk score is within acceptable low-threat tolerance
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

    ## 10-second decaying moving average stall percentage
    avg10: float
    ## 60-second decaying moving average stall percentage
    avg60: float
    ## 300-second (5-minute) decaying moving average stall percentage
    avg300: float
    ## Total cumulative stall duration in microseconds since boot
    total_us: int


@dataclass
class PSISnapshot:
    """
    Snapshot of Pressure Stall Information across 'some' and 'full' contention models.

    'some': Percentage of time when at least ONE runnable task was delayed waiting for the resource.
    'full': Percentage of time when ALL non-idle runnable tasks were simultaneously delayed.
            'full' memory pressure is a catastrophic sign of system thrashing and imminent freeze.
    """

    ## Resource identifier string: 'memory', 'cpu', or 'io'
    resource: str
    ## Metrics for partial stall ('some' tasks delayed)
    some: Optional[PSIMetric] = None
    ## Metrics for complete stall ('full' - all non-idle tasks delayed)
    full: Optional[PSIMetric] = None
    ## Unix epoch timestamp when telemetry was sampled
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
        ## Extract avg10 for full stall, defaulting to 0.0 if metric unavailable
        full_10: float = self.full.avg10 if self.full else 0.0
        ## Extract avg10 for partial stall, defaulting to 0.0 if metric unavailable
        some_10: float = self.some.avg10 if self.some else 0.0

        ## Check for critical stall thresholds (full > 10% or some > 40%)
        if full_10 > 10.0 or some_10 > 40.0:
            return "CRITICAL"
        ## Check for high stall thresholds (full > 2% or some > 20%)
        if full_10 > 2.0 or some_10 > 20.0:
            return "HIGH"
        ## Check for moderate stall threshold (some > 5%)
        if some_10 > 5.0:
            return "MODERATE"
        ## Contention is within normal baseline parameters
        return "NOMINAL"


@dataclass
class HostMemoryInfo:
    """
    Physical hardware memory and swap statistics parsed from /proc/meminfo.

    Used by the Sentinel Generator to calculate safe, proportional resource caps
    that leave sufficient headroom for the desktop environment (Xorg/Wayland, browser).
    """

    ## Total usable physical RAM in bytes
    total_bytes: int
    ## Estimated available RAM for new/existing processes without swapping, in bytes
    available_bytes: int
    ## Strictly unallocated physical RAM in bytes
    free_bytes: int
    ## Reclaimable file-backed page cache in bytes
    cached_bytes: int
    ## Total swap partition/file space in bytes
    swap_total_bytes: int
    ## Unused swap space in bytes
    swap_free_bytes: int

    @property
    def used_bytes(self) -> int:
        """Approximate active memory used by applications and kernel."""
        ## Calculate consumed memory as total minus available (bounded at 0)
        return max(0, self.total_bytes - self.available_bytes)

    @property
    def swap_used_bytes(self) -> int:
        """Active swap consumed."""
        ## Calculate consumed swap as total swap minus free swap (bounded at 0)
        return max(0, self.swap_total_bytes - self.swap_free_bytes)


@dataclass
class CgroupNode:
    """
    Represents an active cgroup directory node inside the /sys/fs/cgroup unified tree.

    Inspects live state directly from Linux virtual filesystem pseudofiles.
    """

    ## Full absolute filesystem path to the cgroup directory
    path: str
    ## Relative path from cgroup root, e.g., 'system.slice/sshd.service'
    relative_path: str
    ## List of active controllers enabled for this cgroup (e.g., ['memory', 'cpu', 'pids'])
    controllers: List[str] = field(default_factory=list)
    ## Currently allocated memory in bytes (from memory.current)
    memory_current: Optional[int] = None
    ## Hard ceiling memory boundary in bytes (-1 for max)
    memory_max: Optional[int] = None
    ## Throttling high watermark boundary in bytes (-1 for max)
    memory_high: Optional[int] = None
    ## Swap currently consumed by processes in this cgroup in bytes
    memory_swap_current: Optional[int] = None
    ## Maximum swap allowed for this cgroup in bytes (-1 for max)
    memory_swap_max: Optional[int] = None
    ## Allowed CPU bandwidth quota in microseconds per period (-1 for max)
    cpu_max_quota: Optional[int] = None
    ## CPU bandwidth scheduling period in microseconds (typically 100000 = 100ms)
    cpu_max_period: Optional[int] = None
    ## Current number of processes and threads attached to this cgroup
    pids_current: Optional[int] = None
    ## Hard limit on total processes/threads allowed in this cgroup (-1 for max)
    pids_max: Optional[int] = None
    ## List of process IDs (PIDs) actively residing in this cgroup node
    pids: List[int] = field(default_factory=list)
