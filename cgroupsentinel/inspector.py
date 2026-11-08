"""
Program: Cgroup Resource Sentinel - Cgroup v2 & System Inspector
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Inspect the Linux cgroup v2 unified hierarchy, read controller metrics, parse /proc/meminfo, and collect PSI pressure data.
"""

from __future__ import annotations

## Standard operating system interface for environment variables and process checks
import os
## Regular expressions for string parsing and numeric extraction
import re
## Epoch time utility for timestamping telemetry samples
import time
## Object-oriented filesystem path manipulation
from pathlib import Path
## Type hinting annotations
from typing import Dict, List, Optional, Tuple

## Import domain models for structured telemetry and limits representation
from .models import (
    CgroupNode,
    HostMemoryInfo,
    PSIMetric,
    PSISnapshot,
    parse_human_bytes,
)


class CgroupInspector:
    """
    Inspects active cgroup v2 nodes, reads live controller metrics,
    and extracts system-level pressure and hardware memory statistics.

    Designed with dependency injection to allow transparent mocking
    for cross-platform tests (e.g., CI runners, macOS, unit test isolation).
    """

    def __init__(
        self,
        cgroup_root: str = "/sys/fs/cgroup",
        proc_root: str = "/proc",
    ) -> None:
        """
        Initializes the inspector with target filesystem mount points.

        Parameters:
            cgroup_root: Path to the cgroup v2 root filesystem (default: '/sys/fs/cgroup').
            proc_root: Path to the procfs mount (default: '/proc').
        """
        ## Store the root path of the cgroup v2 unified filesystem hierarchy
        self.cgroup_root: Path = Path(cgroup_root)
        ## Store the root path of the procfs virtual filesystem
        self.proc_root: Path = Path(proc_root)

    def is_cgroup_v2_available(self) -> bool:
        """
        Determines whether the host operates a unified cgroup v2 filesystem.

        Detection Logic:
        1. Verifies that the root path exists and is a directory.
        2. Checks for the presence of `cgroup.controllers`, which is unique to cgroup v2.
           (cgroup v1 hosts separate controller mount points like /sys/fs/cgroup/memory).

        Returns:
            bool: True if cgroup v2 unified hierarchy is active, False otherwise.
        """
        ## Check if the cgroup root path exists on disk and is a valid directory
        if not self.cgroup_root.exists() or not self.cgroup_root.is_dir():
            return False

        ## Construct path to the root controller specification file
        marker_file: Path = self.cgroup_root / "cgroup.controllers"
        ## cgroup.controllers is only present at the root of a unified cgroup v2 tree
        return marker_file.exists()

    def _read_file_safe(self, path: Path) -> Optional[str]:
        """
        Safely reads the entire contents of a pseudofile, handling missing paths
        or permission restrictions gracefully.

        Parameters:
            path: Path object to read.

        Returns:
            Optional[str]: Stripped text content, or None if reading failed.
        """
        try:
            ## Ensure target exists and is a regular file or readable pseudofile
            if not path.is_file():
                return None
            ## Read file text using UTF-8 encoding and strip leading/trailing whitespace
            return path.read_text(encoding="utf-8").strip()
        except (OSError, PermissionError, UnicodeDecodeError):
            ## Return None safely on permission denial, missing file, or decode error
            return None

    def _parse_int_or_none(self, content: Optional[str]) -> Optional[int]:
        """
        Parses an integer from pseudofile text. Translates 'max' into -1.

        Parameters:
            content: Raw string from cgroup pseudofile.

        Returns:
            Optional[int]: Integer value, -1 for 'max', or None if invalid.
        """
        ## Return None if input string is missing
        if content is None:
            return None

        ## Clean and normalize the text
        text: str = content.strip().lower()

        ## Translate kernel keywords representing unbounded resources to -1
        if text in ("max", "infinity"):
            return -1

        try:
            ## Convert numeric text directly to an integer
            return int(text)
        except ValueError:
            ## Return None if string does not represent a valid base-10 integer
            return None

    def read_host_memory_info(self) -> HostMemoryInfo:
        """
        Parses `/proc/meminfo` to capture physical hardware RAM and swap allocations.

        Educational Detail:
        -------------------
        Linux memory management differentiates between:
        - MemTotal: Total physical RAM usable by the kernel (excluding reserved firmware memory).
        - MemFree: Memory currently unallocated to any cache, buffer, or process.
        - MemAvailable: An estimation of how much memory is available for starting new applications
          without swapping. Unlike MemFree, this counts reclaimable page cache and slab memory.
        - Cached: File-backed page cache memory, which can be discarded or written back to disk.
        - SwapTotal / SwapFree: Secondary storage pagination space.

        Returns:
            HostMemoryInfo: High-precision memory statistics in bytes.
        """
        ## Construct path to the host meminfo pseudofile
        meminfo_path: Path = self.proc_root / "meminfo"
        ## Safely read the entire text of /proc/meminfo
        raw_text: str = self._read_file_safe(meminfo_path) or ""

        ## Initialize storage dictionary with 0 bytes for all essential memory fields
        metrics: Dict[str, int] = {
            "MemTotal": 0,
            "MemAvailable": 0,
            "MemFree": 0,
            "Cached": 0,
            "SwapTotal": 0,
            "SwapFree": 0,
        }

        ## Iterate line by line through the meminfo output
        for line in raw_text.splitlines():
            ## Clean leading and trailing whitespace
            clean_line: str = line.strip()
            ## Skip empty lines
            if not clean_line:
                continue

            ## Split line into key and value around the colon separator
            parts = clean_line.split(":", 1)
            ## Check if line contains a valid key-value pair
            if len(parts) == 2:
                ## Extract and trim key name
                key: str = parts[0].strip()
                ## Process only the metrics we care about
                if key in metrics:
                    ## Search for numeric sequence in the value portion
                    val_match = re.search(r"(\d+)", parts[1])
                    if val_match:
                        ## /proc/meminfo reports values in kB (kibibytes = 1024 bytes)
                        metrics[key] = int(val_match.group(1)) * 1024

        ## Return strongly typed HostMemoryInfo instance populated with byte counts
        return HostMemoryInfo(
            total_bytes=metrics["MemTotal"],
            available_bytes=metrics["MemAvailable"],
            free_bytes=metrics["MemFree"],
            cached_bytes=metrics["Cached"],
            swap_total_bytes=metrics["SwapTotal"],
            swap_free_bytes=metrics["SwapFree"],
        )

    def read_psi(self, resource: str = "memory") -> Optional[PSISnapshot]:
        """
        Parses Pressure Stall Information (PSI) from `/proc/pressure/<resource>`.

        Educational Detail:
        -------------------
        Developed by Facebook and upstreamed in Linux 4.20, PSI replaces imprecise
        CPU load averages and subjective free memory heuristics with deterministic
        loss-of-throughput time measurements.

        A typical `/proc/pressure/memory` output:
            some avg10=0.00 avg60=0.00 avg300=0.00 total=123456
            full avg10=0.00 avg60=0.00 avg300=0.00 total=654321

        - 'some' indicates periods where at least one non-idle task was stalled waiting
          for page reclaim or swap I/O.
        - 'full' indicates periods where ALL runnable tasks were simultaneously stalled,
          meaning zero productive CPU cycles were executed. This is the definition of
          a system-wide desktop freeze / thrash.

        Parameters:
            resource: Resource type ('memory', 'cpu', or 'io').

        Returns:
            Optional[PSISnapshot]: Parsed PSI metric snapshot, or None if unavailable.
        """
        ## Construct path to the target PSI interface pseudofile
        psi_path: Path = self.proc_root / "pressure" / resource
        ## Safely read the pseudofile content
        raw_text: Optional[str] = self._read_file_safe(psi_path)
        ## If pseudofile does not exist or kernel lacks PSI support, return None
        if not raw_text:
            return None

        ## Initialize metric holders for 'some' and 'full' contention models
        some_metric: Optional[PSIMetric] = None
        full_metric: Optional[PSIMetric] = None

        ## Regex pattern matching standard Linux PSI output line format
        line_regex = re.compile(
            r"^(some|full)\s+avg10=([0-9\.]+)\s+avg60=([0-9\.]+)\s+avg300=([0-9\.]+)\s+total=(\d+)"
        )

        ## Parse each line in the PSI file
        for line in raw_text.splitlines():
            ## Strip whitespace
            clean_line: str = line.strip()
            ## Attempt to match regex pattern against the line
            match = line_regex.match(clean_line)
            ## Skip unrecognized lines
            if not match:
                continue

            ## Unpack matched groups: category name, 10s, 60s, 300s averages, and total microseconds
            category, a10, a60, a300, total = match.groups()
            ## Instantiate strongly typed PSIMetric container
            metric = PSIMetric(
                avg10=float(a10),
                avg60=float(a60),
                avg300=float(a300),
                total_us=int(total),
            )

            ## Assign to appropriate contention category
            if category == "some":
                some_metric = metric
            elif category == "full":
                full_metric = metric

        ## Return aggregated PSISnapshot with current timestamp
        return PSISnapshot(
            resource=resource,
            some=some_metric,
            full=full_metric,
            timestamp=time.time(),
        )

    def inspect_cgroup(self, relative_path: str = "") -> Optional[CgroupNode]:
        """
        Inspects a specific cgroup directory node inside the unified hierarchy.

        Parameters:
            relative_path: Relative path from cgroup root, e.g. 'system.slice/sshd.service'.
                           Empty string inspects the root cgroup.

        Returns:
            Optional[CgroupNode]: Detailed cgroup state, or None if path does not exist.
        """
        ## Resolve absolute path to target cgroup directory
        target_dir: Path = self.cgroup_root / relative_path.lstrip("/")
        ## Verify directory existence
        if not target_dir.exists() or not target_dir.is_dir():
            return None

        ## 1. Read enabled controllers from cgroup.controllers
        controllers_raw: str = self._read_file_safe(target_dir / "cgroup.controllers") or ""
        ## Split whitespace-separated controller names into a list
        controllers: List[str] = controllers_raw.split() if controllers_raw else []

        ## 2. Read attached process IDs from cgroup.procs
        procs_raw: str = self._read_file_safe(target_dir / "cgroup.procs") or ""
        pids: List[int] = []
        ## Extract numeric PID values line by line
        for line in procs_raw.splitlines():
            clean_pid: str = line.strip()
            ## Ensure line is numeric before converting to int
            if clean_pid.isdigit():
                pids.append(int(clean_pid))

        ## 3. Read live memory metrics
        ## Read current total memory allocation in bytes
        mem_current: Optional[int] = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.current"))
        ## Read hard ceiling memory boundary (returns -1 if 'max')
        mem_max: Optional[int] = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.max"))
        ## Read throttling high watermark boundary (returns -1 if 'max')
        mem_high: Optional[int] = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.high"))

        ## Read swap controller metrics
        mem_swap_current: Optional[int] = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.swap.current"))
        mem_swap_max: Optional[int] = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.swap.max"))

        ## 4. Read CPU limits: cpu.max contains "quota period", e.g., "50000 100000" or "max 100000"
        cpu_quota: Optional[int] = None
        cpu_period: Optional[int] = None
        cpu_max_raw: Optional[str] = self._read_file_safe(target_dir / "cpu.max")
        if cpu_max_raw:
            parts = cpu_max_raw.split()
            ## Standard format: quota period (two elements)
            if len(parts) >= 2:
                ## If quota is 'max', represent as -1
                cpu_quota = -1 if parts[0] == "max" else int(parts[0])
                cpu_period = int(parts[1])
            ## Unbounded format: 'max' alone with default 100ms period
            elif len(parts) == 1 and parts[0] == "max":
                cpu_quota = -1
                cpu_period = 100000

        ## 5. Read PID / Task metrics
        ## Read currently active threads and processes
        pids_current: Optional[int] = self._parse_int_or_none(self._read_file_safe(target_dir / "pids.current"))
        ## Read maximum tasks allowed
        pids_max: Optional[int] = self._parse_int_or_none(self._read_file_safe(target_dir / "pids.max"))

        ## Construct and return populated CgroupNode dataclass
        return CgroupNode(
            path=str(target_dir),
            relative_path=relative_path,
            controllers=controllers,
            memory_current=mem_current,
            memory_max=mem_max,
            memory_high=mem_high,
            memory_swap_current=mem_swap_current,
            memory_swap_max=mem_swap_max,
            cpu_max_quota=cpu_quota,
            cpu_max_period=cpu_period,
            pids_current=pids_current,
            pids_max=pids_max,
            pids=pids,
        )

    def find_process_cgroup(self, pid: int) -> Optional[str]:
        """
        Determines the cgroup v2 relative path hosting a given process ID.

        Reads `/proc/<pid>/cgroup`.
        In cgroup v2, this file contains a single line formatted as:
            0::<relative-path>
        Example:
            0::/system.slice/systemd-resolved.service

        Parameters:
            pid: The process ID to inspect.

        Returns:
            Optional[str]: Relative cgroup path (e.g. 'system.slice/sshd.service'),
                           or None if unreadable.
        """
        ## Construct path to the process cgroup membership file
        proc_cgroup_file: Path = self.proc_root / str(pid) / "cgroup"
        ## Safely read the pseudofile text
        raw_text: Optional[str] = self._read_file_safe(proc_cgroup_file)
        if not raw_text:
            return None

        ## Iterate lines looking for the unified cgroup v2 entry (prefix '0::')
        for line in raw_text.splitlines():
            clean_line: str = line.strip()
            ## Check if line starts with unified hierarchy prefix '0::'
            if clean_line.startswith("0::"):
                ## Strip the '0::' prefix and any leading slash to return relative path
                return clean_line[3:].lstrip("/")

        return None

    def read_process_oom_score_adj(self, pid: int) -> Optional[int]:
        """
        Reads `/proc/<pid>/oom_score_adj` to determine how the kernel OOM killer
        prioritizes this process when physical memory is exhausted.

        Educational Detail:
        -------------------
        - Negative values (-1 to -999) decrease likelihood of being killed.
        - -1000 completely exempts the process from the OOM killer (OOM_SCORE_ADJ_MIN).
        - Positive values (+1 to +1000) proportionally increase likelihood of being killed.
        - Background daemons SHOULD have positive oom_score_adj (e.g. +500) so the kernel
          kills the background daemon rather than terminating the user's graphical desktop session.

        Parameters:
            pid: Process ID.

        Returns:
            Optional[int]: OOM score adjust integer (-1000 to 1000), or None.
        """
        ## Path to the process OOM badness adjustment file
        path: Path = self.proc_root / str(pid) / "oom_score_adj"
        ## Safely read file text
        val_str: Optional[str] = self._read_file_safe(path)
        if val_str is not None:
            try:
                ## Convert to integer in range [-1000, 1000]
                return int(val_str)
            except ValueError:
                ## Return None if file contains unparseable text
                pass
        return None
