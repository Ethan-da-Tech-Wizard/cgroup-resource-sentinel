"""
cgroupsentinel.inspector
========================

Linux cgroup v2 unified hierarchy explorer, /proc filesystem parser,
and Pressure Stall Information (PSI) telemetry collector.

Educational Architecture Note:
------------------------------
The Linux cgroup v2 unified hierarchy mounts at `/sys/fs/cgroup`.
In cgroup v2, there is only ONE single tree hierarchy for all controllers.
Controllers are explicitly delegated downwards through `cgroup.subtree_control`.
A child cgroup can only regulate a resource if its parent cgroup enabled that
controller in `cgroup.subtree_control`.

Virtual Filesystem (VFS) Pseudofiles:
-------------------------------------
Pseudofiles under `/sys/fs/cgroup` and `/proc` do not reside on physical storage;
they are dynamically synthesized on the fly by kernel routines when read() is called.
- `cgroup.controllers`: Lists controllers supported and enabled by the parent.
- `cgroup.procs`: Lists the PIDs of all processes residing in this specific cgroup node.
  In cgroup v2, internal nodes cannot host processes if child cgroups enable controllers
  ("no internal process rule").
- `memory.current`: Total memory consumed by the cgroup (anonymous memory, page cache,
  kernel page tables, and slab memory).
- `memory.max`: Hard upper limit for memory allocation. If reached, the kernel triggers
  in-cgroup memory reclamation; if failed, the cgroup-scoped OOM killer is dispatched.
- `memory.swap.max`: Maximum swap space this cgroup is permitted to claim.
- `cpu.max`: Quota and period (e.g. '50000 100000' = 50% CPU allocation per 100ms).
- `pids.max`: Ceiling on total number of processes/threads in this cgroup.
- `/proc/pressure/memory`: Linux kernel PSI interface quantifying stall times.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
        self.cgroup_root = Path(cgroup_root)
        self.proc_root = Path(proc_root)

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
        if not self.cgroup_root.exists() or not self.cgroup_root.is_dir():
            return False

        # cgroup.controllers is the definitive marker of a cgroup v2 unified root
        marker_file = self.cgroup_root / "cgroup.controllers"
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
            if not path.is_file():
                return None
            return path.read_text(encoding="utf-8").strip()
        except (OSError, PermissionError, UnicodeDecodeError):
            return None

    def _parse_int_or_none(self, content: Optional[str]) -> Optional[int]:
        """
        Parses an integer from pseudofile text. Translates 'max' into -1.

        Parameters:
            content: Raw string from cgroup pseudofile.

        Returns:
            Optional[int]: Integer value, -1 for 'max', or None if invalid.
        """
        if content is None:
            return None
        text = content.strip().lower()
        if text in ("max", "infinity"):
            return -1
        try:
            return int(text)
        except ValueError:
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
        meminfo_path = self.proc_root / "meminfo"
        raw_text = self._read_file_safe(meminfo_path) or ""

        # Default fallback values (0 if missing/unreadable)
        metrics: Dict[str, int] = {
            "MemTotal": 0,
            "MemAvailable": 0,
            "MemFree": 0,
            "Cached": 0,
            "SwapTotal": 0,
            "SwapFree": 0,
        }

        # Each line in /proc/meminfo has format: Key:\s+Value\s+kB
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                if key in metrics:
                    # Parse numeric value (usually in KiB)
                    val_match = re.search(r"(\d+)", parts[1])
                    if val_match:
                        # /proc/meminfo values are in kB (kibibytes = 1024 bytes)
                        metrics[key] = int(val_match.group(1)) * 1024

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
        psi_path = self.proc_root / "pressure" / resource
        raw_text = self._read_file_safe(psi_path)
        if not raw_text:
            return None

        some_metric: Optional[PSIMetric] = None
        full_metric: Optional[PSIMetric] = None

        line_regex = re.compile(
            r"^(some|full)\s+avg10=([0-9\.]+)\s+avg60=([0-9\.]+)\s+avg300=([0-9\.]+)\s+total=(\d+)"
        )

        for line in raw_text.splitlines():
            line = line.strip()
            match = line_regex.match(line)
            if not match:
                continue

            category, a10, a60, a300, total = match.groups()
            metric = PSIMetric(
                avg10=float(a10),
                avg60=float(a60),
                avg300=float(a300),
                total_us=int(total),
            )

            if category == "some":
                some_metric = metric
            elif category == "full":
                full_metric = metric

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
        target_dir = self.cgroup_root / relative_path.lstrip("/")
        if not target_dir.exists() or not target_dir.is_dir():
            return None

        # 1. Read enabled controllers
        controllers_raw = self._read_file_safe(target_dir / "cgroup.controllers") or ""
        controllers = controllers_raw.split() if controllers_raw else []

        # 2. Read attached process IDs
        procs_raw = self._read_file_safe(target_dir / "cgroup.procs") or ""
        pids: List[int] = []
        for line in procs_raw.splitlines():
            line = line.strip()
            if line.isdigit():
                pids.append(int(line))

        # 3. Read memory metrics
        mem_current = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.current"))
        mem_max = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.max"))
        mem_high = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.high"))

        # Swap metrics
        mem_swap_current = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.swap.current"))
        mem_swap_max = self._parse_int_or_none(self._read_file_safe(target_dir / "memory.swap.max"))

        # 4. Read CPU limits: cpu.max contains "quota period", e.g., "50000 100000" or "max 100000"
        cpu_quota: Optional[int] = None
        cpu_period: Optional[int] = None
        cpu_max_raw = self._read_file_safe(target_dir / "cpu.max")
        if cpu_max_raw:
            parts = cpu_max_raw.split()
            if len(parts) >= 2:
                cpu_quota = -1 if parts[0] == "max" else int(parts[0])
                cpu_period = int(parts[1])
            elif len(parts) == 1 and parts[0] == "max":
                cpu_quota = -1
                cpu_period = 100000

        # 5. Read PID / Task metrics
        pids_current = self._parse_int_or_none(self._read_file_safe(target_dir / "pids.current"))
        pids_max = self._parse_int_or_none(self._read_file_safe(target_dir / "pids.max"))

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
        proc_cgroup_file = self.proc_root / str(pid) / "cgroup"
        raw_text = self._read_file_safe(proc_cgroup_file)
        if not raw_text:
            return None

        # Look for the unified v2 entry starting with '0::'
        for line in raw_text.splitlines():
            line = line.strip()
            if line.startswith("0::"):
                return line[3:].lstrip("/")

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
        path = self.proc_root / str(pid) / "oom_score_adj"
        val_str = self._read_file_safe(path)
        if val_str is not None:
            try:
                return int(val_str)
            except ValueError:
                pass
        return None
