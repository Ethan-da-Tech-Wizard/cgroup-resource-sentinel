"""
cgroupsentinel.auditor
======================

Systemd unit configuration auditor and resource gap analysis engine.

Educational Architecture Note:
------------------------------
In modern Linux distributions running systemd as PID 1, systemd manages the cgroup v2
hierarchy automatically. When a service is started, systemd allocates a dedicated cgroup
node for that unit (typically within `system.slice/<service>.service` for system daemons,
or `user.slice/user-<uid>.slice/user@<uid>.service/app.slice/...` for user sessions).

The Critical Risk of Unbounded Services:
----------------------------------------
By default, upstream package maintainers rarely configure resource boundaries in stock
vendor unit files (`/usr/lib/systemd/system/*.service`).
Without explicit limits:
1. An unconstrained service can exhaust host RAM, forcing the Linux kernel to reclaim
   all filesystem page cache.
2. The system enters catastrophic page thrashing (dirty writeback + swap-in loops).
3. The X11/Wayland display server and desktop compositor drop frames, audio stutters,
   and mouse cursor movement freezes completely.
4. When the Linux Out-Of-Memory (OOM) killer finally wakes up, its heuristic score
   (`badness()` calculation) considers total page count, often terminating the user's
   browser or desktop session instead of the offending background service.

This auditor evaluates systemd `.service` unit files against safe cgroup v2 boundaries,
computes a quantitative Risk Score (0-100), and outputs specific remediation guidance.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import ResourceLimits, ServiceAudit, parse_human_bytes


class SystemdUnitAuditor:
    """
    Audits systemd service unit files to detect missing kernel cgroup v2 boundaries.

    Scans system and user unit directories, resolves systemd drop-in override
    hierarchies (`<unit>.service.d/*.conf`), and generates quantitative risk assessments.
    """

    # Standard systemd search paths in descending priority order
    STANDARD_SYSTEM_PATHS: List[str] = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ]

    STANDARD_USER_PATHS: List[str] = [
        "~/.config/systemd/user",
        "/etc/systemd/user",
        "/usr/local/lib/systemd/user",
        "/usr/lib/systemd/user",
    ]

    def __init__(self, search_paths: Optional[List[str]] = None) -> None:
        """
        Initializes the auditor with a customized or standard set of search paths.

        Parameters:
            search_paths: List of directory paths to search for unit files.
                          If None, defaults to standard system locations.
        """
        if search_paths is not None:
            self.search_paths = [Path(os.path.expanduser(p)) for p in search_paths]
        else:
            self.search_paths = [
                Path(os.path.expanduser(p)) for p in self.STANDARD_SYSTEM_PATHS
            ]

    def find_unit_file(self, unit_name: str) -> Optional[Path]:
        """
        Searches configured paths for a matching unit file.

        Parameters:
            unit_name: Name of the unit (e.g. 'docker.service' or 'docker').

        Returns:
            Optional[Path]: Absolute path to the highest-priority unit file, or None.
        """
        # Ensure name ends with .service
        normalized = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"

        for base_dir in self.search_paths:
            candidate = base_dir / normalized
            if candidate.is_file():
                return candidate.resolve()

        return None

    def find_drop_ins(self, unit_name: str) -> List[Path]:
        """
        Discovers all drop-in configuration snippets (`<unit>.service.d/*.conf`)
        in standard systemd override directories.

        Educational Detail:
        -------------------
        Systemd loads drop-ins in lexicographical order across all search paths.
        Drop-ins in `/etc/systemd/system/` override drop-ins of the same name
        in `/usr/lib/systemd/system/`.

        Parameters:
            unit_name: Base unit name.

        Returns:
            List[Path]: Sorted list of resolved drop-in configuration files.
        """
        normalized = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"
        drop_in_dir_name = f"{normalized}.d"
        drop_ins: List[Path] = []

        for base_dir in self.search_paths:
            drop_in_dir = base_dir / drop_in_dir_name
            if drop_in_dir.is_dir():
                for conf_file in sorted(drop_in_dir.glob("*.conf")):
                    if conf_file.is_file():
                        drop_ins.append(conf_file.resolve())

        return drop_ins

    def parse_systemd_ini(self, file_path: Path) -> Dict[str, Dict[str, str]]:
        """
        Parses systemd-style INI configuration syntax.

        Systemd Parser Specifications:
        - Sections defined by `[SectionName]`.
        - Lines starting with `#` or `;` are comments.
        - Backslash `\\` at end of line indicates line continuation.
        - Key-value pairs separated by `=` (e.g. `MemoryMax=2G`).
        - Directives can be overridden or cleared by setting `Directive=` with empty value.

        Parameters:
            file_path: Path to the .service or drop-in .conf file.

        Returns:
            Dict[str, Dict[str, str]]: Parsed sections and key-value properties.
        """
        sections: Dict[str, Dict[str, str]] = {}
        current_section: Optional[str] = None

        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return sections

        # Handle line continuations (lines ending with backslash)
        raw_lines = content.splitlines()
        merged_lines: List[str] = []
        continuation_buffer = ""

        for line in raw_lines:
            stripped = line.strip()
            if stripped.endswith("\\"):
                continuation_buffer += stripped[:-1].strip() + " "
            else:
                if continuation_buffer:
                    merged_lines.append(continuation_buffer + stripped)
                    continuation_buffer = ""
                else:
                    merged_lines.append(stripped)

        if continuation_buffer:
            merged_lines.append(continuation_buffer)

        for line in merged_lines:
            # Skip empty lines and comments
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            # Section header
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip()
                if current_section not in sections:
                    sections[current_section] = {}
                continue

            # Key-value assignment within section
            if current_section and "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                sections[current_section][key] = val

        return sections

    def load_combined_unit_properties(self, unit_name: str) -> Tuple[Dict[str, str], Optional[Path]]:
        """
        Loads and merges the base unit file and all discovered drop-in overrides.

        Parameters:
            unit_name: Name of the service unit.

        Returns:
            Tuple[Dict[str, str], Optional[Path]]: Merged [Service] section properties
                                                   and the primary unit file path.
        """
        unit_file = self.find_unit_file(unit_name)
        combined_service_props: Dict[str, str] = {}

        if unit_file:
            parsed = self.parse_systemd_ini(unit_file)
            if "Service" in parsed:
                combined_service_props.update(parsed["Service"])

        # Layer on drop-in overrides
        drop_ins = self.find_drop_ins(unit_name)
        for drop_in in drop_ins:
            parsed = self.parse_systemd_ini(drop_in)
            if "Service" in parsed:
                combined_service_props.update(parsed["Service"])

        return combined_service_props, unit_file

    def audit_unit(self, unit_name: str) -> ServiceAudit:
        """
        Performs a deep audit on a specified systemd service.

        Evaluates cgroup v2 resource limits and calculates a risk score (0-100):
        - MemoryMax missing: +35 points
        - MemorySwapMax missing: +15 points
        - CPUQuota missing: +15 points
        - TasksMax missing: +15 points
        - OOMPolicy missing or unsafe: +10 points
        - OOMScoreAdjust missing or dangerous: +10 points

        Parameters:
            unit_name: Name of the service (e.g. 'ollama.service' or 'docker').

        Returns:
            ServiceAudit: Complete audit report with violations and recommendations.
        """
        normalized = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"
        props, unit_file = self.load_combined_unit_properties(normalized)

        if not unit_file and not props:
            return ServiceAudit(
                unit_name=normalized,
                unit_path=None,
                is_present=False,
                violations=["Service unit file not found in any standard search path"],
                recommendations=["Verify unit name or specify full path to the unit file"],
                risk_score=50,
            )

        limits = ResourceLimits()
        violations: List[str] = []
        recommendations: List[str] = []
        risk_score = 0

        # 1. Audit MemoryMax
        # Note: systemd supports 'MemoryMax=' and legacy 'MemoryLimit='
        mem_max_str = props.get("MemoryMax") or props.get("MemoryLimit")
        has_mem_max = bool(mem_max_str and mem_max_str.strip().lower() not in ("infinity", "max", ""))
        if has_mem_max:
            try:
                limits.memory_max = parse_human_bytes(mem_max_str)
            except ValueError:
                violations.append(f"Invalid MemoryMax format: '{mem_max_str}'")
                risk_score += 15
        else:
            violations.append("Missing MemoryMax ceiling (Unconstrained physical RAM allocation)")
            recommendations.append("Define MemoryMax in a drop-in override (e.g. MemoryMax=2G)")
            risk_score += 35

        # 2. Audit MemorySwapMax
        mem_swap_str = props.get("MemorySwapMax")
        has_mem_swap_max = bool(mem_swap_str and mem_swap_str.strip().lower() not in ("infinity", "max", ""))
        if has_mem_swap_max:
            try:
                limits.memory_swap_max = parse_human_bytes(mem_swap_str)
            except ValueError:
                violations.append(f"Invalid MemorySwapMax format: '{mem_swap_str}'")
                risk_score += 5
        else:
            violations.append("Missing MemorySwapMax limit (Runaway memory may thrash swap SSD/disk)")
            recommendations.append("Define MemorySwapMax=0 (to forbid swap) or cap strictly")
            risk_score += 15

        # 3. Audit CPUQuota
        cpu_quota_str = props.get("CPUQuota")
        has_cpu_quota = bool(cpu_quota_str and cpu_quota_str.strip())
        if has_cpu_quota:
            clean_cpu = cpu_quota_str.rstrip("%").strip()
            try:
                limits.cpu_quota_percent = float(clean_cpu)
            except ValueError:
                violations.append(f"Invalid CPUQuota format: '{cpu_quota_str}'")
                risk_score += 5
        else:
            violations.append("Missing CPUQuota limit (Runaway loop can starve desktop compositor)")
            recommendations.append("Define CPUQuota (e.g. CPUQuota=100% for 1 core cap)")
            risk_score += 15

        # 4. Audit TasksMax
        tasks_max_str = props.get("TasksMax")
        has_tasks_max = bool(tasks_max_str and tasks_max_str.strip().lower() not in ("infinity", "max", ""))
        if has_tasks_max:
            try:
                limits.tasks_max = int(tasks_max_str)
            except ValueError:
                violations.append(f"Invalid TasksMax format: '{tasks_max_str}'")
                risk_score += 5
        else:
            violations.append("Missing TasksMax limit (Vulnerable to fork bombs and thread exhaustion)")
            recommendations.append("Define TasksMax (e.g. TasksMax=512) to bound thread count")
            risk_score += 15

        # 5. Audit OOMPolicy
        oom_policy_str = props.get("OOMPolicy")
        has_oom_policy = bool(oom_policy_str and oom_policy_str.strip().lower() in ("stop", "kill"))
        if has_oom_policy:
            limits.oom_policy = oom_policy_str.strip().lower()
        else:
            violations.append("Missing or unsafe OOMPolicy (Recommended: 'stop' or 'kill')")
            recommendations.append("Set OOMPolicy=stop to cleanly terminate failed service on OOM")
            risk_score += 10

        # 6. Audit OOMScoreAdjust
        oom_score_str = props.get("OOMScoreAdjust")
        has_oom_score = False
        if oom_score_str:
            try:
                val = int(oom_score_str)
                limits.oom_score_adjust = val
                # For background daemons, positive score (e.g. 500) ensures daemon is killed before UI
                if val > 0:
                    has_oom_score = True
                else:
                    violations.append(f"OOMScoreAdjust is <= 0 ({val}); background service should yield to GUI")
                    recommendations.append("Set OOMScoreAdjust=500 to protect interactive desktop sessions")
                    risk_score += 5
            except ValueError:
                violations.append(f"Invalid OOMScoreAdjust value: '{oom_score_str}'")
                risk_score += 5
        else:
            violations.append("Missing OOMScoreAdjust (Kernel may kill desktop/browser before this service)")
            recommendations.append("Set OOMScoreAdjust=500 to prioritize background service termination")
            risk_score += 10

        # Clamp total risk score to 0-100 range
        clamped_risk = min(100, max(0, risk_score))

        return ServiceAudit(
            unit_name=normalized,
            unit_path=str(unit_file) if unit_file else None,
            is_present=True,
            has_memory_max=has_mem_max,
            has_memory_swap_max=has_mem_swap_max,
            has_cpu_quota=has_cpu_quota,
            has_tasks_max=has_tasks_max,
            has_oom_policy=has_oom_policy,
            has_oom_score_adjust=has_oom_score,
            current_limits=limits,
            violations=violations,
            recommendations=recommendations,
            risk_score=clamped_risk,
        )

    def audit_directory(self, dir_path: Path) -> List[ServiceAudit]:
        """
        Audits all `.service` files found in a specified directory.

        Parameters:
            dir_path: Target directory to scan.

        Returns:
            List[ServiceAudit]: Audit reports for all discovered services.
        """
        results: List[ServiceAudit] = []
        if not dir_path.is_dir():
            return results

        # Temporarily prepend directory to search paths to ensure local overrides resolve
        original_paths = list(self.search_paths)
        self.search_paths.insert(0, dir_path)

        try:
            for service_file in sorted(dir_path.glob("*.service")):
                if service_file.is_file():
                    audit = self.audit_unit(service_file.name)
                    results.append(audit)
        finally:
            self.search_paths = original_paths

        return results
