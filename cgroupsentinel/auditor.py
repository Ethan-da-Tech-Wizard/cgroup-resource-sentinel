"""
Program: Cgroup Resource Sentinel - Systemd Unit Auditor
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Audit systemd service unit files and drop-in overrides to identify missing cgroup v2 resource limits and calculate risk scores.
"""

from __future__ import annotations

## Operating system utilities for path expansion and environment access
import os
## Object-oriented filesystem path operations
from pathlib import Path
## Typing annotations for static verification
from typing import Dict, List, Optional, Tuple

## Import domain models and conversion helpers
from .models import ResourceLimits, ServiceAudit, parse_human_bytes


class SystemdUnitAuditor:
    """
    Audits systemd service unit files to detect missing kernel cgroup v2 boundaries.

    Scans system and user unit directories, resolves systemd drop-in override
    hierarchies (`<unit>.service.d/*.conf`), and generates quantitative risk assessments.
    """

    ## Standard systemd search paths in descending priority order
    STANDARD_SYSTEM_PATHS: List[str] = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ]

    ## Standard user unit search paths in descending priority order
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
        ## Check if caller provided explicit custom search paths
        if search_paths is not None:
            ## Expand user tildes and convert to Path objects
            self.search_paths: List[Path] = [Path(os.path.expanduser(p)) for p in search_paths]
        else:
            ## Use standard systemd system paths by default
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
        ## Ensure the unit name has the '.service' suffix appended
        normalized: str = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"

        ## Iterate through search paths in priority order
        for base_dir in self.search_paths:
            ## Form candidate file path
            candidate: Path = base_dir / normalized
            ## Check if candidate exists as a file
            if candidate.is_file():
                ## Return resolved canonical absolute path
                return candidate.resolve()

        ## Return None if unit file was not found in any search path
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
        ## Ensure proper .service suffix
        normalized: str = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"
        ## Standard drop-in directory naming convention: <name>.service.d
        drop_in_dir_name: str = f"{normalized}.d"
        ## Accumulator for discovered drop-in configuration files
        drop_ins: List[Path] = []

        ## Check each search path for the drop-in override directory
        for base_dir in self.search_paths:
            drop_in_dir: Path = base_dir / drop_in_dir_name
            ## If the override directory exists, discover all *.conf snippets
            if drop_in_dir.is_dir():
                ## Sort lexicographically to honor systemd drop-in evaluation ordering
                for conf_file in sorted(drop_in_dir.glob("*.conf")):
                    if conf_file.is_file():
                        ## Append resolved canonical path
                        drop_ins.append(conf_file.resolve())

        ## Return sorted list of drop-in files
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
        ## Outer dictionary mapping section name -> {key: value}
        sections: Dict[str, Dict[str, str]] = {}
        ## Pointer tracking the active section name being parsed
        current_section: Optional[str] = None

        try:
            ## Read entire file as UTF-8 string
            content: str = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            ## Return empty sections on read failure or encoding error
            return sections

        ## Split file into individual lines
        raw_lines: List[str] = content.splitlines()
        ## List for holding processed lines after resolving backslash continuations
        merged_lines: List[str] = []
        ## Temporary buffer for multi-line continuation strings
        continuation_buffer: str = ""

        ## First pass: merge lines ending with backslash '\'
        for line in raw_lines:
            stripped: str = line.strip()
            ## If line ends with backslash, strip backslash and accumulate in buffer
            if stripped.endswith("\\"):
                continuation_buffer += stripped[:-1].strip() + " "
            else:
                ## If continuation buffer was active, append merged line
                if continuation_buffer:
                    merged_lines.append(continuation_buffer + stripped)
                    continuation_buffer = ""
                else:
                    merged_lines.append(stripped)

        ## Flush any remaining continuation buffer
        if continuation_buffer:
            merged_lines.append(continuation_buffer)

        ## Second pass: parse sections and key-value pairs
        for line in merged_lines:
            ## Skip blank lines and comment lines (starting with # or ;)
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            ## Detect section header: [SectionName]
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip()
                if current_section not in sections:
                    sections[current_section] = {}
                continue

            ## Detect key-value pair within active section
            if current_section and "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                ## Store directive in current section dictionary
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
        ## Find the base service unit file
        unit_file: Optional[Path] = self.find_unit_file(unit_name)
        ## Dictionary to accumulate merged [Service] directives
        combined_service_props: Dict[str, str] = {}

        ## If base unit file exists, parse its [Service] section
        if unit_file:
            parsed = self.parse_systemd_ini(unit_file)
            if "Service" in parsed:
                combined_service_props.update(parsed["Service"])

        ## Discover and layer on all drop-in overrides in lexicographical order
        drop_ins: List[Path] = self.find_drop_ins(unit_name)
        for drop_in in drop_ins:
            parsed = self.parse_systemd_ini(drop_in)
            if "Service" in parsed:
                ## Overwrite or add directives from drop-in
                combined_service_props.update(parsed["Service"])

        ## Return merged service properties and the path to the base unit file
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
        ## Normalize unit name with .service extension
        normalized: str = unit_name if unit_name.endswith(".service") else f"{unit_name}.service"
        ## Load merged directives from base unit file and drop-in overrides
        props, unit_file = self.load_combined_unit_properties(normalized)

        ## Check if unit file could not be found anywhere
        if not unit_file and not props:
            return ServiceAudit(
                unit_name=normalized,
                unit_path=None,
                is_present=False,
                violations=["Service unit file not found in any standard search path"],
                recommendations=["Verify unit name or specify full path to the unit file"],
                risk_score=50,
            )

        ## Container for parsed effective limits
        limits = ResourceLimits()
        ## List for storing detected boundary violations
        violations: List[str] = []
        ## List for storing actionable remediation steps
        recommendations: List[str] = []
        ## Cumulative risk score counter
        risk_score: int = 0

        ## 1. Audit MemoryMax (hard physical RAM boundary)
        mem_max_str = props.get("MemoryMax") or props.get("MemoryLimit")
        has_mem_max = bool(mem_max_str and mem_max_str.strip().lower() not in ("infinity", "max", ""))
        if has_mem_max:
            try:
                ## Parse memory string to byte integer
                limits.memory_max = parse_human_bytes(mem_max_str)
            except ValueError:
                ## Flag invalid format syntax error
                violations.append(f"Invalid MemoryMax format: '{mem_max_str}'")
                risk_score += 15
        else:
            ## Missing memory ceiling is the single greatest hazard for host stability
            violations.append("Missing MemoryMax ceiling (Unconstrained physical RAM allocation)")
            recommendations.append("Define MemoryMax in a drop-in override (e.g. MemoryMax=2G)")
            risk_score += 35

        ## 2. Audit MemorySwapMax (swap pagination boundary)
        mem_swap_str = props.get("MemorySwapMax")
        has_mem_swap_max = bool(mem_swap_str and mem_swap_str.strip().lower() not in ("infinity", "max", ""))
        if has_mem_swap_max:
            try:
                ## Parse swap string to byte integer
                limits.memory_swap_max = parse_human_bytes(mem_swap_str)
            except ValueError:
                violations.append(f"Invalid MemorySwapMax format: '{mem_swap_str}'")
                risk_score += 5
        else:
            ## Uncapped swap causes SSD write amplification, I/O latency spikes, and GUI stutter
            violations.append("Missing MemorySwapMax limit (Runaway memory may thrash swap SSD/disk)")
            recommendations.append("Define MemorySwapMax=0 (to forbid swap) or cap strictly")
            risk_score += 15

        ## 3. Audit CPUQuota (CPU bandwidth quota)
        cpu_quota_str = props.get("CPUQuota")
        has_cpu_quota = bool(cpu_quota_str and cpu_quota_str.strip())
        if has_cpu_quota:
            clean_cpu = cpu_quota_str.rstrip("%").strip()
            try:
                ## Parse percentage value as float
                limits.cpu_quota_percent = float(clean_cpu)
            except ValueError:
                violations.append(f"Invalid CPUQuota format: '{cpu_quota_str}'")
                risk_score += 5
        else:
            ## Missing CPU quota can allow runaway loops to starve the display server
            violations.append("Missing CPUQuota limit (Runaway loop can starve desktop compositor)")
            recommendations.append("Define CPUQuota (e.g. CPUQuota=100% for 1 core cap)")
            risk_score += 15

        ## 4. Audit TasksMax (task / PID thread count ceiling)
        tasks_max_str = props.get("TasksMax")
        has_tasks_max = bool(tasks_max_str and tasks_max_str.strip().lower() not in ("infinity", "max", ""))
        if has_tasks_max:
            try:
                ## Parse task count as integer
                limits.tasks_max = int(tasks_max_str)
            except ValueError:
                violations.append(f"Invalid TasksMax format: '{tasks_max_str}'")
                risk_score += 5
        else:
            ## Missing TasksMax exposes system to thread leaks and fork bombs
            violations.append("Missing TasksMax limit (Vulnerable to fork bombs and thread exhaustion)")
            recommendations.append("Define TasksMax (e.g. TasksMax=512) to bound thread count")
            risk_score += 15

        ## 5. Audit OOMPolicy (behavior when cgroup memory ceiling is breached)
        oom_policy_str = props.get("OOMPolicy")
        has_oom_policy = bool(oom_policy_str and oom_policy_str.strip().lower() in ("stop", "kill"))
        if has_oom_policy:
            limits.oom_policy = oom_policy_str.strip().lower()
        else:
            violations.append("Missing or unsafe OOMPolicy (Recommended: 'stop' or 'kill')")
            recommendations.append("Set OOMPolicy=stop to cleanly terminate failed service on OOM")
            risk_score += 10

        ## 6. Audit OOMScoreAdjust (kernel badness bias)
        oom_score_str = props.get("OOMScoreAdjust")
        has_oom_score: bool = False
        if oom_score_str:
            try:
                val: int = int(oom_score_str)
                limits.oom_score_adjust = val
                ## Positive score ensures background service is sacrificed before GUI / browser
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

        ## Clamp cumulative risk score to standard 0-100 range
        clamped_risk: int = min(100, max(0, risk_score))

        ## Assemble and return completed ServiceAudit report
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
        ## Accumulator for directory audit results
        results: List[ServiceAudit] = []
        ## Verify that target path is an existing directory
        if not dir_path.is_dir():
            return results

        ## Temporarily prepend directory to search paths to ensure local overrides resolve
        original_paths: List[Path] = list(self.search_paths)
        self.search_paths.insert(0, dir_path)

        try:
            ## Scan for all files matching '*.service' pattern in alphabetical order
            for service_file in sorted(dir_path.glob("*.service")):
                if service_file.is_file():
                    ## Audit individual service unit
                    audit: ServiceAudit = self.audit_unit(service_file.name)
                    results.append(audit)
        finally:
            ## Restore original search paths configuration
            self.search_paths = original_paths

        return results
