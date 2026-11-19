# ==============================================================================
# Program: cli.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Interactive Command Line Interface for Cgroup Resource Sentinel.
#          Inputs: Command line arguments (audit, inspect, pressure, generate, report).
#          Outputs: Formatted ANSI terminal reports, generated systemd drop-ins,
#                   or structured JSON documents to stdout/stderr.
#          Design Rationale: Delivers unified operator tooling for inspecting live
#                            cgroup telemetry and automating host stability hardening.
# ==============================================================================

from __future__ import annotations

## Argument parsing for command-line arguments and subcommands
import argparse
## JSON formatting for machine-readable output mode
import json
## Operating system interface for environment variables
import os
## System-specific parameters and standard stream references
import sys
## Object-oriented filesystem path operations
from pathlib import Path
## Type hinting annotations
from typing import Any, Dict, List, Optional

## Import auditor for systemd unit file analysis
from .auditor import SystemdUnitAuditor
## Import drop-in generator for synthesizing configuration files
from .generator import DropInGenerator
## Import inspector for live cgroup v2 and PSI telemetry
from .inspector import CgroupInspector
## Import domain models and conversion helpers
from .models import (
    CgroupNode,
    HostMemoryInfo,
    PSISnapshot,
    ResourceLimits,
    ServiceAudit,
    format_bytes_human,
    parse_human_bytes,
)

## Check if stdout is an interactive terminal and NO_COLOR environment variable is absent
# Evaluated once at import: color is used only for real terminals, so piped
# output and JSON consumers never receive escape codes (NO_COLOR convention).
USE_COLOR: bool = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def colorize(text: str, color_code: str) -> str:
    """Wraps text in ANSI color escape sequences if colors are active."""
    ## If terminal colors are disabled, return raw text unchanged
    if not USE_COLOR:
        return text
    ## Return string wrapped in ANSI terminal color escape codes
    return f"\033[{color_code}m{text}\033[0m"


def bold(text: str) -> str:
    """Formats text in bold."""
    return colorize(text, "1")


def red(text: str) -> str:
    """Formats text in red."""
    return colorize(text, "31")


def green(text: str) -> str:
    """Formats text in green."""
    return colorize(text, "32")


def yellow(text: str) -> str:
    """Formats text in yellow."""
    return colorize(text, "33")


def blue(text: str) -> str:
    """Formats text in blue."""
    return colorize(text, "34")


def cyan(text: str) -> str:
    """Formats text in cyan."""
    return colorize(text, "36")


# Subcommand handlers below all return a process exit code (0 ok, 1 failure)
# and share one shape: build the helper objects, gather data, then either emit
# JSON (machine mode, no colors) or a human-readable report.
def cmd_audit(args: argparse.Namespace) -> int:
    """Executes the 'audit' subcommand."""
    ## Configure custom search path if supplied via CLI argument
    search_paths = [args.search_path] if args.search_path else None
    ## Instantiate auditor with configured search paths
    auditor = SystemdUnitAuditor(search_paths=search_paths)
    ## Target unit name or directory path
    target: Optional[str] = args.target

    ## List to accumulate individual audit reports
    audits: List[ServiceAudit] = []

    ## Check if explicit target was provided
    # Resolve the audit target three ways: directory, a literal .service file path,
    # or a bare unit name looked up through the auditor's search paths.
    if target:
        target_path = Path(target)
        ## If target is a directory, audit all .service files inside it
        if target_path.is_dir():
            audits = auditor.audit_directory(target_path)
        ## If target is a specific existing .service file, audit directly
        # A file path is audited through a throwaway auditor rooted at its parent
        # directory, so the unit is found by name there.
        elif target_path.is_file() and target_path.suffix == ".service":
            parent_auditor = SystemdUnitAuditor(search_paths=[str(target_path.parent)])
            audits = [parent_auditor.audit_unit(target_path.name)]
        ## Otherwise treat target as a service unit name to look up
        else:
            audits = [auditor.audit_unit(target)]
    else:
        ## Default mode: scan standard system units directory if present
        etc_systemd = Path("/etc/systemd/system")
        if etc_systemd.is_dir():
            audits = auditor.audit_directory(etc_systemd)
        else:
            audits = [auditor.audit_unit("systemd-resolved.service")]

    ## Check if output was requested in JSON format
    # JSON mode returns early so no colored or decorative text pollutes stdout.
    if args.json:
        out_list = []
        ## Transform each ServiceAudit dataclass into a JSON-serializable dictionary
        for a in audits:
            out_list.append({
                "unit_name": a.unit_name,
                "unit_path": a.unit_path,
                "is_present": a.is_present,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level,
                "is_safe": a.is_safe,
                "violations": a.violations,
                "recommendations": a.recommendations,
                "limits": {
                    "memory_max": a.current_limits.memory_max,
                    "memory_swap_max": a.current_limits.memory_swap_max,
                    "cpu_quota_percent": a.current_limits.cpu_quota_percent,
                    "tasks_max": a.current_limits.tasks_max,
                    "oom_policy": a.current_limits.oom_policy,
                    "oom_score_adjust": a.current_limits.oom_score_adjust,
                },
            })
        ## Print indented JSON string to stdout
        print(json.dumps(out_list, indent=2))
        return 0

    ## Terminal presentation header
    print(bold("\n=== Systemd Service Cgroup v2 Resource Audit ==="))
    print(f"Audited {len(audits)} service(s):\n")

    ## Flag tracking presence of any high or critical threat configurations
    # Remembered across the loop so the exit code can be decided after all output is shown.
    # Remembered across the loop so the exit code can be decided after all output is shown.
    has_critical_failure: bool = False

    ## Display findings for each audited service
    # Walk the results and map each risk level to a badge; HIGH and CRITICAL both
    # flip the flag that --strict later turns into a failing exit code.
    for a in audits:
        ## Assign visual badge based on evaluated risk level
        if a.risk_level == "CRITICAL":
            badge = red("[CRITICAL RISK]")
            has_critical_failure = True
        elif a.risk_level == "HIGH":
            badge = red("[HIGH RISK]")
            has_critical_failure = True
        elif a.risk_level == "MEDIUM":
            badge = yellow("[MEDIUM RISK]")
        else:
            badge = green("[SAFE]")

        print(f"  {bold(a.unit_name)} {badge} (Score: {a.risk_score}/100)")
        if a.unit_path:
            print(f"    Path: {cyan(a.unit_path)}")

        ## Print detected boundary violations
        if a.violations:
            print("    Violations:")
            for v in a.violations:
                print(f"      {red('✗')} {v}")

        ## Print actionable recommendations
        if a.recommendations:
            print("    Recommendations:")
            for r in a.recommendations:
                print(f"      {blue('→')} {r}")
        print()

    ## In strict mode, exit with code 1 if any critical or high hazards exist
    # --strict exists for CI gating: a risky unit makes the command fail.
    if args.strict and has_critical_failure:
        sys.stderr.write(red("Strict mode enabled: Critical or high-risk services detected!\n"))
        return 1

    return 0


# Inspect accepts either a PID or a cgroup path; a PID is first translated to
# its cgroup via /proc/<pid>/cgroup.
def cmd_inspect(args: argparse.Namespace) -> int:
    """Executes the 'inspect' subcommand."""
    ## Instantiate inspector with CLI root overrides
    inspector = CgroupInspector(cgroup_root=args.cgroup_root, proc_root=args.proc_root)
    target = args.target

    ## Warn if unified cgroup v2 is not active
    # Only warn (do not abort): the inspector may still be pointed at a fixture
    # tree through --cgroup-root. Suppressed in JSON mode to keep stdout parseable.
    if not inspector.is_cgroup_v2_available():
        if not args.json:
            print(yellow(f"Warning: Unified cgroup v2 controllers not found at {args.cgroup_root}"))

    # Starts unresolved; either lookup path below assigns it.
    node: Optional[CgroupNode] = None

    ## Determine if target is PID or cgroup path
    # All-digit targets are treated as PIDs; anything else is a cgroup path.
    if target.isdigit():
        pid = int(target)
        cgroup_rel = inspector.find_process_cgroup(pid)
        if not cgroup_rel:
            sys.stderr.write(red(f"Error: Could not locate cgroup for PID {pid}\n"))
            return 1
        node = inspector.inspect_cgroup(cgroup_rel)
    else:
        node = inspector.inspect_cgroup(target)

    ## Check if inspection succeeded
    if not node:
        sys.stderr.write(red(f"Error: Cgroup path '{target}' could not be resolved or inspected.\n"))
        return 1

    ## JSON output mode
    if args.json:
        out = {
            "path": node.path,
            "relative_path": node.relative_path,
            "controllers": node.controllers,
            "memory_current": node.memory_current,
            "memory_max": node.memory_max,
            "memory_high": node.memory_high,
            "memory_swap_current": node.memory_swap_current,
            "memory_swap_max": node.memory_swap_max,
            "cpu_max_quota": node.cpu_max_quota,
            "cpu_max_period": node.cpu_max_period,
            "pids_current": node.pids_current,
            "pids_max": node.pids_max,
            "process_pids": node.pids,
        }
        print(json.dumps(out, indent=2))
        return 0

    ## Formatted terminal output
    print(bold("\n=== Cgroup v2 Live Node State ==="))
    print(f"Path: {cyan(node.path)}")
    print(f"Relative: {node.relative_path or '/'}")
    print(f"Controllers: {', '.join(node.controllers) if node.controllers else 'none'}")
    print(f"Active PIDs: {len(node.pids)} processes {node.pids[:10]}{'...' if len(node.pids) > 10 else ''}")

    print("\n" + bold("Memory Controller (memory.*):"))
    print(f"  Current Usage:     {format_bytes_human(node.memory_current or 0)}")
    print(f"  Hard Ceiling (max):{format_bytes_human(node.memory_max if node.memory_max is not None else -1)}")
    print(f"  Watermark (high):  {format_bytes_human(node.memory_high if node.memory_high is not None else -1)}")
    print(f"  Swap Current:      {format_bytes_human(node.memory_swap_current or 0)}")
    print(f"  Swap Max:          {format_bytes_human(node.memory_swap_max if node.memory_swap_max is not None else -1)}")

    # cpu.max holds quota/period in microseconds; a negative quota means "max" (no limit),
    # so the percentage is only computed for a real quota.
    print("\n" + bold("CPU Controller (cpu.*):"))
    if node.cpu_max_quota is not None and node.cpu_max_period:
        if node.cpu_max_quota < 0:
            quota_str = "max (unrestricted)"
        else:
            pct = (node.cpu_max_quota / node.cpu_max_period) * 100.0
            quota_str = f"{node.cpu_max_quota}us / {node.cpu_max_period}us ({pct:.0f}%)"
        print(f"  Bandwidth:         {quota_str}")
    else:
        print("  Bandwidth:         unrestricted / not configured")

    print("\n" + bold("PIDs Controller (pids.*):"))
    print(f"  Active Tasks:      {node.pids_current if node.pids_current is not None else 'unknown'}")
    print(f"  Max Tasks:         {node.pids_max if node.pids_max is not None and node.pids_max >= 0 else 'max'}")
    print()

    return 0


# generate-override is a dry run unless --apply is given, so previewing is the
# safe default and nothing is written to disk by accident.
def cmd_generate_override(args: argparse.Namespace) -> int:
    """Executes the 'generate-override' subcommand."""
    ## Instantiate inspector and drop-in generator
    inspector = CgroupInspector(cgroup_root=args.cgroup_root, proc_root=args.proc_root)
    generator = DropInGenerator(inspector=inspector)

    ## Map explicit CLI arguments to custom override dictionary
    # Empty by default: with no flags the profile alone decides every limit.
    custom_overrides: Dict[str, Any] = {}
    # Only flags the operator actually passed become overrides; unset ones fall
    # through to the chosen profile's computed defaults.
    if args.memory_max:
        custom_overrides["memory_max"] = parse_human_bytes(args.memory_max)
    if args.memory_high:
        custom_overrides["memory_high"] = parse_human_bytes(args.memory_high)
    if args.memory_swap_max:
        custom_overrides["memory_swap_max"] = parse_human_bytes(args.memory_swap_max)
    # Accept '150%' or '150': strip the percent sign before converting.
    if args.cpu_quota:
        clean_cpu = args.cpu_quota.rstrip("%").strip()
        custom_overrides["cpu_quota_percent"] = float(clean_cpu)
    if args.tasks_max:
        custom_overrides["tasks_max"] = int(args.tasks_max)
    if args.oom_score:
        custom_overrides["oom_score_adjust"] = int(args.oom_score)

    ## Calculate effective limits using selected profile and hardware heuristics
    # Profile heuristics (scaled to host RAM) first, then explicit overrides on top.
    limits = generator.calculate_limits(
        profile=args.profile,
        custom_overrides=custom_overrides,
    )

    ## Output directory specification
    out_dir = Path(args.out_dir) if args.out_dir else None
    ## Write configuration file or preview content
    target_file, content = generator.write_drop_in(
        unit_name=args.unit_name,
        limits=limits,
        destination_dir=out_dir,
        is_user=args.user,
        # dry_run is the inverse of --apply.
        dry_run=not args.apply,
    )

    ## JSON output mode
    if args.json:
        out = {
            "unit_name": args.unit_name,
            "target_file": str(target_file),
            "applied": bool(args.apply),
            "profile": args.profile,
            "limits": {
                "memory_max": limits.memory_max,
                "memory_high": limits.memory_high,
                "memory_swap_max": limits.memory_swap_max,
                "cpu_quota_percent": limits.cpu_quota_percent,
                "tasks_max": limits.tasks_max,
                "oom_policy": limits.oom_policy,
                "oom_score_adjust": limits.oom_score_adjust,
            },
            "content": content,
        }
        print(json.dumps(out, indent=2))
        return 0

    ## Terminal output mode
    if args.apply:
        print(green(f"✓ Drop-in override successfully installed to: {target_file}"))
        print("\nTo activate new limits:")
        if args.user:
            print(cyan(f"  systemctl --user daemon-reload && systemctl --user restart {args.unit_name}"))
        else:
            print(cyan(f"  sudo systemctl daemon-reload && sudo systemctl restart {args.unit_name}"))
    else:
        print(bold(f"\n=== Generated Drop-in Preview: {target_file} ==="))
        print(yellow("# (Dry-run mode: run with --apply or sudo --apply to write file)\n"))
        print(content)
        print("To apply this override directly:")
        print(cyan(f"  cgroup-sentinel generate-override {args.unit_name} --profile {args.profile} --apply"))

    return 0


# PSI = Pressure Stall Information. 'some' means at least one task stalled,
# 'full' means every task stalled; avgN are percentages over N seconds.
def cmd_pressure(args: argparse.Namespace) -> int:
    """Executes the 'pressure' subcommand."""
    ## Instantiate inspector
    inspector = CgroupInspector(cgroup_root=args.cgroup_root, proc_root=args.proc_root)
    ## Determine which resources to query
    # 'all' fans out to the three PSI resources the kernel exposes.
    resources = ["memory", "cpu", "io"] if args.resource == "all" else [args.resource]

    ## Read PSI snapshots for requested resources
    # Keyed by resource name; None marks a resource the kernel did not expose.
    snapshots: Dict[str, Optional[PSISnapshot]] = {}
    for res in resources:
        snapshots[res] = inspector.read_psi(res)

    ## JSON output mode
    if args.json:
        out = {}
        for res, snap in snapshots.items():
            if snap:
                out[res] = {
                    "resource": snap.resource,
                    "pressure_level": snap.pressure_level,
                    "some": {
                        "avg10": snap.some.avg10,
                        "avg60": snap.some.avg60,
                        "avg300": snap.some.avg300,
                        "total_us": snap.some.total_us,
                    } if snap.some else None,
                    "full": {
                        "avg10": snap.full.avg10,
                        "avg60": snap.full.avg60,
                        "avg300": snap.full.avg300,
                        "total_us": snap.full.total_us,
                    } if snap.full else None,
                }
            else:
                out[res] = None
        print(json.dumps(out, indent=2))
        return 0

    ## Terminal output mode
    print(bold("\n=== Linux Kernel Pressure Stall Information (PSI) ==="))
    for res, snap in snapshots.items():
        print(f"\n{bold(res.upper())} Pressure:")
        # None means /proc/pressure/<res> is missing (PSI disabled or old kernel).
        if not snap:
            print(f"  {yellow('Unavailable')} (PSI not enabled in kernel or /proc/pressure/{res} missing)")
            continue

        # CRITICAL and HIGH are both shown in red; the text label still tells them apart.
        level_str = snap.pressure_level
        if level_str == "CRITICAL":
            badge = red(f"[{level_str}]")
        elif level_str == "HIGH":
            badge = red(f"[{level_str}]")
        elif level_str == "MODERATE":
            badge = yellow(f"[{level_str}]")
        else:
            badge = green(f"[{level_str}]")

        print(f"  Overall Contention: {badge}")

        if snap.some:
            print(f"  some (at least 1 task stalled): avg10={snap.some.avg10:.2f}% avg60={snap.some.avg60:.2f}% avg300={snap.some.avg300:.2f}% (total: {snap.some.total_us/1000:.0f}ms)")
        if snap.full:
            print(f"  full (ALL tasks stalled):      avg10={snap.full.avg10:.2f}% avg60={snap.full.avg60:.2f}% avg300={snap.full.avg300:.2f}% (total: {snap.full.total_us/1000:.0f}ms)")

    print()
    return 0


# report is an at-a-glance summary: host memory, PSI levels, and a small audit of
# commonly resource-hungry services (only those actually installed).
def cmd_report(args: argparse.Namespace) -> int:
    """Executes the 'report' subcommand (comprehensive system evaluation)."""
    ## Telemetry inspector
    inspector = CgroupInspector(cgroup_root=args.cgroup_root, proc_root=args.proc_root)
    # All readers degrade gracefully when files are missing, so report never crashes
    # on hosts without cgroup v2 or PSI.
    mem_info = inspector.read_host_memory_info()
    psi_mem = inspector.read_psi("memory")
    psi_cpu = inspector.read_psi("cpu")
    psi_io = inspector.read_psi("io")
    cgroup_v2 = inspector.is_cgroup_v2_available()

    ## Sample auditor
    auditor = SystemdUnitAuditor()
    # Fixed sample list; units that cannot be found are skipped, not reported as errors.
    sample_services = ["docker.service", "ollama.service", "sshd.service", "systemd-resolved.service"]
    audits = [auditor.audit_unit(s) for s in sample_services if auditor.find_unit_file(s)]

    ## JSON output mode
    if args.json:
        out = {
            "cgroup_v2_active": cgroup_v2,
            "host_memory": {
                "total_bytes": mem_info.total_bytes,
                "available_bytes": mem_info.available_bytes,
                "used_bytes": mem_info.used_bytes,
                "free_bytes": mem_info.free_bytes,
                "cached_bytes": mem_info.cached_bytes,
                "swap_total_bytes": mem_info.swap_total_bytes,
                "swap_free_bytes": mem_info.swap_free_bytes,
            },
            "pressure": {
                "memory": psi_mem.pressure_level if psi_mem else "unavailable",
                "cpu": psi_cpu.pressure_level if psi_cpu else "unavailable",
                "io": psi_io.pressure_level if psi_io else "unavailable",
            },
            "audits": [
                {
                    "unit_name": a.unit_name,
                    "risk_score": a.risk_score,
                    "risk_level": a.risk_level,
                }
                for a in audits
            ],
        }
        print(json.dumps(out, indent=2))
        return 0

    ## Terminal presentation
    print(bold("\n========================================================"))
    print(bold("        CGROUP RESOURCE SENTINEL: SYSTEM REPORT         "))
    print(bold("========================================================"))

    # Cgroup v2 status
    cg_badge = green("ONLINE (Unified Hierarchy)") if cgroup_v2 else yellow("OFFLINE / NOT DETECTED")
    print(f"\nCgroup v2 Subsystem: {cg_badge}")

    # Host Memory
    print(f"\n{bold('Physical Memory & Swap:')}")
    print(f"  RAM Total:       {format_bytes_human(mem_info.total_bytes)}")
    print(f"  RAM Available:   {format_bytes_human(mem_info.available_bytes)}")
    print(f"  RAM In Use:      {format_bytes_human(mem_info.used_bytes)}")
    print(f"  Page Cache:      {format_bytes_human(mem_info.cached_bytes)}")
    print(f"  Swap Total:      {format_bytes_human(mem_info.swap_total_bytes)}")
    print(f"  Swap In Use:     {format_bytes_human(mem_info.swap_used_bytes)}")

    # Pressure Stall Information
    print(f"\n{bold('Live Pressure Telemetry (PSI):')}")
    for name, p in [("Memory", psi_mem), ("CPU", psi_cpu), ("I/O", psi_io)]:
        if p:
            print(f"  {name:<8}: {p.pressure_level} (some avg10: {p.some.avg10 if p.some else 0.0}%, full avg10: {p.full.avg10 if p.full else 0.0}%)")
        else:
            print(f"  {name:<8}: UNAVAILABLE")

    # Sample Audits
    if audits:
        print(f"\n{bold('Detected Services Audit Preview:')}")
        for a in audits:
            print(f"  {a.unit_name:<28} Risk: {a.risk_level:<8} (Score: {a.risk_score}/100)")
    print()

    return 0


# Parser construction is separated from main() so tests can build and inspect it
# without executing a command.
def build_parser() -> argparse.ArgumentParser:
    """Builds and returns the CLI argument parser."""
    ## Root parser configuration
    parser = argparse.ArgumentParser(
        prog="cgroup-sentinel",
        description="Zero-dependency Linux cgroup v2 resource governor, systemd unit auditor, and automated drop-in override generator.",
    )
    ## Global argument: custom cgroup root mount point
    parser.add_argument(
        "--cgroup-root",
        default="/sys/fs/cgroup",
        help="Root path to cgroup v2 hierarchy (default: /sys/fs/cgroup)",
    )
    ## Global argument: custom procfs mount point
    parser.add_argument(
        "--proc-root",
        default="/proc",
        help="Root path to procfs (default: /proc)",
    )

    ## Subparser container for Sentinel subcommands
    subparsers = parser.add_subparsers(dest="command", help="Sentinel subcommands")

    ## 1. audit subcommand
    # Each subcommand below declares its own flags; --json is repeated per command
    # so it can follow the subcommand name on the command line.
    p_audit = subparsers.add_parser("audit", help="Audit systemd unit files for resource boundaries")
    p_audit.add_argument("target", nargs="?", help="Specific service unit or directory to audit")
    p_audit.add_argument("--search-path", help="Custom search directory for units")
    p_audit.add_argument("--strict", action="store_true", help="Exit with code 1 if critical/high risk found")
    p_audit.add_argument("--json", action="store_true", help="Output results in JSON format")

    ## 2. inspect subcommand
    p_inspect = subparsers.add_parser("inspect", help="Inspect live cgroup v2 metrics")
    p_inspect.add_argument("target", help="Cgroup relative path (e.g. system.slice/docker.service) or PID")
    p_inspect.add_argument("--json", action="store_true", help="Output results in JSON format")

    ## 3. generate-override subcommand
    p_gen = subparsers.add_parser("generate-override", help="Generate systemd drop-in override")
    p_gen.add_argument("unit_name", help="Target service unit (e.g. ollama.service)")
    p_gen.add_argument(
        "--profile",
        choices=["conservative", "standard", "aggressive", "custom"],
        default="standard",
        help="Resource limit profile (default: standard)",
    )
    p_gen.add_argument("--memory-max", help="Custom MemoryMax (e.g. 2G, 512M)")
    p_gen.add_argument("--memory-high", help="Custom MemoryHigh watermark (e.g. 1.8G)")
    p_gen.add_argument("--memory-swap-max", help="Custom MemorySwapMax (e.g. 0, 500M)")
    # Note '%%' because argparse help strings use %-formatting.
    p_gen.add_argument("--cpu-quota", help="Custom CPUQuota percentage (e.g. 100%%)")
    p_gen.add_argument("--tasks-max", help="Custom TasksMax ceiling (e.g. 512)")
    p_gen.add_argument("--oom-score", help="Custom OOMScoreAdjust (-1000 to 1000)")
    p_gen.add_argument("--user", action="store_true", help="Target user session unit instead of system")
    p_gen.add_argument("--out-dir", help="Custom destination directory for drop-in")
    p_gen.add_argument("--apply", action="store_true", help="Write drop-in override directly to disk")
    p_gen.add_argument("--json", action="store_true", help="Output in JSON format")

    ## 4. pressure subcommand
    p_psi = subparsers.add_parser("pressure", help="Display Linux Pressure Stall Information (PSI)")
    p_psi.add_argument(
        "--resource",
        choices=["memory", "cpu", "io", "all"],
        default="all",
        help="Resource to inspect (default: all)",
    )
    p_psi.add_argument("--json", action="store_true", help="Output in JSON format")

    ## 5. report subcommand
    p_rep = subparsers.add_parser("report", help="Generate comprehensive host resource and vulnerability report")
    p_rep.add_argument("--json", action="store_true", help="Output in JSON format")

    return parser


# main returns an int rather than calling sys.exit so it stays testable; only the
# __main__ guard at the bottom turns it into an exit status.
def main() -> int:
    """Main CLI entrypoint."""
    ## Parse command-line arguments
    parser = build_parser()
    args = parser.parse_args()

    ## If no subcommand provided, show help message and exit
    if not args.command:
        parser.print_help()
        return 0

    ## Dispatch table mapping subcommand names to their respective handlers
    # Dispatch table instead of an if/elif chain; adding a subcommand means one
    # parser entry plus one line here.
    commands = {
        "audit": cmd_audit,
        "inspect": cmd_inspect,
        "generate-override": cmd_generate_override,
        "pressure": cmd_pressure,
        "report": cmd_report,
    }

    ## Execute matching handler
    # Unknown commands cannot normally reach here (argparse rejects them) but the
    # fallback keeps the function total.
    handler = commands.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 1


## Direct script execution entry point
if __name__ == "__main__":
    sys.exit(main())
