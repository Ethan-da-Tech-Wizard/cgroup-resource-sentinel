# ==============================================================================
# Program: __init__.py
# Programmer: Ethan-da-Tech-Wizard
# Course: CIS 156 / Advanced Systems
# Last Modified: November 18, 2026
# Purpose: Package initialization and public API export for Cgroup Resource Sentinel.
#          Inputs: Package-level imports of auditor, generator, inspector, and models.
#          Outputs: Exported classes, dataclasses, conversion utilities, and version metadata.
#          Design Rationale: Exposes a clean, unified public interface for auditing
#                            and generating Linux cgroup v2 systemd resource boundaries.
# ==============================================================================

## Import the core systemd unit auditor responsible for scanning unit files for missing boundaries
from .auditor import SystemdUnitAuditor

## Import the drop-in configuration synthesizer that calculates and writes safe limits
from .generator import DropInGenerator

## Import the cgroup v2 and /proc filesystem inspector for live telemetry and hardware detection
from .inspector import CgroupInspector

## Import the strongly-typed domain dataclasses and conversion utility functions
from .models import (
    CgroupNode,
    HostMemoryInfo,
    PSIMetric,
    PSISnapshot,
    ResourceLimits,
    ServiceAudit,
    format_bytes_human,
    parse_human_bytes,
)

## Package release version identifier
__version__ = "0.1.0"

## Author and copyright owner
__author__ = "Ethan-da-Tech-Wizard"

## Explicit list of exported symbols available on wildcard import (`from cgroupsentinel import *`)
__all__ = [
    "SystemdUnitAuditor",
    "DropInGenerator",
    "CgroupInspector",
    "CgroupNode",
    "HostMemoryInfo",
    "PSIMetric",
    "PSISnapshot",
    "ResourceLimits",
    "ServiceAudit",
    "format_bytes_human",
    "parse_human_bytes",
    "__version__",
]
