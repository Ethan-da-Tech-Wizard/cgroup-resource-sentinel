"""
Program: Cgroup Resource Sentinel - Package Initialization
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Expose public API classes, data structures, and utilities for the cgroup-resource-sentinel package.
"""

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
__author__ = "Ethan Kilmer"

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
