"""
cgroup-resource-sentinel
========================

Zero-dependency Linux cgroup v2 resource governor, systemd unit auditor,
and automated drop-in override generator.

Prevents desktop freezes, runaway background processes, and unconstrained
memory leaks by auditing and enforcing kernel cgroup v2 resource constraints
for systemd services.
"""

from .auditor import SystemdUnitAuditor
from .generator import DropInGenerator
from .inspector import CgroupInspector
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

__version__ = "0.1.0"
__author__ = "Ethan Kilmer"
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
