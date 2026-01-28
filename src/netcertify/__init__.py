"""
NetCertify - Enterprise Firewall Certification Automation Framework

A vendor-agnostic, PyATS-integrated framework for automating firewall
certification, compliance validation, and operational readiness testing.

Supports: Palo Alto Networks, Fortinet FortiGate, Mock Devices
"""

__version__ = "1.0.0"
__author__ = "NetCertify Team"

from netcertify.schemas.device import DeviceInfo, DeviceCredentials, ConnectionParams
from netcertify.schemas.results import (
    TestResult,
    AssertionResult,
    CertificationReport,
)
from netcertify.adapters.registry import AdapterRegistry
from netcertify.validators.engine import ValidationEngine

__all__ = [
    "__version__",
    "DeviceInfo",
    "DeviceCredentials", 
    "ConnectionParams",
    "TestResult",
    "AssertionResult",
    "CertificationReport",
    "AdapterRegistry",
    "ValidationEngine",
]
