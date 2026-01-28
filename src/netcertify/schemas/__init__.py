"""
NetCertify Schemas - Pydantic models for type-safe data flow.

All structured data in the framework flows through these validated models.
"""

from netcertify.schemas.device import (
    DeviceVendor,
    DeviceType,
    DeviceCredentials,
    ConnectionParams,
    DeviceInfo,
    DeviceInventory,
)
from netcertify.schemas.configuration import (
    NTPServer,
    NTPConfiguration,
    DNSConfiguration,
    InterfaceConfig,
    RouteEntry,
    RoutingTable,
    SecurityZone,
    SecurityPolicy,
    NATRule,
    VPNTunnel,
    SNMPConfig,
    LoggingConfig,
    CertificateInfo,
    HAConfiguration,
    SystemConfiguration,
)
from netcertify.schemas.status import (
    NTPStatus,
    InterfaceStatus,
    HAStatus,
    SystemHealth,
    LicenseStatus,
    SessionTableStatus,
    ThreatPreventionStatus,
    VPNTunnelStatus,
    ServiceStatus,
    DeviceRuntimeStatus,
)
from netcertify.schemas.results import (
    Severity,
    AssertionResult,
    TestStepResult,
    TestResult,
    CertificationSuiteResult,
    CertificationReport,
)

__all__ = [
    # Device
    "DeviceVendor",
    "DeviceType",
    "DeviceCredentials",
    "ConnectionParams",
    "DeviceInfo",
    "DeviceInventory",
    # Configuration
    "NTPServer",
    "NTPConfiguration",
    "DNSConfiguration",
    "InterfaceConfig",
    "RouteEntry",
    "RoutingTable",
    "SecurityZone",
    "SecurityPolicy",
    "NATRule",
    "VPNTunnel",
    "SNMPConfig",
    "LoggingConfig",
    "CertificateInfo",
    "HAConfiguration",
    "SystemConfiguration",
    # Status
    "NTPStatus",
    "InterfaceStatus",
    "HAStatus",
    "SystemHealth",
    "LicenseStatus",
    "SessionTableStatus",
    "ThreatPreventionStatus",
    "VPNTunnelStatus",
    "ServiceStatus",
    "DeviceRuntimeStatus",
    # Results
    "Severity",
    "AssertionResult",
    "TestStepResult",
    "TestResult",
    "CertificationSuiteResult",
    "CertificationReport",
]
