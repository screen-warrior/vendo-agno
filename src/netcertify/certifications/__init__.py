"""
NetCertify Certifications - Pre-built certification test suites.

Comprehensive certification tests for firewall operational readiness.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.certifications.ntp_sync import NTPCertificationTest
from netcertify.certifications.interface_status import InterfaceCertificationTest
from netcertify.certifications.ha_status import HACertificationTest
from netcertify.certifications.system_health import SystemHealthCertificationTest
from netcertify.certifications.license_compliance import LicenseCertificationTest
from netcertify.certifications.security_policy import SecurityPolicyCertificationTest
from netcertify.certifications.vpn_tunnel import VPNCertificationTest
from netcertify.certifications.threat_prevention import ThreatPreventionCertificationTest
from netcertify.certifications.dns_config import DNSCertificationTest
from netcertify.certifications.routing_validation import RoutingCertificationTest
from netcertify.certifications.certificate_validity import CertificateCertificationTest
from netcertify.certifications.session_table import SessionTableCertificationTest
from netcertify.certifications.logging_config import LoggingCertificationTest
from netcertify.certifications.snmp_config import SNMPCertificationTest
from netcertify.certifications.firmware_compliance import FirmwareCertificationTest
from netcertify.certifications.management_access import ManagementAccessCertificationTest

# All available certification tests
ALL_TESTS = [
    NTPCertificationTest,
    InterfaceCertificationTest,
    HACertificationTest,
    SystemHealthCertificationTest,
    LicenseCertificationTest,
    SecurityPolicyCertificationTest,
    VPNCertificationTest,
    ThreatPreventionCertificationTest,
    DNSCertificationTest,
    RoutingCertificationTest,
    CertificateCertificationTest,
    SessionTableCertificationTest,
    LoggingCertificationTest,
    SNMPCertificationTest,
    FirmwareCertificationTest,
    ManagementAccessCertificationTest,
]

# Quick certification presets
BASIC_TESTS = [
    NTPCertificationTest,
    InterfaceCertificationTest,
    SystemHealthCertificationTest,
]

SECURITY_TESTS = [
    SecurityPolicyCertificationTest,
    ThreatPreventionCertificationTest,
    CertificateCertificationTest,
    LoggingCertificationTest,
]

NETWORK_TESTS = [
    InterfaceCertificationTest,
    RoutingCertificationTest,
    VPNCertificationTest,
    DNSCertificationTest,
]

COMPLIANCE_TESTS = [
    LicenseCertificationTest,
    FirmwareCertificationTest,
    LoggingCertificationTest,
    SNMPCertificationTest,
]

__all__ = [
    "BaseCertificationTest",
    "NTPCertificationTest",
    "InterfaceCertificationTest",
    "HACertificationTest",
    "SystemHealthCertificationTest",
    "LicenseCertificationTest",
    "SecurityPolicyCertificationTest",
    "VPNCertificationTest",
    "ThreatPreventionCertificationTest",
    "DNSCertificationTest",
    "RoutingCertificationTest",
    "CertificateCertificationTest",
    "SessionTableCertificationTest",
    "LoggingCertificationTest",
    "SNMPCertificationTest",
    "FirmwareCertificationTest",
    "ManagementAccessCertificationTest",
    "ALL_TESTS",
    "BASIC_TESTS",
    "SECURITY_TESTS",
    "NETWORK_TESTS",
    "COMPLIANCE_TESTS",
]
