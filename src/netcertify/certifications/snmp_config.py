"""
SNMP Configuration Certification Test.

Validates SNMP configuration and security.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity
from netcertify.schemas.configuration import SNMPVersion


class SNMPCertificationTest(BaseCertificationTest):
    """
    Certification test for SNMP configuration.
    
    Validates:
    - SNMP version is secure (v3 preferred)
    - Community strings not default
    """
    
    name = "SNMP Configuration"
    description = "Validate SNMP settings and security"
    category = "management"
    tags = ["snmp", "monitoring", "management"]
    
    def run(self) -> None:
        if self.skip_if_unsupported("supports_snmp", "SNMP Check"):
            return
        
        snmp_config = self.adapter.get_snmp_configuration()
        
        with self.engine.step("SNMP Configuration"):
            if not snmp_config.enabled:
                self.engine.skip("SNMP Validation", "SNMP is disabled")
                return
            
            self.engine.log(f"SNMP version: {snmp_config.version.value}")
            
            # Prefer SNMPv3
            self.engine.assert_equals(
                "SNMP Version 3",
                snmp_config.version,
                SNMPVersion.V3,
                severity=Severity.HIGH,
                reason=f"Using SNMPv{snmp_config.version.value}, SNMPv3 recommended",
                remediation="Upgrade to SNMPv3 for encryption and authentication"
            )
            
            # If v2c, check community string
            if snmp_config.version == SNMPVersion.V2C and snmp_config.community_string:
                default_communities = ["public", "private", "community"]
                is_default = snmp_config.community_string.lower() in default_communities
                
                self.engine.assert_false(
                    "Non-Default Community String",
                    is_default,
                    severity=Severity.CRITICAL,
                    reason="Default SNMP community string in use",
                    remediation="Change SNMP community string to a unique value"
                )
