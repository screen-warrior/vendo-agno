"""
DNS Configuration Certification Test.

Validates DNS resolver configuration.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity


class DNSCertificationTest(BaseCertificationTest):
    """
    Certification test for DNS configuration.
    
    Validates:
    - DNS servers are configured
    - Multiple DNS servers for redundancy
    """
    
    name = "DNS Configuration"
    description = "Validate DNS resolver configuration"
    category = "network"
    tags = ["dns", "network", "resolution"]
    
    def run(self) -> None:
        if self.skip_if_unsupported("supports_dns_config", "DNS Config Check"):
            return
        
        dns_config = self.adapter.get_dns_configuration()
        
        with self.engine.step("DNS Server Configuration"):
            self.engine.assert_not_none(
                "Primary DNS Server Configured",
                dns_config.primary_server,
                severity=Severity.HIGH,
                reason="Primary DNS server must be configured",
                remediation="Configure a primary DNS server"
            )
            
            # Check for redundancy
            has_secondary = dns_config.secondary_server is not None
            self.engine.assert_true(
                "Secondary DNS Server Configured",
                has_secondary,
                severity=Severity.MEDIUM,
                reason="Secondary DNS server recommended for redundancy"
            )
            
            if dns_config.primary_server:
                self.engine.log(f"Primary DNS: {dns_config.primary_server}")
            if dns_config.secondary_server:
                self.engine.log(f"Secondary DNS: {dns_config.secondary_server}")
