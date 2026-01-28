"""
Certificate Validity Certification Test.

Validates SSL/TLS certificate expiration and validity.
"""

from datetime import datetime
from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity


class CertificateCertificationTest(BaseCertificationTest):
    """
    Certification test for certificates.
    
    Validates:
    - Certificates are not expired
    - Certificates are not expiring soon
    - Key sizes are adequate
    """
    
    name = "Certificate Validity"
    description = "Validate certificate expiration and configuration"
    category = "security"
    tags = ["certificates", "ssl", "tls", "security"]
    
    EXPIRY_WARNING_DAYS = 30
    EXPIRY_CRITICAL_DAYS = 7
    MIN_KEY_SIZE = 2048
    
    def run(self) -> None:
        if self.skip_if_unsupported("supports_certificates", "Certificate Check"):
            return
        
        certs = self.adapter.get_certificates()
        
        with self.engine.step("Certificate Discovery"):
            if not certs:
                self.engine.skip("Certificate Validation", "No certificates found")
                return
            
            self.engine.log(f"Found {len(certs)} certificate(s)")
        
        with self.engine.step("Certificate Expiration"):
            for cert in certs:
                # Check not expired
                self.engine.assert_false(
                    f"Certificate {cert.name} Not Expired",
                    cert.is_expired,
                    severity=Severity.CRITICAL,
                    reason=f"Certificate {cert.name} has expired",
                    remediation="Renew or replace the expired certificate"
                )
                
                # Check expiration warning
                days_left = cert.days_until_expiry
                if days_left <= self.EXPIRY_CRITICAL_DAYS:
                    self.engine.assert_greater_than(
                        f"Certificate {cert.name} Critical Expiry",
                        days_left,
                        self.EXPIRY_CRITICAL_DAYS,
                        severity=Severity.CRITICAL,
                        reason=f"Certificate expires in {days_left} days"
                    )
                elif days_left <= self.EXPIRY_WARNING_DAYS:
                    self.engine.assert_greater_than(
                        f"Certificate {cert.name} Warning Expiry",
                        days_left,
                        self.EXPIRY_WARNING_DAYS,
                        severity=Severity.MEDIUM,
                        reason=f"Certificate expires in {days_left} days"
                    )
        
        with self.engine.step("Certificate Key Strength"):
            for cert in certs:
                self.engine.assert_greater_than(
                    f"Certificate {cert.name} Key Size",
                    cert.key_size,
                    self.MIN_KEY_SIZE - 1,
                    inclusive=True,
                    severity=Severity.HIGH,
                    reason=f"Key size {cert.key_size} is below minimum {self.MIN_KEY_SIZE}",
                    remediation="Generate new certificate with larger key size"
                )
