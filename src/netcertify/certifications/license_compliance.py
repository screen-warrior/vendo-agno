"""
License Compliance Certification Test.

Validates licensing status and feature availability.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity
from netcertify.schemas.status import LicenseState


class LicenseCertificationTest(BaseCertificationTest):
    """
    Certification test for license compliance.
    
    Validates:
    - All required licenses are valid
    - No licenses are expired
    - License expiration warnings
    - Feature license availability
    """
    
    name = "License Compliance"
    description = "Validate licensing status and feature availability"
    category = "compliance"
    tags = ["license", "compliance", "features", "support"]
    
    # Thresholds
    EXPIRY_WARNING_DAYS = 30
    EXPIRY_CRITICAL_DAYS = 7
    
    def run(self) -> None:
        """Execute license compliance certification tests."""
        
        if self.skip_if_unsupported("supports_license_status", "License Status Check"):
            return
        
        license_status = self.adapter.get_license_status()
        
        with self.engine.step("Overall License Status"):
            self.engine.assert_not_equals(
                "License State Valid",
                license_status.overall_state,
                LicenseState.EXPIRED,
                severity=Severity.CRITICAL,
                reason="One or more licenses have expired",
                remediation="Renew expired licenses immediately"
            )
            
            self.engine.assert_not_equals(
                "License State Known",
                license_status.overall_state,
                LicenseState.INVALID,
                severity=Severity.CRITICAL,
                reason="License state is invalid"
            )
            
            self.engine.log(f"Overall license state: {license_status.overall_state.value}")
        
        with self.engine.step("Individual Feature Licenses"):
            for feature in license_status.features:
                # Check feature is not expired
                self.engine.assert_not_equals(
                    f"License {feature.name} Not Expired",
                    feature.state,
                    LicenseState.EXPIRED,
                    severity=Severity.CRITICAL,
                    reason=f"License for {feature.name} has expired",
                    remediation=f"Renew {feature.name} license"
                )
                
                # Check feature is enabled
                if feature.enabled:
                    self.engine.assert_equals(
                        f"License {feature.name} Valid",
                        feature.state,
                        LicenseState.VALID,
                        severity=Severity.HIGH,
                        reason=f"License for {feature.name} is not valid"
                    )
        
        with self.engine.step("License Expiration Warnings"):
            expiring_soon = license_status.expiring_features
            
            for feature in license_status.features:
                if feature.days_until_expiry is not None:
                    # Critical - expires within 7 days
                    if feature.days_until_expiry <= self.EXPIRY_CRITICAL_DAYS:
                        self.engine.assert_greater_than(
                            f"License {feature.name} Critical Expiry",
                            feature.days_until_expiry,
                            self.EXPIRY_CRITICAL_DAYS,
                            severity=Severity.CRITICAL,
                            reason=f"{feature.name} expires in {feature.days_until_expiry} days",
                            remediation="Immediately renew this license"
                        )
                    # Warning - expires within 30 days
                    elif feature.days_until_expiry <= self.EXPIRY_WARNING_DAYS:
                        self.engine.assert_greater_than(
                            f"License {feature.name} Warning Expiry",
                            feature.days_until_expiry,
                            self.EXPIRY_WARNING_DAYS,
                            severity=Severity.MEDIUM,
                            reason=f"{feature.name} expires in {feature.days_until_expiry} days",
                            remediation="Plan to renew this license soon"
                        )
            
            if expiring_soon:
                self.engine.log(f"Warning: {len(expiring_soon)} feature(s) expiring within 30 days")
