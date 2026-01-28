"""
Firmware Compliance Certification Test.

Validates firmware version meets requirements.
"""

import re
from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity


class FirmwareCertificationTest(BaseCertificationTest):
    """
    Certification test for firmware compliance.
    
    Validates:
    - Firmware version is known
    - Meets minimum version requirements
    """
    
    name = "Firmware Compliance"
    description = "Validate firmware version requirements"
    category = "compliance"
    tags = ["firmware", "version", "compliance", "patching"]
    
    def run(self) -> None:
        if self.skip_if_unsupported("supports_firmware_info", "Firmware Check"):
            return
        
        current_version = self.adapter.get_firmware_version()
        required_version = self.device.minimum_firmware
        
        with self.engine.step("Firmware Version"):
            self.engine.assert_not_none(
                "Firmware Version Retrieved",
                current_version,
                severity=Severity.HIGH,
                reason="Unable to retrieve firmware version"
            )
            
            if current_version:
                self.engine.log(f"Current firmware: {current_version}")
            
            # If minimum version specified, check compliance
            if required_version:
                self.engine.log(f"Required minimum: {required_version}")
                
                meets_requirement = self._compare_versions(
                    current_version, required_version
                ) >= 0
                
                self.engine.assert_true(
                    "Meets Minimum Firmware Version",
                    meets_requirement,
                    severity=Severity.HIGH,
                    reason=f"Firmware {current_version} below required {required_version}",
                    remediation="Upgrade firmware to meet minimum requirements"
                )
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        def normalize(v):
            return [int(x) for x in re.findall(r'\d+', v)]
        
        parts1 = normalize(v1)
        parts2 = normalize(v2)
        
        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            if p1 > p2:
                return 1
        
        return len(parts1) - len(parts2)
