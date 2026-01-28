"""
Base Certification Test - Foundation for all certification tests.

Provides common functionality and patterns for certification testing.
"""

from netcertify.orchestrator.runner import CertificationTest
from netcertify.schemas.results import Severity


class BaseCertificationTest(CertificationTest):
    """
    Base class for all NetCertify certification tests.
    
    Extends CertificationTest with additional utilities and
    common validation patterns.
    """
    
    # Default thresholds (can be overridden by subclasses)
    CPU_WARNING_THRESHOLD = 70.0
    CPU_CRITICAL_THRESHOLD = 90.0
    MEMORY_WARNING_THRESHOLD = 80.0
    MEMORY_CRITICAL_THRESHOLD = 95.0
    DISK_WARNING_THRESHOLD = 80.0
    DISK_CRITICAL_THRESHOLD = 95.0
    
    def check_adapter_capability(self, capability: str) -> bool:
        """
        Check if the adapter supports a specific capability.
        
        Args:
            capability: Capability name (e.g., 'supports_ntp_status')
            
        Returns:
            True if capability is supported
        """
        caps = self.adapter.capabilities
        return getattr(caps, capability, False)
    
    def skip_if_unsupported(self, capability: str, test_name: str) -> bool:
        """
        Skip a validation if capability is not supported.
        
        Args:
            capability: Required capability
            test_name: Name for the skip record
            
        Returns:
            True if test should be skipped
        """
        if not self.check_adapter_capability(capability):
            self.engine.skip(
                test_name,
                f"Adapter does not support {capability}"
            )
            return True
        return False
