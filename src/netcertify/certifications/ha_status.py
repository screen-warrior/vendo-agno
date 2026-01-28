"""
High Availability Status Certification Test.

Validates HA configuration and operational status.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity
from netcertify.schemas.status import HAState
from netcertify.schemas.configuration import HAMode


class HACertificationTest(BaseCertificationTest):
    """
    Certification test for High Availability.
    
    Validates:
    - HA configuration is consistent
    - Peer connectivity is established
    - Configuration and session synchronization
    - HA links are operational
    """
    
    name = "High Availability Status"
    description = "Validate HA configuration and peer status"
    category = "availability"
    tags = ["ha", "high-availability", "redundancy", "failover"]
    
    def run(self) -> None:
        """Execute HA certification tests."""
        
        if self.skip_if_unsupported("supports_ha_status", "HA Status Check"):
            return
        
        ha_config = self.adapter.get_ha_configuration()
        ha_status = self.adapter.get_ha_status()
        
        with self.engine.step("HA Configuration Check"):
            # If HA is not enabled, all tests pass (HA is optional)
            if not ha_config.enabled:
                self.engine.skip(
                    "HA Validation",
                    "HA is not enabled on this device"
                )
                return
            
            self.engine.assert_true(
                "HA Enabled",
                ha_status.enabled,
                severity=Severity.HIGH,
                reason="HA should be enabled based on configuration"
            )
            
            # Validate HA mode
            self.engine.assert_not_equals(
                "HA Mode Configured",
                ha_config.mode,
                HAMode.DISABLED,
                severity=Severity.HIGH,
                reason="HA mode should be properly configured"
            )
        
        with self.engine.step("HA Peer Connectivity"):
            self.engine.assert_true(
                "HA Peer Connected",
                ha_status.peer_connected,
                severity=Severity.CRITICAL,
                reason="HA peer must be connected for redundancy",
                remediation="Check HA link connectivity and peer device status"
            )
            
            # Check local state is valid
            valid_states = [HAState.ACTIVE, HAState.PASSIVE]
            self.engine.assert_in_list(
                "Local HA State Valid",
                ha_status.local_state,
                valid_states,
                severity=Severity.CRITICAL,
                reason=f"Local state is {ha_status.local_state.value}, expected active or passive"
            )
            
            # Check peer state is valid
            self.engine.assert_in_list(
                "Peer HA State Valid",
                ha_status.peer_state,
                valid_states,
                severity=Severity.HIGH,
                reason=f"Peer state is {ha_status.peer_state.value}, expected active or passive"
            )
            
            # Check no both-active scenario
            self.engine.assert_false(
                "No Split-Brain (Both Active)",
                ha_status.local_state == HAState.ACTIVE and ha_status.peer_state == HAState.ACTIVE,
                severity=Severity.CRITICAL,
                reason="Split-brain detected: both units are active",
                remediation="Immediately investigate HA cluster - potential split-brain condition"
            )
        
        with self.engine.step("HA Synchronization"):
            self.engine.assert_true(
                "Configuration Synchronized",
                ha_status.config_synced,
                severity=Severity.HIGH,
                reason="Configuration must be synchronized between HA peers",
                remediation="Trigger configuration sync from active device"
            )
            
            if ha_status.session_synced is not None:
                self.engine.assert_true(
                    "Session State Synchronized",
                    ha_status.session_synced,
                    severity=Severity.MEDIUM,
                    reason="Session state should be synchronized for seamless failover"
                )
        
        with self.engine.step("HA Link Status"):
            if ha_status.ha1_link_status:
                self.engine.assert_equals(
                    "HA1 Link Status",
                    ha_status.ha1_link_status.lower(),
                    "up",
                    severity=Severity.CRITICAL,
                    reason="HA1 control link must be operational"
                )
            
            if ha_status.ha2_link_status:
                self.engine.assert_equals(
                    "HA2 Link Status",
                    ha_status.ha2_link_status.lower(),
                    "up",
                    severity=Severity.HIGH,
                    reason="HA2 data link should be operational"
                )
