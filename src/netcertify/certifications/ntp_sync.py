"""
NTP Synchronization Certification Test.

Validates NTP configuration and synchronization status.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity
from netcertify.schemas.status import SyncState


class NTPCertificationTest(BaseCertificationTest):
    """
    Certification test for NTP synchronization.
    
    Validates:
    - NTP is configured and enabled
    - At least one NTP server is configured
    - Device is synchronized to an NTP source
    - Clock offset is within acceptable bounds
    - NTP peers are reachable
    """
    
    name = "NTP Synchronization"
    description = "Validate NTP configuration and time synchronization"
    category = "time"
    tags = ["ntp", "time", "synchronization", "baseline"]
    
    # Thresholds
    MAX_OFFSET_MS = 100.0  # Maximum acceptable offset in milliseconds
    MIN_SERVERS = 1  # Minimum NTP servers required
    RECOMMENDED_SERVERS = 2  # Recommended number of NTP servers
    
    def run(self) -> None:
        """Execute NTP certification tests."""
        
        if self.skip_if_unsupported("supports_ntp_status", "NTP Status Check"):
            return
        
        # Get NTP configuration and status
        ntp_config = self.adapter.get_ntp_configuration()
        ntp_status = self.adapter.get_ntp_status()
        
        with self.engine.step("NTP Configuration Validation"):
            # Check NTP is enabled
            self.engine.assert_true(
                "NTP Enabled",
                ntp_config.enabled,
                severity=Severity.CRITICAL,
                reason="NTP must be enabled for proper time synchronization",
                remediation="Enable NTP synchronization in system settings"
            )
            
            # Check minimum servers configured
            self.engine.assert_greater_than(
                "Minimum NTP Servers",
                len(ntp_config.servers),
                self.MIN_SERVERS - 1,
                inclusive=True,
                severity=Severity.HIGH,
                reason=f"At least {self.MIN_SERVERS} NTP server(s) should be configured",
                remediation="Configure at least one NTP server"
            )
            
            # Check recommended servers (informational)
            if len(ntp_config.servers) < self.RECOMMENDED_SERVERS:
                self.engine.assert_greater_than(
                    "Recommended NTP Servers",
                    len(ntp_config.servers),
                    self.RECOMMENDED_SERVERS - 1,
                    inclusive=True,
                    severity=Severity.LOW,
                    reason=f"Recommended to have at least {self.RECOMMENDED_SERVERS} NTP servers for redundancy"
                )
        
        with self.engine.step("NTP Synchronization Status"):
            # Check sync state
            self.engine.assert_equals(
                "NTP Sync State",
                ntp_status.sync_state,
                SyncState.SYNCED,
                severity=Severity.CRITICAL,
                reason="Device must be synchronized to NTP source",
                remediation="Verify NTP server reachability and firewall rules"
            )
            
            # Check synced source
            self.engine.assert_not_none(
                "NTP Sync Source",
                ntp_status.synced_to,
                severity=Severity.HIGH,
                reason="Device should have an active sync source"
            )
            
            # Check stratum (should be <= 15)
            if ntp_status.stratum > 0:
                self.engine.assert_less_than(
                    "NTP Stratum Level",
                    ntp_status.stratum,
                    16,
                    severity=Severity.MEDIUM,
                    reason="Stratum 16 indicates unsynchronized state"
                )
        
        with self.engine.step("NTP Offset Validation"):
            # Check clock offset
            self.engine.assert_less_than(
                "Clock Offset Within Bounds",
                abs(ntp_status.offset_ms),
                self.MAX_OFFSET_MS,
                severity=Severity.HIGH,
                reason=f"Clock offset should be less than {self.MAX_OFFSET_MS}ms",
                remediation="High offset may indicate network latency or unstable NTP source"
            )
        
        with self.engine.step("NTP Peer Reachability"):
            # Check peer reachability
            reachable_peers = ntp_status.reachable_peers
            
            self.engine.assert_greater_than(
                "Reachable NTP Peers",
                reachable_peers,
                0,
                severity=Severity.HIGH,
                reason="At least one NTP peer should be reachable"
            )
            
            # Validate individual peers
            for peer in ntp_status.peers:
                self.engine.assert_true(
                    f"NTP Peer Reachable: {peer.address}",
                    peer.is_reachable,
                    severity=Severity.MEDIUM,
                    reason=f"NTP peer {peer.address} should be reachable"
                )
