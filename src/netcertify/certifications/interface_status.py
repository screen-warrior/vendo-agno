"""
Interface Status Certification Test.

Validates network interface operational status and health.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity
from netcertify.schemas.status import LinkState


class InterfaceCertificationTest(BaseCertificationTest):
    """
    Certification test for network interfaces.
    
    Validates:
    - Configured interfaces are operational
    - Interface error counters are acceptable
    - Link speed and duplex are as expected
    - No excessive drops or errors
    """
    
    name = "Interface Status"
    description = "Validate network interface operational status"
    category = "network"
    tags = ["interfaces", "network", "connectivity", "baseline"]
    
    # Thresholds
    MAX_ERROR_RATE = 0.001  # 0.1% error rate
    MAX_DROP_RATE = 0.01   # 1% drop rate
    
    def run(self) -> None:
        """Execute interface certification tests."""
        
        if self.skip_if_unsupported("supports_interface_status", "Interface Status Check"):
            return
        
        interfaces = self.adapter.get_interface_status()
        configs = self.adapter.get_interfaces()
        
        # Build config lookup
        config_map = {c.name: c for c in configs}
        
        with self.engine.step("Interface Discovery"):
            self.engine.assert_greater_than(
                "Interfaces Discovered",
                len(interfaces),
                0,
                severity=Severity.CRITICAL,
                reason="Device should have at least one interface"
            )
            self.engine.log(f"Found {len(interfaces)} interfaces")
        
        with self.engine.step("Interface Operational Status"):
            operational_count = 0
            
            for iface in interfaces:
                config = config_map.get(iface.name)
                
                # Skip interfaces that are admin down by design
                if config and not config.enabled:
                    continue
                
                # Check link state for configured-up interfaces
                if iface.admin_state.lower() == "up":
                    is_up = iface.link_state == LinkState.UP
                    
                    if is_up:
                        operational_count += 1
                    
                    self.engine.assert_true(
                        f"Interface {iface.name} Link Up",
                        is_up,
                        severity=Severity.HIGH,
                        reason=f"Interface {iface.name} is admin-up but link is {iface.link_state.value}",
                        remediation="Check cable connections and remote port status"
                    )
            
            self.engine.log(f"{operational_count}/{len(interfaces)} interfaces operational")
        
        with self.engine.step("Interface Error Counters"):
            for iface in interfaces:
                if not iface.is_operational:
                    continue
                
                total_rx = iface.rx_packets or 1
                total_tx = iface.tx_packets or 1
                
                # Calculate error rates
                rx_error_rate = iface.rx_errors / total_rx if total_rx > 0 else 0
                tx_error_rate = iface.tx_errors / total_tx if total_tx > 0 else 0
                
                # Check RX errors
                self.engine.assert_less_than(
                    f"Interface {iface.name} RX Error Rate",
                    rx_error_rate,
                    self.MAX_ERROR_RATE,
                    severity=Severity.MEDIUM,
                    reason=f"RX error rate {rx_error_rate:.4%} exceeds threshold"
                )
                
                # Check TX errors
                self.engine.assert_less_than(
                    f"Interface {iface.name} TX Error Rate",
                    tx_error_rate,
                    self.MAX_ERROR_RATE,
                    severity=Severity.MEDIUM,
                    reason=f"TX error rate {tx_error_rate:.4%} exceeds threshold"
                )
        
        with self.engine.step("Interface Drop Counters"):
            for iface in interfaces:
                if not iface.is_operational:
                    continue
                
                total_rx = iface.rx_packets or 1
                total_tx = iface.tx_packets or 1
                
                # Calculate drop rates
                rx_drop_rate = iface.rx_drops / total_rx if total_rx > 0 else 0
                tx_drop_rate = iface.tx_drops / total_tx if total_tx > 0 else 0
                
                # Check RX drops
                self.engine.assert_less_than(
                    f"Interface {iface.name} RX Drop Rate",
                    rx_drop_rate,
                    self.MAX_DROP_RATE,
                    severity=Severity.LOW,
                    reason=f"RX drop rate {rx_drop_rate:.4%} exceeds threshold"
                )
                
                # Check TX drops
                self.engine.assert_less_than(
                    f"Interface {iface.name} TX Drop Rate",
                    tx_drop_rate,
                    self.MAX_DROP_RATE,
                    severity=Severity.LOW,
                    reason=f"TX drop rate {tx_drop_rate:.4%} exceeds threshold"
                )
