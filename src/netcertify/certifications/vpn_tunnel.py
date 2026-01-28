"""
VPN Tunnel Certification Test.

Validates VPN tunnel configuration and operational status.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity
from netcertify.schemas.status import TunnelState


class VPNCertificationTest(BaseCertificationTest):
    """
    Certification test for VPN tunnels.
    
    Validates:
    - Configured VPN tunnels are established
    - IPsec SAs are active
    - Tunnel counters show traffic flow
    - No tunnel errors or drops
    """
    
    name = "VPN Tunnel Status"
    description = "Validate VPN tunnel operational status"
    category = "vpn"
    tags = ["vpn", "ipsec", "tunnel", "connectivity"]
    
    def run(self) -> None:
        """Execute VPN tunnel certification tests."""
        
        if self.skip_if_unsupported("supports_vpn_status", "VPN Status Check"):
            return
        
        vpn_configs = self.adapter.get_vpn_tunnels()
        vpn_status = self.adapter.get_vpn_tunnel_status()
        
        with self.engine.step("VPN Configuration"):
            # If no VPNs configured, skip
            if not vpn_configs:
                self.engine.skip(
                    "VPN Validation",
                    "No VPN tunnels configured on this device"
                )
                return
            
            self.engine.log(f"Found {len(vpn_configs)} configured VPN tunnel(s)")
        
        # Build status lookup by name
        status_map = {s.name: s for s in vpn_status}
        
        with self.engine.step("VPN Tunnel Status"):
            established_count = 0
            
            for tunnel in vpn_configs:
                if not tunnel.enabled:
                    self.engine.skip(
                        f"VPN {tunnel.name} Status",
                        "Tunnel is administratively disabled"
                    )
                    continue
                
                status = status_map.get(tunnel.name)
                
                if status is None:
                    self.engine.assert_not_none(
                        f"VPN {tunnel.name} Status Available",
                        status,
                        severity=Severity.HIGH,
                        reason=f"No status information for tunnel {tunnel.name}"
                    )
                    continue
                
                # Check tunnel is established
                is_up = status.state == TunnelState.UP
                
                if is_up:
                    established_count += 1
                
                self.engine.assert_true(
                    f"VPN {tunnel.name} Established",
                    is_up,
                    severity=Severity.CRITICAL,
                    reason=f"VPN tunnel {tunnel.name} is {status.state.value}",
                    remediation="Check IKE configuration, pre-shared keys, and peer reachability"
                )
                
                # Check phase states
                if status.phase1_state:
                    self.engine.assert_contains(
                        f"VPN {tunnel.name} IKE Phase 1",
                        status.phase1_state.lower(),
                        "established",
                        severity=Severity.HIGH,
                        reason=f"IKE phase 1 state: {status.phase1_state}"
                    )
                
                if status.phase2_state:
                    phase2_ok = any(
                        x in status.phase2_state.lower() 
                        for x in ["installed", "established", "up"]
                    )
                    self.engine.assert_true(
                        f"VPN {tunnel.name} IPsec Phase 2",
                        phase2_ok,
                        severity=Severity.HIGH,
                        reason=f"IPsec phase 2 state: {status.phase2_state}"
                    )
            
            self.engine.log(
                f"{established_count}/{len(vpn_configs)} VPN tunnels established"
            )
        
        with self.engine.step("VPN Tunnel Traffic"):
            for status in vpn_status:
                if not status.is_established:
                    continue
                
                # Check for traffic flow (non-zero counters indicate activity)
                has_traffic = status.bytes_in > 0 or status.bytes_out > 0
                
                self.engine.assert_true(
                    f"VPN {status.name} Has Traffic",
                    has_traffic,
                    severity=Severity.LOW,
                    reason=f"No traffic observed on tunnel {status.name}"
                )
                
                if has_traffic:
                    self.engine.log(
                        f"Tunnel {status.name}: "
                        f"RX {status.bytes_in/1024/1024:.1f}MB, "
                        f"TX {status.bytes_out/1024/1024:.1f}MB"
                    )
