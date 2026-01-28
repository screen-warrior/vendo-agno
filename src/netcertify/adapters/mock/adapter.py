"""
Mock Firewall Adapter - Full simulation for testing.

This adapter provides realistic mock data for all firewall operations,
enabling comprehensive testing of the certification framework without
requiring access to real firewall devices.

Mock behavior can be customized through the device's custom_attributes:
    device.custom_attributes = {
        "mock_ntp_synced": True,
        "mock_ha_enabled": True,
        "mock_cpu_usage": 45.0,
        "mock_license_valid": True,
        "mock_firmware_version": "10.2.3",
        ...
    }
"""

import random
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from netcertify.adapters.base import BaseFirewallAdapter, AdapterCapabilities
from netcertify.schemas.device import DeviceInfo, DeviceVendor
from netcertify.schemas.configuration import (
    NTPConfiguration,
    NTPServer,
    DNSConfiguration,
    InterfaceConfig,
    InterfaceType,
    RoutingTable,
    RouteEntry,
    RouteType,
    SecurityZone,
    SecurityPolicy,
    PolicyAction,
    NATRule,
    NATType,
    VPNTunnel,
    VPNType,
    SNMPConfig,
    SNMPVersion,
    LoggingConfig,
    LogSeverity,
    CertificateInfo,
    HAConfiguration,
    HAMode,
)
from netcertify.schemas.status import (
    NTPStatus,
    NTPPeerStatus,
    SyncState,
    InterfaceStatus,
    LinkState,
    HAStatus,
    HAState,
    SystemHealth,
    LicenseStatus,
    LicenseFeature,
    LicenseState,
    SessionTableStatus,
    ThreatPreventionStatus,
    VPNTunnelStatus,
    TunnelState,
    ServiceStatus,
    ServiceState,
)


class MockFirewallAdapter(BaseFirewallAdapter):
    """
    Mock firewall adapter for testing and development.
    
    Simulates a fully functional firewall device with configurable behavior.
    All responses return realistic Pydantic models suitable for testing
    certification workflows.
    """
    
    def __init__(self, device: DeviceInfo):
        super().__init__(device)
        self._mock_config: Dict[str, Any] = {}
        self._load_mock_settings()
    
    def _load_mock_settings(self) -> None:
        """Load mock behavior settings from device custom_attributes."""
        attrs = self.device.custom_attributes
        
        # NTP settings
        self._mock_config["ntp_synced"] = attrs.get("mock_ntp_synced", True)
        self._mock_config["ntp_offset_ms"] = attrs.get("mock_ntp_offset_ms", 0.5)
        
        # HA settings
        self._mock_config["ha_enabled"] = attrs.get("mock_ha_enabled", False)
        self._mock_config["ha_state"] = attrs.get("mock_ha_state", "active")
        
        # System health
        self._mock_config["cpu_usage"] = attrs.get("mock_cpu_usage", 35.0)
        self._mock_config["memory_usage_percent"] = attrs.get("mock_memory_usage", 60.0)
        self._mock_config["disk_usage_percent"] = attrs.get("mock_disk_usage", 45.0)
        
        # License
        self._mock_config["license_valid"] = attrs.get("mock_license_valid", True)
        self._mock_config["license_days_remaining"] = attrs.get("mock_license_days", 365)
        
        # Firmware
        self._mock_config["firmware_version"] = attrs.get(
            "mock_firmware_version", 
            self.device.firmware_version or "10.2.3"
        )
        
        # Interface states
        self._mock_config["interface_states"] = attrs.get("mock_interface_states", {})
        
        # Threat prevention
        self._mock_config["threat_prevention_enabled"] = attrs.get("mock_threat_enabled", True)
        
        # VPN tunnels
        self._mock_config["vpn_tunnels_up"] = attrs.get("mock_vpn_tunnels_up", True)
        
        # Session table
        self._mock_config["session_utilization"] = attrs.get("mock_session_util", 25.0)
        
        # Failure simulation
        self._mock_config["simulate_failures"] = attrs.get("mock_simulate_failures", [])
    
    @property
    def vendor(self) -> DeviceVendor:
        return DeviceVendor.MOCK
    
    @property
    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            supports_api=True,
            supports_ssh=True,
            supports_ntp_config=True,
            supports_ntp_status=True,
            supports_dns_config=True,
            supports_interface_config=True,
            supports_interface_status=True,
            supports_routing_config=True,
            supports_routing_status=True,
            supports_security_zones=True,
            supports_security_policies=True,
            supports_nat=True,
            supports_vpn_config=True,
            supports_vpn_status=True,
            supports_ha_config=True,
            supports_ha_status=True,
            supports_snmp=True,
            supports_logging=True,
            supports_certificates=True,
            supports_system_health=True,
            supports_license_status=True,
            supports_session_table=True,
            supports_threat_prevention=True,
            supports_firmware_info=True,
            supports_config_backup=True,
            supports_config_commit=True,
            supports_config_rollback=True,
        )
    
    # =========================================================================
    # Connection Management
    # =========================================================================
    
    def connect(self) -> None:
        """Simulate connection establishment."""
        if "connection" in self._mock_config.get("simulate_failures", []):
            raise ConnectionError("Mock connection failure (simulated)")
        
        self._connected = True
        self._connection_time = datetime.utcnow()
    
    def disconnect(self) -> None:
        """Simulate connection closure."""
        self._connected = False
        self._connection_time = None
    
    def validate_connection(self) -> bool:
        """Validate mock connection."""
        return self._connected
    
    # =========================================================================
    # Device Information
    # =========================================================================
    
    def get_device_info(self) -> Dict[str, Any]:
        return {
            "hostname": self.device.name,
            "model": self.device.model or "MockFW-5000",
            "serial": self.device.serial_number or "MOCK123456789",
            "firmware_version": self._mock_config["firmware_version"],
            "uptime_seconds": 864000,  # 10 days
            "vendor": "Mock Vendor",
        }
    
    def get_firmware_version(self) -> str:
        return self._mock_config["firmware_version"]
    
    def get_serial_number(self) -> str:
        return self.device.serial_number or "MOCK123456789"
    
    def get_hostname(self) -> str:
        return self.device.name
    
    # =========================================================================
    # NTP Operations
    # =========================================================================
    
    def get_ntp_configuration(self) -> NTPConfiguration:
        return NTPConfiguration(
            enabled=True,
            servers=[
                NTPServer(address="0.pool.ntp.org", preferred=True),
                NTPServer(address="1.pool.ntp.org", preferred=False),
                NTPServer(address="2.pool.ntp.org", preferred=False),
            ],
            primary_server="0.pool.ntp.org",
            timezone="UTC",
            authentication_enabled=False,
        )
    
    def get_ntp_status(self) -> NTPStatus:
        is_synced = self._mock_config["ntp_synced"]
        offset = self._mock_config["ntp_offset_ms"]
        
        peers = [
            NTPPeerStatus(
                address="0.pool.ntp.org",
                stratum=2,
                reach=377,
                delay_ms=15.5,
                offset_ms=offset,
                jitter_ms=1.2,
                is_selected=True,
                is_reachable=True,
                last_response=datetime.utcnow() - timedelta(seconds=30),
            ),
            NTPPeerStatus(
                address="1.pool.ntp.org",
                stratum=2,
                reach=377,
                delay_ms=25.3,
                offset_ms=offset + 0.3,
                jitter_ms=2.1,
                is_selected=False,
                is_reachable=True,
                last_response=datetime.utcnow() - timedelta(seconds=35),
            ),
            NTPPeerStatus(
                address="2.pool.ntp.org",
                stratum=3,
                reach=377,
                delay_ms=45.8,
                offset_ms=offset + 1.5,
                jitter_ms=3.5,
                is_selected=False,
                is_reachable=True,
                last_response=datetime.utcnow() - timedelta(seconds=40),
            ),
        ]
        
        return NTPStatus(
            sync_state=SyncState.SYNCED if is_synced else SyncState.NOT_SYNCED,
            synced_to="0.pool.ntp.org" if is_synced else None,
            stratum=3 if is_synced else 16,
            reference_time=datetime.utcnow() if is_synced else None,
            system_time=datetime.utcnow(),
            offset_ms=offset if is_synced else 0.0,
            peers=peers,
            last_sync=datetime.utcnow() - timedelta(minutes=5) if is_synced else None,
        )
    
    def configure_ntp(self, config: NTPConfiguration) -> bool:
        self._mock_config["ntp_config"] = config
        return True
    
    # =========================================================================
    # DNS Operations
    # =========================================================================
    
    def get_dns_configuration(self) -> DNSConfiguration:
        return DNSConfiguration(
            primary_server="8.8.8.8",
            secondary_server="8.8.4.4",
            domain_name="example.com",
            search_domains=["example.com", "internal.example.com"],
            dns_proxy_enabled=False,
        )
    
    def configure_dns(self, config: DNSConfiguration) -> bool:
        self._mock_config["dns_config"] = config
        return True
    
    # =========================================================================
    # Interface Operations
    # =========================================================================
    
    def get_interfaces(self) -> List[InterfaceConfig]:
        return [
            InterfaceConfig(
                name="ethernet1/1",
                type=InterfaceType.ETHERNET,
                enabled=True,
                description="WAN Interface",
                ip_address="203.0.113.1/24",
                mtu=1500,
                zone="untrust",
                speed="auto",
            ),
            InterfaceConfig(
                name="ethernet1/2",
                type=InterfaceType.ETHERNET,
                enabled=True,
                description="LAN Interface",
                ip_address="10.0.0.1/24",
                mtu=1500,
                zone="trust",
                speed="auto",
            ),
            InterfaceConfig(
                name="ethernet1/3",
                type=InterfaceType.ETHERNET,
                enabled=True,
                description="DMZ Interface",
                ip_address="172.16.0.1/24",
                mtu=1500,
                zone="dmz",
                speed="auto",
            ),
            InterfaceConfig(
                name="loopback.1",
                type=InterfaceType.LOOPBACK,
                enabled=True,
                description="Loopback",
                ip_address="10.255.255.1/32",
                mtu=1500,
            ),
            InterfaceConfig(
                name="tunnel.1",
                type=InterfaceType.TUNNEL,
                enabled=True,
                description="VPN Tunnel",
                ip_address="169.254.1.1/30",
                mtu=1400,
                zone="vpn",
            ),
        ]
    
    def get_interface_status(self, interface_name: Optional[str] = None) -> List[InterfaceStatus]:
        interface_states = self._mock_config.get("interface_states", {})
        
        interfaces = [
            InterfaceStatus(
                name="ethernet1/1",
                admin_state="up",
                link_state=LinkState(interface_states.get("ethernet1/1", "up")),
                ip_address="203.0.113.1/24",
                mac_address="00:1B:17:00:01:01",
                speed_mbps=1000,
                duplex="full",
                mtu=1500,
                rx_bytes=1500000000,
                tx_bytes=1200000000,
                rx_packets=10000000,
                tx_packets=8000000,
                rx_errors=0,
                tx_errors=0,
                rx_drops=50,
                tx_drops=10,
                uptime_seconds=864000,
            ),
            InterfaceStatus(
                name="ethernet1/2",
                admin_state="up",
                link_state=LinkState(interface_states.get("ethernet1/2", "up")),
                ip_address="10.0.0.1/24",
                mac_address="00:1B:17:00:01:02",
                speed_mbps=10000,
                duplex="full",
                mtu=1500,
                rx_bytes=5000000000,
                tx_bytes=4500000000,
                rx_packets=50000000,
                tx_packets=45000000,
                rx_errors=0,
                tx_errors=0,
                rx_drops=100,
                tx_drops=50,
                uptime_seconds=864000,
            ),
            InterfaceStatus(
                name="ethernet1/3",
                admin_state="up",
                link_state=LinkState(interface_states.get("ethernet1/3", "up")),
                ip_address="172.16.0.1/24",
                mac_address="00:1B:17:00:01:03",
                speed_mbps=1000,
                duplex="full",
                mtu=1500,
                rx_bytes=500000000,
                tx_bytes=450000000,
                rx_packets=5000000,
                tx_packets=4500000,
                rx_errors=0,
                tx_errors=0,
                rx_drops=25,
                tx_drops=10,
                uptime_seconds=864000,
            ),
            InterfaceStatus(
                name="loopback.1",
                admin_state="up",
                link_state=LinkState.UP,
                ip_address="10.255.255.1/32",
                mtu=1500,
                rx_bytes=0,
                tx_bytes=0,
                rx_packets=0,
                tx_packets=0,
                rx_errors=0,
                tx_errors=0,
                rx_drops=0,
                tx_drops=0,
                uptime_seconds=864000,
            ),
            InterfaceStatus(
                name="tunnel.1",
                admin_state="up",
                link_state=LinkState.UP if self._mock_config["vpn_tunnels_up"] else LinkState.DOWN,
                ip_address="169.254.1.1/30",
                mtu=1400,
                rx_bytes=100000000,
                tx_bytes=95000000,
                rx_packets=1000000,
                tx_packets=950000,
                rx_errors=0,
                tx_errors=0,
                rx_drops=5,
                tx_drops=2,
                uptime_seconds=86400 if self._mock_config["vpn_tunnels_up"] else 0,
            ),
        ]
        
        if interface_name:
            return [i for i in interfaces if i.name == interface_name]
        return interfaces
    
    def configure_interface(self, config: InterfaceConfig) -> bool:
        return True
    
    # =========================================================================
    # Routing Operations
    # =========================================================================
    
    def get_routing_table(self, virtual_router: str = "default") -> RoutingTable:
        return RoutingTable(
            virtual_router=virtual_router,
            routes=[
                RouteEntry(
                    destination="0.0.0.0/0",
                    next_hop="203.0.113.254",
                    interface="ethernet1/1",
                    metric=10,
                    route_type=RouteType.STATIC,
                    administrative_distance=1,
                    is_active=True,
                ),
                RouteEntry(
                    destination="10.0.0.0/24",
                    next_hop=None,
                    interface="ethernet1/2",
                    metric=0,
                    route_type=RouteType.CONNECTED,
                    administrative_distance=0,
                    is_active=True,
                ),
                RouteEntry(
                    destination="172.16.0.0/24",
                    next_hop=None,
                    interface="ethernet1/3",
                    metric=0,
                    route_type=RouteType.CONNECTED,
                    administrative_distance=0,
                    is_active=True,
                ),
                RouteEntry(
                    destination="192.168.100.0/24",
                    next_hop="169.254.1.2",
                    interface="tunnel.1",
                    metric=10,
                    route_type=RouteType.STATIC,
                    administrative_distance=1,
                    is_active=True,
                ),
            ],
        )
    
    # =========================================================================
    # Security Zone Operations
    # =========================================================================
    
    def get_security_zones(self) -> List[SecurityZone]:
        return [
            SecurityZone(
                name="trust",
                interfaces=["ethernet1/2"],
                protection_profile="default-protection",
                log_setting="default",
            ),
            SecurityZone(
                name="untrust",
                interfaces=["ethernet1/1"],
                protection_profile="strict-protection",
                log_setting="default",
            ),
            SecurityZone(
                name="dmz",
                interfaces=["ethernet1/3"],
                protection_profile="default-protection",
                log_setting="default",
            ),
            SecurityZone(
                name="vpn",
                interfaces=["tunnel.1"],
                protection_profile="default-protection",
                log_setting="default",
            ),
        ]
    
    # =========================================================================
    # Security Policy Operations
    # =========================================================================
    
    def get_security_policies(self, rulebase: str = "security") -> List[SecurityPolicy]:
        return [
            SecurityPolicy(
                name="allow-outbound",
                enabled=True,
                sequence=1,
                source_zones=["trust"],
                destination_zones=["untrust"],
                source_addresses=["any"],
                destination_addresses=["any"],
                applications=["any"],
                services=["application-default"],
                action=PolicyAction.ALLOW,
                log_end=True,
                description="Allow outbound traffic",
            ),
            SecurityPolicy(
                name="allow-dns",
                enabled=True,
                sequence=2,
                source_zones=["trust", "dmz"],
                destination_zones=["untrust"],
                source_addresses=["any"],
                destination_addresses=["any"],
                applications=["dns"],
                services=["application-default"],
                action=PolicyAction.ALLOW,
                log_end=True,
                description="Allow DNS queries",
            ),
            SecurityPolicy(
                name="allow-vpn",
                enabled=True,
                sequence=3,
                source_zones=["trust"],
                destination_zones=["vpn"],
                source_addresses=["10.0.0.0/24"],
                destination_addresses=["192.168.100.0/24"],
                applications=["any"],
                services=["any"],
                action=PolicyAction.ALLOW,
                log_end=True,
                description="Allow VPN traffic",
            ),
            SecurityPolicy(
                name="deny-all",
                enabled=True,
                sequence=1000,
                source_zones=["any"],
                destination_zones=["any"],
                source_addresses=["any"],
                destination_addresses=["any"],
                applications=["any"],
                services=["any"],
                action=PolicyAction.DENY,
                log_end=True,
                description="Default deny",
            ),
        ]
    
    # =========================================================================
    # NAT Operations
    # =========================================================================
    
    def get_nat_rules(self) -> List[NATRule]:
        return [
            NATRule(
                name="outbound-nat",
                enabled=True,
                nat_type=NATType.DYNAMIC_IP_AND_PORT,
                source_zone="trust",
                destination_zone="untrust",
                source_address="10.0.0.0/24",
                translated_address="203.0.113.1",
            ),
            NATRule(
                name="dmz-nat",
                enabled=True,
                nat_type=NATType.DYNAMIC_IP_AND_PORT,
                source_zone="dmz",
                destination_zone="untrust",
                source_address="172.16.0.0/24",
                translated_address="203.0.113.1",
            ),
        ]
    
    # =========================================================================
    # VPN Operations
    # =========================================================================
    
    def get_vpn_tunnels(self) -> List[VPNTunnel]:
        return [
            VPNTunnel(
                name="site-to-site-vpn",
                tunnel_type=VPNType.IPSEC,
                enabled=True,
                local_address="203.0.113.1",
                remote_address="198.51.100.1",
                ike_gateway="ike-gw-1",
                ipsec_crypto_profile="aes256-sha256",
                local_networks=["10.0.0.0/24"],
                remote_networks=["192.168.100.0/24"],
                tunnel_interface="tunnel.1",
            ),
        ]
    
    def get_vpn_tunnel_status(self) -> List[VPNTunnelStatus]:
        is_up = self._mock_config["vpn_tunnels_up"]
        
        return [
            VPNTunnelStatus(
                name="site-to-site-vpn",
                state=TunnelState.UP if is_up else TunnelState.DOWN,
                local_address="203.0.113.1",
                remote_address="198.51.100.1",
                uptime_seconds=86400 if is_up else 0,
                established_at=datetime.utcnow() - timedelta(days=1) if is_up else None,
                last_rekey=datetime.utcnow() - timedelta(hours=2) if is_up else None,
                bytes_in=100000000 if is_up else 0,
                bytes_out=95000000 if is_up else 0,
                packets_in=1000000 if is_up else 0,
                packets_out=950000 if is_up else 0,
                ike_version="IKEv2",
                phase1_state="established" if is_up else "down",
                phase2_state="installed" if is_up else "down",
                encryption_algorithm="AES-256-CBC",
                authentication_algorithm="SHA256",
            ),
        ]
    
    # =========================================================================
    # High Availability Operations
    # =========================================================================
    
    def get_ha_configuration(self) -> HAConfiguration:
        if not self._mock_config["ha_enabled"]:
            return HAConfiguration(enabled=False, mode=HAMode.DISABLED)
        
        return HAConfiguration(
            enabled=True,
            mode=HAMode.ACTIVE_PASSIVE,
            group_id=1,
            peer_address="192.168.255.2",
            priority=100,
            preemptive=True,
            heartbeat_interval_ms=1000,
            heartbeat_threshold=3,
            ha1_interface="ethernet1/10",
            ha2_interface="ethernet1/11",
            config_sync_enabled=True,
            session_sync_enabled=True,
        )
    
    def get_ha_status(self) -> HAStatus:
        if not self._mock_config["ha_enabled"]:
            return HAStatus(enabled=False, local_state=HAState.DISABLED, peer_state=HAState.DISABLED)
        
        state_map = {
            "active": HAState.ACTIVE,
            "passive": HAState.PASSIVE,
            "initial": HAState.INITIAL,
            "suspended": HAState.SUSPENDED,
        }
        local_state = state_map.get(self._mock_config["ha_state"], HAState.ACTIVE)
        peer_state = HAState.PASSIVE if local_state == HAState.ACTIVE else HAState.ACTIVE
        
        return HAStatus(
            enabled=True,
            local_state=local_state,
            peer_state=peer_state,
            peer_connected=True,
            peer_address="192.168.255.2",
            config_synced=True,
            session_synced=True,
            last_sync_time=datetime.utcnow() - timedelta(seconds=30),
            ha1_link_status="up",
            ha2_link_status="up",
            last_failover=datetime.utcnow() - timedelta(days=30),
            failover_count=2,
            local_priority=100,
            peer_priority=90,
        )
    
    # =========================================================================
    # System Health Operations
    # =========================================================================
    
    def get_system_health(self) -> SystemHealth:
        return SystemHealth(
            cpu_utilization_percent=self._mock_config["cpu_usage"],
            cpu_cores=8,
            memory_total_mb=16384,
            memory_used_mb=int(16384 * self._mock_config["memory_usage_percent"] / 100),
            memory_free_mb=int(16384 * (100 - self._mock_config["memory_usage_percent"]) / 100),
            disk_total_gb=500.0,
            disk_used_gb=500.0 * self._mock_config["disk_usage_percent"] / 100,
            uptime_seconds=864000,  # 10 days
            load_average=[1.5, 1.2, 0.8],
            temperature_celsius=45.0,
            power_status="normal",
            fan_status="normal",
            collected_at=datetime.utcnow(),
        )
    
    def get_system_uptime(self) -> int:
        return 864000  # 10 days
    
    # =========================================================================
    # License Operations
    # =========================================================================
    
    def get_license_status(self) -> LicenseStatus:
        is_valid = self._mock_config["license_valid"]
        days_remaining = self._mock_config["license_days_remaining"]
        expiration = datetime.utcnow() + timedelta(days=days_remaining)
        
        state = LicenseState.VALID if is_valid else LicenseState.EXPIRED
        if is_valid and days_remaining <= 30:
            state = LicenseState.EXPIRING_SOON
        
        return LicenseStatus(
            serial_number=self.get_serial_number(),
            support_level="Premium",
            overall_state=state,
            features=[
                LicenseFeature(
                    name="Threat Prevention",
                    enabled=True,
                    state=state,
                    expiration_date=expiration,
                ),
                LicenseFeature(
                    name="URL Filtering",
                    enabled=True,
                    state=state,
                    expiration_date=expiration,
                ),
                LicenseFeature(
                    name="WildFire",
                    enabled=True,
                    state=state,
                    expiration_date=expiration,
                ),
                LicenseFeature(
                    name="GlobalProtect",
                    enabled=True,
                    state=state,
                    expiration_date=expiration,
                ),
                LicenseFeature(
                    name="DNS Security",
                    enabled=True,
                    state=state,
                    expiration_date=expiration,
                ),
            ],
            earliest_expiration=expiration,
            licensed_throughput_gbps=10.0,
            licensed_sessions=2000000,
        )
    
    # =========================================================================
    # Session Table Operations
    # =========================================================================
    
    def get_session_table_status(self) -> SessionTableStatus:
        utilization = self._mock_config["session_utilization"]
        max_sessions = 2000000
        active = int(max_sessions * utilization / 100)
        
        return SessionTableStatus(
            max_sessions=max_sessions,
            active_sessions=active,
            tcp_sessions=int(active * 0.7),
            udp_sessions=int(active * 0.25),
            icmp_sessions=int(active * 0.05),
            sessions_per_second=5000,
            peak_sessions=int(active * 1.2),
            warning_threshold_percent=80.0,
            critical_threshold_percent=95.0,
        )
    
    # =========================================================================
    # Threat Prevention Operations
    # =========================================================================
    
    def get_threat_prevention_status(self) -> ThreatPreventionStatus:
        enabled = self._mock_config["threat_prevention_enabled"]
        
        return ThreatPreventionStatus(
            antivirus_enabled=enabled,
            anti_spyware_enabled=enabled,
            vulnerability_protection_enabled=enabled,
            url_filtering_enabled=enabled,
            wildfire_enabled=enabled,
            dos_protection_enabled=enabled,
            antivirus_version="4500-5000" if enabled else None,
            threat_version="8700-8200" if enabled else None,
            app_version="8700-8100" if enabled else None,
            wildfire_version="750000-755000" if enabled else None,
            url_database_version="20240115" if enabled else None,
            last_av_update=datetime.utcnow() - timedelta(hours=6) if enabled else None,
            last_threat_update=datetime.utcnow() - timedelta(hours=6) if enabled else None,
            last_app_update=datetime.utcnow() - timedelta(hours=12) if enabled else None,
            last_wildfire_update=datetime.utcnow() - timedelta(minutes=15) if enabled else None,
            threats_blocked_24h=1500 if enabled else 0,
            malware_blocked_24h=50 if enabled else 0,
            phishing_blocked_24h=200 if enabled else 0,
        )
    
    # =========================================================================
    # SNMP Operations
    # =========================================================================
    
    def get_snmp_configuration(self) -> SNMPConfig:
        return SNMPConfig(
            enabled=True,
            version=SNMPVersion.V3,
            username="snmpuser",
            auth_protocol="SHA",
            priv_protocol="AES128",
            trap_receivers=["192.168.1.100", "192.168.1.101"],
            system_location="DataCenter-East-Rack12",
            system_contact="noc@example.com",
        )
    
    # =========================================================================
    # Logging Operations
    # =========================================================================
    
    def get_logging_configuration(self) -> LoggingConfig:
        return LoggingConfig(
            syslog_enabled=True,
            syslog_servers=["192.168.1.50", "192.168.1.51"],
            syslog_port=514,
            syslog_protocol="tcp",
            minimum_severity=LogSeverity.WARNING,
            local_log_enabled=True,
            log_rotation_size_mb=100,
            log_retention_days=30,
            traffic_log_enabled=True,
            threat_log_enabled=True,
            config_log_enabled=True,
            system_log_enabled=True,
        )
    
    # =========================================================================
    # Certificate Operations
    # =========================================================================
    
    def get_certificates(self) -> List[CertificateInfo]:
        return [
            CertificateInfo(
                name="device-cert",
                subject="CN=fw-mock-01.example.com",
                issuer="CN=Example CA",
                serial_number="1234567890ABCDEF",
                valid_from=datetime.utcnow() - timedelta(days=365),
                valid_until=datetime.utcnow() + timedelta(days=365),
                key_type="RSA",
                key_size=2048,
                is_ca=False,
                key_usage=["Digital Signature", "Key Encipherment"],
            ),
            CertificateInfo(
                name="ssl-inbound-cert",
                subject="CN=*.example.com",
                issuer="CN=DigiCert CA",
                serial_number="FEDCBA0987654321",
                valid_from=datetime.utcnow() - timedelta(days=180),
                valid_until=datetime.utcnow() + timedelta(days=185),
                key_type="RSA",
                key_size=4096,
                is_ca=False,
                key_usage=["Digital Signature", "Key Encipherment"],
            ),
            CertificateInfo(
                name="root-ca",
                subject="CN=Example Root CA",
                issuer="CN=Example Root CA",
                serial_number="0000000000000001",
                valid_from=datetime.utcnow() - timedelta(days=3650),
                valid_until=datetime.utcnow() + timedelta(days=3650),
                key_type="RSA",
                key_size=4096,
                is_ca=True,
                key_usage=["Certificate Sign", "CRL Sign"],
            ),
        ]
    
    # =========================================================================
    # Service Status Operations
    # =========================================================================
    
    def get_service_status(self) -> List[ServiceStatus]:
        return [
            ServiceStatus(
                name="management-server",
                state=ServiceState.RUNNING,
                enabled=True,
                pid=1234,
                uptime_seconds=864000,
            ),
            ServiceStatus(
                name="log-collector",
                state=ServiceState.RUNNING,
                enabled=True,
                pid=1235,
                uptime_seconds=864000,
            ),
            ServiceStatus(
                name="ipsec",
                state=ServiceState.RUNNING,
                enabled=True,
                pid=1236,
                uptime_seconds=864000,
            ),
            ServiceStatus(
                name="ssl-vpn",
                state=ServiceState.RUNNING,
                enabled=True,
                pid=1237,
                uptime_seconds=864000,
            ),
            ServiceStatus(
                name="user-id",
                state=ServiceState.RUNNING,
                enabled=True,
                pid=1238,
                uptime_seconds=864000,
            ),
        ]
    
    # =========================================================================
    # Configuration Management Operations
    # =========================================================================
    
    def commit_configuration(self, description: str = "") -> bool:
        return True
    
    def backup_configuration(self) -> str:
        return """<?xml version="1.0"?>
<config version="10.2.0">
  <mgt-config>
    <users><entry name="admin"><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry></users>
  </mgt-config>
  <devices><entry name="localhost.localdomain">
    <deviceconfig><system><hostname>mock-firewall</hostname></system></deviceconfig>
  </entry></devices>
</config>"""
    
    def rollback_configuration(self, version: Optional[str] = None) -> bool:
        return True
