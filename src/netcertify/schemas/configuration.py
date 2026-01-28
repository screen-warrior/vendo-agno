"""
Configuration Schemas - Pydantic models for firewall configurations.

These models represent the expected and actual configuration state of firewall features.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pydantic import BaseModel, Field, field_validator


class NTPServer(BaseModel):
    """Individual NTP server configuration."""
    address: str = Field(..., description="NTP server address (hostname or IP)")
    preferred: bool = Field(False, description="Is this the preferred server")
    authentication_enabled: bool = Field(False, description="NTP authentication enabled")
    key_id: Optional[int] = Field(None, description="Authentication key ID")
    
    model_config = {"extra": "forbid"}


class NTPConfiguration(BaseModel):
    """Complete NTP configuration model."""
    enabled: bool = Field(True, description="NTP synchronization enabled")
    servers: List[NTPServer] = Field(default_factory=list, description="Configured NTP servers")
    primary_server: Optional[str] = Field(None, description="Primary NTP server address")
    timezone: str = Field("UTC", description="System timezone")
    authentication_enabled: bool = Field(False, description="Global NTP authentication")
    
    model_config = {"extra": "forbid"}
    
    @property
    def server_count(self) -> int:
        return len(self.servers)


class DNSConfiguration(BaseModel):
    """DNS resolver configuration."""
    primary_server: Optional[str] = Field(None, description="Primary DNS server")
    secondary_server: Optional[str] = Field(None, description="Secondary DNS server")
    domain_name: Optional[str] = Field(None, description="Default domain name")
    search_domains: List[str] = Field(default_factory=list, description="DNS search domains")
    dns_proxy_enabled: bool = Field(False, description="DNS proxy functionality")
    
    model_config = {"extra": "forbid"}


class InterfaceType(str, Enum):
    """Network interface types."""
    ETHERNET = "ethernet"
    LOOPBACK = "loopback"
    TUNNEL = "tunnel"
    VLAN = "vlan"
    AGGREGATE = "aggregate"
    MANAGEMENT = "management"


class InterfaceConfig(BaseModel):
    """Network interface configuration."""
    name: str = Field(..., description="Interface name (e.g., ethernet1/1)")
    type: InterfaceType = Field(InterfaceType.ETHERNET, description="Interface type")
    enabled: bool = Field(True, description="Administrative status")
    description: Optional[str] = Field(None, description="Interface description")
    
    # Layer 3 configuration
    ip_address: Optional[str] = Field(None, description="IPv4 address with mask")
    ipv6_address: Optional[str] = Field(None, description="IPv6 address with prefix")
    mtu: int = Field(1500, ge=576, le=9216, description="MTU size")
    
    # Layer 2 configuration
    vlan_id: Optional[int] = Field(None, ge=1, le=4094, description="VLAN ID")
    
    # Security zone
    zone: Optional[str] = Field(None, description="Security zone assignment")
    
    # Link parameters
    speed: Optional[str] = Field(None, description="Link speed (auto, 1g, 10g, etc.)")
    duplex: Optional[str] = Field(None, description="Duplex mode")
    
    model_config = {"extra": "forbid"}


class RouteType(str, Enum):
    """Routing entry types."""
    STATIC = "static"
    CONNECTED = "connected"
    BGP = "bgp"
    OSPF = "ospf"
    EIGRP = "eigrp"


class RouteEntry(BaseModel):
    """Individual routing table entry."""
    destination: str = Field(..., description="Destination network")
    next_hop: Optional[str] = Field(None, description="Next-hop address")
    interface: Optional[str] = Field(None, description="Egress interface")
    metric: int = Field(0, ge=0, description="Route metric")
    route_type: RouteType = Field(RouteType.STATIC, description="Route type")
    administrative_distance: int = Field(1, ge=0, le=255, description="Admin distance")
    is_active: bool = Field(True, description="Route is active in RIB")
    
    model_config = {"extra": "forbid"}


class RoutingTable(BaseModel):
    """Complete routing table configuration."""
    virtual_router: str = Field("default", description="Virtual router name")
    routes: List[RouteEntry] = Field(default_factory=list, description="Route entries")
    
    model_config = {"extra": "forbid"}
    
    @property
    def route_count(self) -> int:
        return len(self.routes)
    
    @property
    def static_routes(self) -> List[RouteEntry]:
        return [r for r in self.routes if r.route_type == RouteType.STATIC]


class SecurityZone(BaseModel):
    """Security zone definition."""
    name: str = Field(..., description="Zone name")
    interfaces: List[str] = Field(default_factory=list, description="Member interfaces")
    protection_profile: Optional[str] = Field(None, description="Zone protection profile")
    log_setting: Optional[str] = Field(None, description="Log forwarding profile")
    enable_packet_buffer_protection: bool = Field(False)
    
    model_config = {"extra": "forbid"}


class PolicyAction(str, Enum):
    """Security policy actions."""
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    RESET_CLIENT = "reset-client"
    RESET_SERVER = "reset-server"
    RESET_BOTH = "reset-both"


class SecurityPolicy(BaseModel):
    """Security/firewall policy rule."""
    name: str = Field(..., description="Policy name")
    enabled: bool = Field(True, description="Policy enabled")
    sequence: int = Field(0, ge=0, description="Rule sequence/order")
    
    # Match criteria
    source_zones: List[str] = Field(default_factory=list, description="Source zones")
    destination_zones: List[str] = Field(default_factory=list, description="Destination zones")
    source_addresses: List[str] = Field(default_factory=list, description="Source addresses/groups")
    destination_addresses: List[str] = Field(default_factory=list, description="Destination addresses/groups")
    applications: List[str] = Field(default_factory=list, description="Applications")
    services: List[str] = Field(default_factory=list, description="Services/ports")
    
    # Action
    action: PolicyAction = Field(PolicyAction.DENY, description="Policy action")
    
    # Security profiles
    antivirus_profile: Optional[str] = Field(None, description="Antivirus profile")
    vulnerability_profile: Optional[str] = Field(None, description="Vulnerability profile")
    spyware_profile: Optional[str] = Field(None, description="Anti-spyware profile")
    url_filtering_profile: Optional[str] = Field(None, description="URL filtering profile")
    file_blocking_profile: Optional[str] = Field(None, description="File blocking profile")
    
    # Logging
    log_start: bool = Field(False, description="Log session start")
    log_end: bool = Field(True, description="Log session end")
    log_setting: Optional[str] = Field(None, description="Log forwarding profile")
    
    # Metadata
    description: Optional[str] = Field(None, description="Policy description")
    tags: List[str] = Field(default_factory=list, description="Policy tags")
    
    model_config = {"extra": "forbid"}


class NATType(str, Enum):
    """NAT rule types."""
    SOURCE = "source"
    DESTINATION = "destination"
    STATIC = "static"
    DYNAMIC_IP = "dynamic-ip"
    DYNAMIC_IP_AND_PORT = "dynamic-ip-and-port"


class NATRule(BaseModel):
    """NAT translation rule."""
    name: str = Field(..., description="NAT rule name")
    enabled: bool = Field(True, description="Rule enabled")
    nat_type: NATType = Field(..., description="NAT type")
    
    # Original packet match
    source_zone: Optional[str] = Field(None, description="Source zone")
    destination_zone: Optional[str] = Field(None, description="Destination zone")
    source_address: Optional[str] = Field(None, description="Original source")
    destination_address: Optional[str] = Field(None, description="Original destination")
    service: Optional[str] = Field(None, description="Service/port")
    
    # Translation
    translated_address: Optional[str] = Field(None, description="Translated address")
    translated_port: Optional[int] = Field(None, description="Translated port")
    interface: Optional[str] = Field(None, description="NAT interface")
    
    model_config = {"extra": "forbid"}


class VPNType(str, Enum):
    """VPN tunnel types."""
    IPSEC = "ipsec"
    SSL = "ssl"
    GLOBALPROTECT = "globalprotect"
    SITE_TO_SITE = "site-to-site"


class VPNTunnel(BaseModel):
    """VPN tunnel configuration."""
    name: str = Field(..., description="Tunnel name")
    tunnel_type: VPNType = Field(..., description="VPN type")
    enabled: bool = Field(True, description="Tunnel enabled")
    
    # Endpoints
    local_address: Optional[str] = Field(None, description="Local endpoint")
    remote_address: Optional[str] = Field(None, description="Remote endpoint")
    
    # IPSec parameters
    ike_gateway: Optional[str] = Field(None, description="IKE gateway name")
    ipsec_crypto_profile: Optional[str] = Field(None, description="IPSec crypto profile")
    
    # Proxy IDs / traffic selectors
    local_networks: List[str] = Field(default_factory=list, description="Local networks")
    remote_networks: List[str] = Field(default_factory=list, description="Remote networks")
    
    # Tunnel interface
    tunnel_interface: Optional[str] = Field(None, description="Associated tunnel interface")
    
    model_config = {"extra": "forbid"}


class SNMPVersion(str, Enum):
    """SNMP protocol versions."""
    V2C = "v2c"
    V3 = "v3"


class SNMPConfig(BaseModel):
    """SNMP configuration."""
    enabled: bool = Field(False, description="SNMP enabled")
    version: SNMPVersion = Field(SNMPVersion.V3, description="SNMP version")
    
    # SNMPv2c
    community_string: Optional[str] = Field(None, description="Community string (v2c)")
    
    # SNMPv3
    username: Optional[str] = Field(None, description="SNMPv3 username")
    auth_protocol: Optional[str] = Field(None, description="Authentication protocol")
    priv_protocol: Optional[str] = Field(None, description="Privacy protocol")
    
    # Trap receivers
    trap_receivers: List[str] = Field(default_factory=list, description="Trap receiver addresses")
    
    # System info
    system_location: Optional[str] = Field(None, description="System location")
    system_contact: Optional[str] = Field(None, description="System contact")
    
    model_config = {"extra": "forbid"}


class LogSeverity(str, Enum):
    """Syslog severity levels."""
    EMERGENCY = "emergency"
    ALERT = "alert"
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFORMATIONAL = "informational"
    DEBUG = "debug"


class LoggingConfig(BaseModel):
    """System logging configuration."""
    syslog_enabled: bool = Field(False, description="Syslog forwarding enabled")
    syslog_servers: List[str] = Field(default_factory=list, description="Syslog server addresses")
    syslog_port: int = Field(514, description="Syslog port")
    syslog_protocol: str = Field("udp", description="Syslog protocol (udp/tcp/ssl)")
    minimum_severity: LogSeverity = Field(LogSeverity.WARNING, description="Minimum log severity")
    
    # Local logging
    local_log_enabled: bool = Field(True, description="Local logging enabled")
    log_rotation_size_mb: int = Field(100, description="Log rotation size")
    log_retention_days: int = Field(30, description="Log retention period")
    
    # Traffic logging
    traffic_log_enabled: bool = Field(True, description="Traffic logging")
    threat_log_enabled: bool = Field(True, description="Threat logging")
    config_log_enabled: bool = Field(True, description="Configuration logging")
    system_log_enabled: bool = Field(True, description="System logging")
    
    model_config = {"extra": "forbid"}


class CertificateInfo(BaseModel):
    """SSL/TLS certificate information."""
    name: str = Field(..., description="Certificate name")
    subject: str = Field(..., description="Certificate subject")
    issuer: str = Field(..., description="Certificate issuer")
    serial_number: str = Field(..., description="Serial number")
    
    # Validity
    valid_from: datetime = Field(..., description="Valid from date")
    valid_until: datetime = Field(..., description="Expiration date")
    
    # Key info
    key_type: str = Field("RSA", description="Key algorithm")
    key_size: int = Field(2048, description="Key size in bits")
    
    # Usage
    is_ca: bool = Field(False, description="Is CA certificate")
    key_usage: List[str] = Field(default_factory=list, description="Key usage extensions")
    
    model_config = {"extra": "forbid"}
    
    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.valid_until
    
    @property
    def days_until_expiry(self) -> int:
        delta = self.valid_until - datetime.utcnow()
        return delta.days


class HAMode(str, Enum):
    """High Availability modes."""
    DISABLED = "disabled"
    ACTIVE_PASSIVE = "active-passive"
    ACTIVE_ACTIVE = "active-active"
    CLUSTER = "cluster"


class HAConfiguration(BaseModel):
    """High Availability configuration."""
    enabled: bool = Field(False, description="HA enabled")
    mode: HAMode = Field(HAMode.DISABLED, description="HA mode")
    
    # Cluster identity
    group_id: Optional[int] = Field(None, description="HA group ID")
    peer_address: Optional[str] = Field(None, description="HA peer address")
    
    # Priority and preemption
    priority: int = Field(100, ge=1, le=255, description="HA priority")
    preemptive: bool = Field(False, description="Preemptive failover")
    
    # Heartbeat
    heartbeat_interval_ms: int = Field(1000, description="Heartbeat interval")
    heartbeat_threshold: int = Field(3, description="Missed heartbeats before failover")
    
    # Interfaces
    ha1_interface: Optional[str] = Field(None, description="HA1 control link")
    ha2_interface: Optional[str] = Field(None, description="HA2 data link")
    ha3_interface: Optional[str] = Field(None, description="HA3 backup link")
    
    # Sync settings
    config_sync_enabled: bool = Field(True, description="Configuration sync")
    session_sync_enabled: bool = Field(True, description="Session sync")
    
    model_config = {"extra": "forbid"}


class SystemConfiguration(BaseModel):
    """
    Aggregate system configuration model.
    
    Contains all configurable aspects of a firewall device.
    """
    hostname: str = Field(..., description="System hostname")
    domain: Optional[str] = Field(None, description="Domain name")
    
    # Time and network services
    ntp: NTPConfiguration = Field(default_factory=NTPConfiguration)
    dns: DNSConfiguration = Field(default_factory=DNSConfiguration)
    
    # Network
    interfaces: List[InterfaceConfig] = Field(default_factory=list)
    zones: List[SecurityZone] = Field(default_factory=list)
    routing: RoutingTable = Field(default_factory=RoutingTable)
    
    # Security
    policies: List[SecurityPolicy] = Field(default_factory=list)
    nat_rules: List[NATRule] = Field(default_factory=list)
    vpn_tunnels: List[VPNTunnel] = Field(default_factory=list)
    
    # Management
    snmp: SNMPConfig = Field(default_factory=SNMPConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    certificates: List[CertificateInfo] = Field(default_factory=list)
    
    # High availability
    ha: HAConfiguration = Field(default_factory=HAConfiguration)
    
    # Metadata
    last_commit: Optional[datetime] = Field(None, description="Last configuration commit")
    config_version: Optional[str] = Field(None, description="Configuration version")
    
    model_config = {"extra": "forbid"}
