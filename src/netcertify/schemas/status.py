"""
Status Schemas - Pydantic models for runtime status and health data.

These models capture the operational state of firewall devices and their features.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, computed_field


class SyncState(str, Enum):
    """Synchronization states."""
    SYNCED = "synced"
    SYNCING = "syncing"
    NOT_SYNCED = "not_synced"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class NTPPeerStatus(BaseModel):
    """Status of an individual NTP peer."""
    address: str = Field(..., description="NTP server address")
    stratum: int = Field(-1, ge=-1, le=16, description="NTP stratum level")
    reach: int = Field(0, ge=0, le=377, description="Reachability register (octal)")
    delay_ms: float = Field(0.0, description="Round-trip delay in milliseconds")
    offset_ms: float = Field(0.0, description="Clock offset in milliseconds")
    jitter_ms: float = Field(0.0, description="Dispersion/jitter in milliseconds")
    is_selected: bool = Field(False, description="Currently selected as sync source")
    is_reachable: bool = Field(False, description="Server is reachable")
    last_response: Optional[datetime] = Field(None, description="Last response time")
    
    model_config = {"extra": "forbid"}


class NTPStatus(BaseModel):
    """Complete NTP synchronization status."""
    sync_state: SyncState = Field(SyncState.UNKNOWN, description="Overall sync state")
    synced_to: Optional[str] = Field(None, description="Current sync source")
    stratum: int = Field(-1, description="Local stratum level")
    reference_time: Optional[datetime] = Field(None, description="Reference timestamp")
    system_time: datetime = Field(default_factory=datetime.utcnow, description="Device system time")
    offset_ms: float = Field(0.0, description="Clock offset from reference")
    peers: List[NTPPeerStatus] = Field(default_factory=list, description="NTP peer statuses")
    last_sync: Optional[datetime] = Field(None, description="Last successful sync")
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def is_synchronized(self) -> bool:
        """Check if NTP is properly synchronized."""
        return self.sync_state == SyncState.SYNCED and self.synced_to is not None
    
    @computed_field
    @property
    def reachable_peers(self) -> int:
        """Count of reachable NTP peers."""
        return sum(1 for p in self.peers if p.is_reachable)


class LinkState(str, Enum):
    """Interface link states."""
    UP = "up"
    DOWN = "down"
    ADMIN_DOWN = "admin_down"
    ERROR = "error"
    UNKNOWN = "unknown"


class InterfaceStatus(BaseModel):
    """Runtime status of a network interface."""
    name: str = Field(..., description="Interface name")
    admin_state: str = Field("up", description="Administrative state")
    link_state: LinkState = Field(LinkState.UNKNOWN, description="Link state")
    
    # Addressing
    ip_address: Optional[str] = Field(None, description="Configured IP")
    mac_address: Optional[str] = Field(None, description="MAC address")
    
    # Link parameters
    speed_mbps: Optional[int] = Field(None, description="Current speed in Mbps")
    duplex: Optional[str] = Field(None, description="Current duplex mode")
    mtu: int = Field(1500, description="Current MTU")
    
    # Counters
    rx_bytes: int = Field(0, ge=0, description="Received bytes")
    tx_bytes: int = Field(0, ge=0, description="Transmitted bytes")
    rx_packets: int = Field(0, ge=0, description="Received packets")
    tx_packets: int = Field(0, ge=0, description="Transmitted packets")
    rx_errors: int = Field(0, ge=0, description="Receive errors")
    tx_errors: int = Field(0, ge=0, description="Transmit errors")
    rx_drops: int = Field(0, ge=0, description="Receive drops")
    tx_drops: int = Field(0, ge=0, description="Transmit drops")
    
    # Timestamps
    last_flap: Optional[datetime] = Field(None, description="Last link state change")
    uptime_seconds: int = Field(0, ge=0, description="Interface uptime")
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def is_operational(self) -> bool:
        """Check if interface is operationally up."""
        return self.link_state == LinkState.UP


class HAState(str, Enum):
    """HA operational states."""
    ACTIVE = "active"
    PASSIVE = "passive"
    INITIAL = "initial"
    SUSPENDED = "suspended"
    TENTATIVE = "tentative"
    NON_FUNCTIONAL = "non-functional"
    DISABLED = "disabled"


class HAStatus(BaseModel):
    """High Availability runtime status."""
    enabled: bool = Field(False, description="HA is enabled")
    local_state: HAState = Field(HAState.DISABLED, description="Local device state")
    peer_state: HAState = Field(HAState.DISABLED, description="Peer device state")
    
    # Connectivity
    peer_connected: bool = Field(False, description="Peer is connected")
    peer_address: Optional[str] = Field(None, description="Peer IP address")
    
    # Sync status
    config_synced: bool = Field(False, description="Configuration synchronized")
    session_synced: bool = Field(False, description="Sessions synchronized")
    last_sync_time: Optional[datetime] = Field(None, description="Last sync time")
    
    # Health
    ha1_link_status: str = Field("unknown", description="HA1 link status")
    ha2_link_status: str = Field("unknown", description="HA2 link status")
    
    # Failover history
    last_failover: Optional[datetime] = Field(None, description="Last failover event")
    failover_count: int = Field(0, ge=0, description="Total failover count")
    failover_reason: Optional[str] = Field(None, description="Last failover reason")
    
    # Priority
    local_priority: int = Field(100, description="Local priority")
    peer_priority: int = Field(100, description="Peer priority")
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def is_healthy(self) -> bool:
        """Check if HA is in a healthy state."""
        if not self.enabled:
            return True  # Disabled is considered healthy
        return (
            self.peer_connected and 
            self.config_synced and 
            self.local_state in [HAState.ACTIVE, HAState.PASSIVE]
        )


class ResourceUtilization(BaseModel):
    """System resource utilization metrics."""
    name: str = Field(..., description="Resource name")
    current_value: float = Field(0.0, ge=0, description="Current utilization")
    max_value: float = Field(100.0, description="Maximum value")
    unit: str = Field("percent", description="Unit of measurement")
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def utilization_percent(self) -> float:
        """Calculate utilization percentage."""
        if self.max_value == 0:
            return 0.0
        return (self.current_value / self.max_value) * 100


class SystemHealth(BaseModel):
    """Overall system health and resource status."""
    # CPU
    cpu_utilization_percent: float = Field(0.0, ge=0, le=100, description="CPU usage")
    cpu_cores: int = Field(1, ge=1, description="CPU core count")
    
    # Memory
    memory_total_mb: int = Field(0, ge=0, description="Total memory in MB")
    memory_used_mb: int = Field(0, ge=0, description="Used memory in MB")
    memory_free_mb: int = Field(0, ge=0, description="Free memory in MB")
    
    # Disk/Storage
    disk_total_gb: float = Field(0.0, ge=0, description="Total disk in GB")
    disk_used_gb: float = Field(0.0, ge=0, description="Used disk in GB")
    
    # System
    uptime_seconds: int = Field(0, ge=0, description="System uptime")
    load_average: List[float] = Field(default_factory=list, description="Load averages")
    
    # Temperature (if available)
    temperature_celsius: Optional[float] = Field(None, description="System temperature")
    
    # Power
    power_status: str = Field("normal", description="Power supply status")
    
    # Fan status
    fan_status: str = Field("normal", description="Fan/cooling status")
    
    # Custom metrics
    custom_metrics: Dict[str, ResourceUtilization] = Field(
        default_factory=dict, 
        description="Additional resource metrics"
    )
    
    # Timestamp
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def memory_utilization_percent(self) -> float:
        """Calculate memory utilization percentage."""
        if self.memory_total_mb == 0:
            return 0.0
        return (self.memory_used_mb / self.memory_total_mb) * 100
    
    @computed_field
    @property
    def disk_utilization_percent(self) -> float:
        """Calculate disk utilization percentage."""
        if self.disk_total_gb == 0:
            return 0.0
        return (self.disk_used_gb / self.disk_total_gb) * 100
    
    @computed_field
    @property
    def uptime_days(self) -> float:
        """Convert uptime to days."""
        return self.uptime_seconds / 86400


class LicenseState(str, Enum):
    """License validity states."""
    VALID = "valid"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class LicenseFeature(BaseModel):
    """Individual license feature status."""
    name: str = Field(..., description="Feature name")
    enabled: bool = Field(False, description="Feature is licensed")
    state: LicenseState = Field(LicenseState.UNKNOWN, description="License state")
    expiration_date: Optional[datetime] = Field(None, description="Expiration date")
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def days_until_expiry(self) -> Optional[int]:
        """Days until license expires."""
        if self.expiration_date is None:
            return None
        delta = self.expiration_date - datetime.utcnow()
        return delta.days


class LicenseStatus(BaseModel):
    """Overall license status."""
    serial_number: str = Field(..., description="Device serial number")
    support_level: Optional[str] = Field(None, description="Support level")
    
    # Overall state
    overall_state: LicenseState = Field(LicenseState.UNKNOWN)
    
    # Features
    features: List[LicenseFeature] = Field(default_factory=list)
    
    # Expiration tracking
    earliest_expiration: Optional[datetime] = Field(None, description="Earliest feature expiration")
    
    # Capacity
    licensed_throughput_gbps: Optional[float] = Field(None, description="Licensed throughput")
    licensed_sessions: Optional[int] = Field(None, description="Licensed session count")
    licensed_users: Optional[int] = Field(None, description="Licensed user count")
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def expiring_features(self) -> List[LicenseFeature]:
        """Features expiring within 30 days."""
        return [
            f for f in self.features 
            if f.days_until_expiry is not None and 0 < f.days_until_expiry <= 30
        ]


class SessionTableStatus(BaseModel):
    """Session/connection table status."""
    max_sessions: int = Field(0, ge=0, description="Maximum supported sessions")
    active_sessions: int = Field(0, ge=0, description="Currently active sessions")
    tcp_sessions: int = Field(0, ge=0, description="Active TCP sessions")
    udp_sessions: int = Field(0, ge=0, description="Active UDP sessions")
    icmp_sessions: int = Field(0, ge=0, description="Active ICMP sessions")
    
    # Rate
    sessions_per_second: int = Field(0, ge=0, description="New sessions per second")
    peak_sessions: int = Field(0, ge=0, description="Peak session count")
    
    # Thresholds
    warning_threshold_percent: float = Field(80.0, description="Warning threshold")
    critical_threshold_percent: float = Field(95.0, description="Critical threshold")
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def utilization_percent(self) -> float:
        """Session table utilization percentage."""
        if self.max_sessions == 0:
            return 0.0
        return (self.active_sessions / self.max_sessions) * 100
    
    @computed_field
    @property
    def is_critical(self) -> bool:
        """Check if session utilization is critical."""
        return self.utilization_percent >= self.critical_threshold_percent


class ThreatCategory(str, Enum):
    """Threat detection categories."""
    VIRUS = "virus"
    SPYWARE = "spyware"
    VULNERABILITY = "vulnerability"
    URL = "url"
    WILDFIRE = "wildfire"
    DOS = "dos"


class ThreatPreventionStatus(BaseModel):
    """Threat prevention feature status."""
    # Feature enablement
    antivirus_enabled: bool = Field(False, description="Antivirus enabled")
    anti_spyware_enabled: bool = Field(False, description="Anti-spyware enabled")
    vulnerability_protection_enabled: bool = Field(False, description="Vulnerability protection")
    url_filtering_enabled: bool = Field(False, description="URL filtering enabled")
    wildfire_enabled: bool = Field(False, description="WildFire enabled")
    dos_protection_enabled: bool = Field(False, description="DoS protection enabled")
    
    # Signature versions
    antivirus_version: Optional[str] = Field(None, description="AV signature version")
    threat_version: Optional[str] = Field(None, description="Threat signature version")
    app_version: Optional[str] = Field(None, description="App-ID version")
    wildfire_version: Optional[str] = Field(None, description="WildFire version")
    url_database_version: Optional[str] = Field(None, description="URL database version")
    
    # Last update times
    last_av_update: Optional[datetime] = Field(None)
    last_threat_update: Optional[datetime] = Field(None)
    last_app_update: Optional[datetime] = Field(None)
    last_wildfire_update: Optional[datetime] = Field(None)
    
    # Statistics (last 24 hours)
    threats_blocked_24h: int = Field(0, ge=0, description="Threats blocked in 24h")
    malware_blocked_24h: int = Field(0, ge=0)
    phishing_blocked_24h: int = Field(0, ge=0)
    
    model_config = {"extra": "forbid"}


class TunnelState(str, Enum):
    """VPN tunnel operational states."""
    UP = "up"
    DOWN = "down"
    INIT = "initializing"
    KEY_EXCHANGE = "key_exchange"
    ERROR = "error"


class VPNTunnelStatus(BaseModel):
    """VPN tunnel runtime status."""
    name: str = Field(..., description="Tunnel name")
    state: TunnelState = Field(TunnelState.DOWN, description="Tunnel state")
    
    # Endpoints
    local_address: Optional[str] = Field(None)
    remote_address: Optional[str] = Field(None)
    
    # Timing
    uptime_seconds: int = Field(0, ge=0, description="Tunnel uptime")
    established_at: Optional[datetime] = Field(None)
    last_rekey: Optional[datetime] = Field(None)
    
    # Counters
    bytes_in: int = Field(0, ge=0)
    bytes_out: int = Field(0, ge=0)
    packets_in: int = Field(0, ge=0)
    packets_out: int = Field(0, ge=0)
    
    # IKE/IPsec info
    ike_version: str = Field("IKEv2", description="IKE version")
    phase1_state: str = Field("unknown", description="IKE phase 1 state")
    phase2_state: str = Field("unknown", description="IPsec SA state")
    
    # Encryption
    encryption_algorithm: Optional[str] = Field(None)
    authentication_algorithm: Optional[str] = Field(None)
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def is_established(self) -> bool:
        """Check if tunnel is established."""
        return self.state == TunnelState.UP


class ServiceState(str, Enum):
    """System service states."""
    RUNNING = "running"
    STOPPED = "stopped"
    STARTING = "starting"
    STOPPING = "stopping"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ServiceStatus(BaseModel):
    """Individual system service status."""
    name: str = Field(..., description="Service name")
    state: ServiceState = Field(ServiceState.UNKNOWN, description="Service state")
    enabled: bool = Field(False, description="Service is enabled")
    pid: Optional[int] = Field(None, description="Process ID")
    uptime_seconds: int = Field(0, ge=0, description="Service uptime")
    last_restart: Optional[datetime] = Field(None)
    
    model_config = {"extra": "forbid"}


class DeviceRuntimeStatus(BaseModel):
    """
    Aggregate runtime status model.
    
    Contains all runtime state information from a firewall device.
    """
    device_name: str = Field(..., description="Device name")
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Core status
    system_health: SystemHealth = Field(default_factory=SystemHealth)
    ntp_status: NTPStatus = Field(default_factory=NTPStatus)
    ha_status: HAStatus = Field(default_factory=HAStatus)
    
    # Network status
    interfaces: List[InterfaceStatus] = Field(default_factory=list)
    vpn_tunnels: List[VPNTunnelStatus] = Field(default_factory=list)
    session_table: SessionTableStatus = Field(default_factory=SessionTableStatus)
    
    # Security status
    threat_prevention: ThreatPreventionStatus = Field(default_factory=ThreatPreventionStatus)
    
    # Licensing
    license_status: LicenseStatus = Field(
        default_factory=lambda: LicenseStatus(serial_number="unknown")
    )
    
    # Services
    services: List[ServiceStatus] = Field(default_factory=list)
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def operational_interfaces(self) -> int:
        """Count of operational interfaces."""
        return sum(1 for i in self.interfaces if i.is_operational)
    
    @computed_field
    @property
    def established_tunnels(self) -> int:
        """Count of established VPN tunnels."""
        return sum(1 for t in self.vpn_tunnels if t.is_established)
