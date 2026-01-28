"""
Base Adapter - Abstract base class for vendor-specific firewall adapters.

All vendor adapters must implement this interface to ensure consistency
across the certification framework.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from datetime import datetime
from pydantic import BaseModel, Field

from netcertify.schemas.device import DeviceInfo, DeviceVendor
from netcertify.schemas.configuration import (
    NTPConfiguration,
    DNSConfiguration,
    InterfaceConfig,
    RoutingTable,
    SecurityZone,
    SecurityPolicy,
    NATRule,
    VPNTunnel,
    SNMPConfig,
    LoggingConfig,
    CertificateInfo,
    HAConfiguration,
    SystemConfiguration,
)
from netcertify.schemas.status import (
    NTPStatus,
    InterfaceStatus,
    HAStatus,
    SystemHealth,
    LicenseStatus,
    SessionTableStatus,
    ThreatPreventionStatus,
    VPNTunnelStatus,
    ServiceStatus,
    DeviceRuntimeStatus,
)


class AdapterCapabilities(BaseModel):
    """
    Declares what features an adapter supports.
    
    Used to skip tests for features not supported by a particular vendor/adapter.
    """
    # Connection
    supports_api: bool = Field(True, description="REST/XML API support")
    supports_ssh: bool = Field(True, description="SSH CLI support")
    
    # NTP
    supports_ntp_config: bool = Field(True)
    supports_ntp_status: bool = Field(True)
    
    # DNS
    supports_dns_config: bool = Field(True)
    
    # Interfaces
    supports_interface_config: bool = Field(True)
    supports_interface_status: bool = Field(True)
    
    # Routing
    supports_routing_config: bool = Field(True)
    supports_routing_status: bool = Field(True)
    
    # Security
    supports_security_zones: bool = Field(True)
    supports_security_policies: bool = Field(True)
    supports_nat: bool = Field(True)
    
    # VPN
    supports_vpn_config: bool = Field(True)
    supports_vpn_status: bool = Field(True)
    
    # HA
    supports_ha_config: bool = Field(True)
    supports_ha_status: bool = Field(True)
    
    # Management
    supports_snmp: bool = Field(True)
    supports_logging: bool = Field(True)
    supports_certificates: bool = Field(True)
    
    # System
    supports_system_health: bool = Field(True)
    supports_license_status: bool = Field(True)
    supports_session_table: bool = Field(True)
    supports_threat_prevention: bool = Field(True)
    supports_firmware_info: bool = Field(True)
    
    # Operations
    supports_config_backup: bool = Field(True)
    supports_config_commit: bool = Field(True)
    supports_config_rollback: bool = Field(True)
    
    model_config = {"extra": "forbid"}


class BaseFirewallAdapter(ABC):
    """
    Abstract base class for all firewall vendor adapters.
    
    Provides a unified interface for interacting with different firewall vendors.
    All certification tests operate through this interface, ensuring vendor-agnostic
    test logic.
    
    Usage:
        adapter = PaloAltoAdapter(device_info)
        with adapter.connect():
            ntp_status = adapter.get_ntp_status()
            health = adapter.get_system_health()
    """
    
    def __init__(self, device: DeviceInfo):
        """
        Initialize the adapter with device information.
        
        Args:
            device: Complete device information including credentials and connection params
        """
        self.device = device
        self._connected = False
        self._connection_time: Optional[datetime] = None
        self._last_error: Optional[str] = None
    
    @property
    @abstractmethod
    def vendor(self) -> DeviceVendor:
        """Return the vendor type this adapter supports."""
        pass
    
    @property
    @abstractmethod
    def capabilities(self) -> AdapterCapabilities:
        """Return the capabilities supported by this adapter."""
        pass
    
    @property
    def is_connected(self) -> bool:
        """Check if adapter is currently connected to the device."""
        return self._connected
    
    @property
    def device_name(self) -> str:
        """Get the device name."""
        return self.device.name
    
    # =========================================================================
    # Connection Management
    # =========================================================================
    
    @abstractmethod
    def connect(self) -> None:
        """
        Establish connection to the firewall device.
        
        Raises:
            ConnectionError: If connection fails
            AuthenticationError: If authentication fails
        """
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """
        Close connection to the firewall device.
        
        Should be idempotent - safe to call multiple times.
        """
        pass
    
    @contextmanager
    def session(self):
        """
        Context manager for automatic connection handling.
        
        Usage:
            with adapter.session():
                # perform operations
                status = adapter.get_ntp_status()
        """
        try:
            self.connect()
            yield self
        finally:
            self.disconnect()
    
    @abstractmethod
    def validate_connection(self) -> bool:
        """
        Validate that the connection is still active.
        
        Returns:
            True if connection is valid, False otherwise
        """
        pass
    
    # =========================================================================
    # Device Information
    # =========================================================================
    
    @abstractmethod
    def get_device_info(self) -> Dict[str, Any]:
        """
        Retrieve basic device information.
        
        Returns:
            Dictionary with hostname, model, serial, firmware version, etc.
        """
        pass
    
    @abstractmethod
    def get_firmware_version(self) -> str:
        """
        Get the current firmware/software version.
        
        Returns:
            Version string (e.g., "10.2.3")
        """
        pass
    
    @abstractmethod
    def get_serial_number(self) -> str:
        """
        Get the device serial number.
        
        Returns:
            Serial number string
        """
        pass
    
    @abstractmethod
    def get_hostname(self) -> str:
        """
        Get the device hostname.
        
        Returns:
            Hostname string
        """
        pass
    
    # =========================================================================
    # NTP Operations
    # =========================================================================
    
    @abstractmethod
    def get_ntp_configuration(self) -> NTPConfiguration:
        """
        Retrieve the current NTP configuration.
        
        Returns:
            NTPConfiguration model with servers and settings
        """
        pass
    
    @abstractmethod
    def get_ntp_status(self) -> NTPStatus:
        """
        Retrieve the current NTP synchronization status.
        
        Returns:
            NTPStatus model with sync state and peer information
        """
        pass
    
    @abstractmethod
    def configure_ntp(self, config: NTPConfiguration) -> bool:
        """
        Apply NTP configuration to the device.
        
        Args:
            config: NTPConfiguration to apply
            
        Returns:
            True if configuration was successful
        """
        pass
    
    # =========================================================================
    # DNS Operations
    # =========================================================================
    
    @abstractmethod
    def get_dns_configuration(self) -> DNSConfiguration:
        """
        Retrieve the current DNS configuration.
        
        Returns:
            DNSConfiguration model
        """
        pass
    
    @abstractmethod
    def configure_dns(self, config: DNSConfiguration) -> bool:
        """
        Apply DNS configuration to the device.
        
        Args:
            config: DNSConfiguration to apply
            
        Returns:
            True if configuration was successful
        """
        pass
    
    # =========================================================================
    # Interface Operations
    # =========================================================================
    
    @abstractmethod
    def get_interfaces(self) -> List[InterfaceConfig]:
        """
        Retrieve all interface configurations.
        
        Returns:
            List of InterfaceConfig models
        """
        pass
    
    @abstractmethod
    def get_interface_status(self, interface_name: Optional[str] = None) -> List[InterfaceStatus]:
        """
        Retrieve interface runtime status.
        
        Args:
            interface_name: Optional specific interface, or all if None
            
        Returns:
            List of InterfaceStatus models
        """
        pass
    
    @abstractmethod
    def configure_interface(self, config: InterfaceConfig) -> bool:
        """
        Configure a network interface.
        
        Args:
            config: InterfaceConfig to apply
            
        Returns:
            True if configuration was successful
        """
        pass
    
    # =========================================================================
    # Routing Operations
    # =========================================================================
    
    @abstractmethod
    def get_routing_table(self, virtual_router: str = "default") -> RoutingTable:
        """
        Retrieve the routing table.
        
        Args:
            virtual_router: Virtual router name
            
        Returns:
            RoutingTable model
        """
        pass
    
    # =========================================================================
    # Security Zone Operations
    # =========================================================================
    
    @abstractmethod
    def get_security_zones(self) -> List[SecurityZone]:
        """
        Retrieve all security zone configurations.
        
        Returns:
            List of SecurityZone models
        """
        pass
    
    # =========================================================================
    # Security Policy Operations
    # =========================================================================
    
    @abstractmethod
    def get_security_policies(self, rulebase: str = "security") -> List[SecurityPolicy]:
        """
        Retrieve security policies.
        
        Args:
            rulebase: Rulebase name (default: "security")
            
        Returns:
            List of SecurityPolicy models
        """
        pass
    
    # =========================================================================
    # NAT Operations
    # =========================================================================
    
    @abstractmethod
    def get_nat_rules(self) -> List[NATRule]:
        """
        Retrieve NAT rules.
        
        Returns:
            List of NATRule models
        """
        pass
    
    # =========================================================================
    # VPN Operations
    # =========================================================================
    
    @abstractmethod
    def get_vpn_tunnels(self) -> List[VPNTunnel]:
        """
        Retrieve VPN tunnel configurations.
        
        Returns:
            List of VPNTunnel models
        """
        pass
    
    @abstractmethod
    def get_vpn_tunnel_status(self) -> List[VPNTunnelStatus]:
        """
        Retrieve VPN tunnel runtime status.
        
        Returns:
            List of VPNTunnelStatus models
        """
        pass
    
    # =========================================================================
    # High Availability Operations
    # =========================================================================
    
    @abstractmethod
    def get_ha_configuration(self) -> HAConfiguration:
        """
        Retrieve HA configuration.
        
        Returns:
            HAConfiguration model
        """
        pass
    
    @abstractmethod
    def get_ha_status(self) -> HAStatus:
        """
        Retrieve HA runtime status.
        
        Returns:
            HAStatus model
        """
        pass
    
    # =========================================================================
    # System Health Operations
    # =========================================================================
    
    @abstractmethod
    def get_system_health(self) -> SystemHealth:
        """
        Retrieve system health metrics.
        
        Returns:
            SystemHealth model with CPU, memory, disk, etc.
        """
        pass
    
    @abstractmethod
    def get_system_uptime(self) -> int:
        """
        Get system uptime in seconds.
        
        Returns:
            Uptime in seconds
        """
        pass
    
    # =========================================================================
    # License Operations
    # =========================================================================
    
    @abstractmethod
    def get_license_status(self) -> LicenseStatus:
        """
        Retrieve license information.
        
        Returns:
            LicenseStatus model
        """
        pass
    
    # =========================================================================
    # Session Table Operations
    # =========================================================================
    
    @abstractmethod
    def get_session_table_status(self) -> SessionTableStatus:
        """
        Retrieve session table statistics.
        
        Returns:
            SessionTableStatus model
        """
        pass
    
    # =========================================================================
    # Threat Prevention Operations
    # =========================================================================
    
    @abstractmethod
    def get_threat_prevention_status(self) -> ThreatPreventionStatus:
        """
        Retrieve threat prevention feature status.
        
        Returns:
            ThreatPreventionStatus model
        """
        pass
    
    # =========================================================================
    # SNMP Operations
    # =========================================================================
    
    @abstractmethod
    def get_snmp_configuration(self) -> SNMPConfig:
        """
        Retrieve SNMP configuration.
        
        Returns:
            SNMPConfig model
        """
        pass
    
    # =========================================================================
    # Logging Operations
    # =========================================================================
    
    @abstractmethod
    def get_logging_configuration(self) -> LoggingConfig:
        """
        Retrieve logging configuration.
        
        Returns:
            LoggingConfig model
        """
        pass
    
    # =========================================================================
    # Certificate Operations
    # =========================================================================
    
    @abstractmethod
    def get_certificates(self) -> List[CertificateInfo]:
        """
        Retrieve certificate information.
        
        Returns:
            List of CertificateInfo models
        """
        pass
    
    # =========================================================================
    # Service Status Operations
    # =========================================================================
    
    @abstractmethod
    def get_service_status(self) -> List[ServiceStatus]:
        """
        Retrieve system service statuses.
        
        Returns:
            List of ServiceStatus models
        """
        pass
    
    # =========================================================================
    # Configuration Management Operations
    # =========================================================================
    
    @abstractmethod
    def commit_configuration(self, description: str = "") -> bool:
        """
        Commit pending configuration changes.
        
        Args:
            description: Optional commit description
            
        Returns:
            True if commit was successful
        """
        pass
    
    @abstractmethod
    def backup_configuration(self) -> str:
        """
        Create a backup of the current configuration.
        
        Returns:
            Configuration backup as string (XML, JSON, or text)
        """
        pass
    
    @abstractmethod
    def rollback_configuration(self, version: Optional[str] = None) -> bool:
        """
        Rollback to a previous configuration.
        
        Args:
            version: Optional version/snapshot to rollback to
            
        Returns:
            True if rollback was successful
        """
        pass
    
    # =========================================================================
    # Aggregate Operations
    # =========================================================================
    
    def get_full_configuration(self) -> SystemConfiguration:
        """
        Retrieve the complete system configuration.
        
        This method aggregates all configuration data into a single model.
        
        Returns:
            SystemConfiguration model
        """
        return SystemConfiguration(
            hostname=self.get_hostname(),
            ntp=self.get_ntp_configuration(),
            dns=self.get_dns_configuration(),
            interfaces=self.get_interfaces(),
            zones=self.get_security_zones(),
            routing=self.get_routing_table(),
            policies=self.get_security_policies(),
            nat_rules=self.get_nat_rules(),
            vpn_tunnels=self.get_vpn_tunnels(),
            snmp=self.get_snmp_configuration(),
            logging=self.get_logging_configuration(),
            certificates=self.get_certificates(),
            ha=self.get_ha_configuration(),
        )
    
    def get_runtime_status(self) -> DeviceRuntimeStatus:
        """
        Retrieve complete runtime status.
        
        This method aggregates all status data into a single model.
        
        Returns:
            DeviceRuntimeStatus model
        """
        return DeviceRuntimeStatus(
            device_name=self.device_name,
            system_health=self.get_system_health(),
            ntp_status=self.get_ntp_status(),
            ha_status=self.get_ha_status(),
            interfaces=self.get_interface_status(),
            vpn_tunnels=self.get_vpn_tunnel_status(),
            session_table=self.get_session_table_status(),
            threat_prevention=self.get_threat_prevention_status(),
            license_status=self.get_license_status(),
            services=self.get_service_status(),
        )
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(device={self.device_name}, connected={self._connected})"
    
    def __str__(self) -> str:
        return f"{self.vendor.value} adapter for {self.device_name}"
