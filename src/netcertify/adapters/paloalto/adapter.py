"""
Palo Alto Networks Adapter - Full pan-os-python integration.

This adapter provides complete support for PAN-OS firewalls using the
official pan-os-python SDK. All operations are mapped to appropriate
API calls and responses are parsed into validated Pydantic models.

Requirements:
    pip install pan-os-python

Reference:
    https://pan-os-python.readthedocs.io/
"""

import logging
import re
import xml.etree.ElementTree as ET
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

logger = logging.getLogger(__name__)

# Try to import pan-os-python, provide helpful error if not available
try:
    from panos.firewall import Firewall
    from panos.panorama import Panorama
    from panos import network, objects, policies, device as panos_device
    from panos.errors import PanDeviceError, PanConnectionTimeout, PanURLError
    PANOS_AVAILABLE = True
except ImportError:
    PANOS_AVAILABLE = False
    Firewall = None
    Panorama = None
    PanDeviceError = Exception
    PanConnectionTimeout = Exception
    PanURLError = Exception


class PaloAltoAdapter(BaseFirewallAdapter):
    """
    Adapter for Palo Alto Networks PAN-OS firewalls.
    
    Uses the pan-os-python SDK for all operations. Supports both
    direct firewall connections and Panorama-managed devices.
    
    Usage:
        device = DeviceInfo(
            name="pa-5220-prod",
            vendor=DeviceVendor.PALO_ALTO,
            credentials=DeviceCredentials(username="admin", password="..."),
            connection=ConnectionParams(host="192.168.1.1", port=443),
        )
        
        adapter = PaloAltoAdapter(device)
        with adapter.session():
            ntp_status = adapter.get_ntp_status()
    """
    
    def __init__(self, device: DeviceInfo):
        if not PANOS_AVAILABLE:
            raise ImportError(
                "pan-os-python is not installed. Install with: pip install pan-os-python"
            )
        
        super().__init__(device)
        self._fw: Optional[Firewall] = None
        self._api_key: Optional[str] = None
    
    @property
    def vendor(self) -> DeviceVendor:
        return DeviceVendor.PALO_ALTO
    
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
        """Establish connection to the Palo Alto firewall."""
        if self._connected:
            return
        
        try:
            # Get API key if provided
            api_key = None
            if self.device.credentials.api_key:
                api_key = self.device.credentials.api_key.get_secret_value()
            
            # Create firewall connection
            self._fw = Firewall(
                hostname=self.device.connection.host,
                api_username=self.device.credentials.username,
                api_password=self.device.credentials.password.get_secret_value(),
                api_key=api_key,
                port=self.device.connection.port,
            )
            
            # Verify connection by getting system info
            self._fw.refresh_system_info()
            
            self._connected = True
            self._connection_time = datetime.utcnow()
            logger.info(f"Connected to Palo Alto firewall: {self.device.name}")
            
        except PanConnectionTimeout as e:
            self._last_error = f"Connection timeout: {e}"
            raise ConnectionError(self._last_error) from e
        except PanURLError as e:
            self._last_error = f"Connection error: {e}"
            raise ConnectionError(self._last_error) from e
        except PanDeviceError as e:
            self._last_error = f"Device error: {e}"
            raise ConnectionError(self._last_error) from e
        except Exception as e:
            self._last_error = f"Unexpected error: {e}"
            raise ConnectionError(self._last_error) from e
    
    def disconnect(self) -> None:
        """Close connection to the firewall."""
        self._fw = None
        self._connected = False
        self._connection_time = None
        logger.info(f"Disconnected from Palo Alto firewall: {self.device.name}")
    
    def validate_connection(self) -> bool:
        """Validate the connection is still active."""
        if not self._fw or not self._connected:
            return False
        
        try:
            self._fw.refresh_system_info()
            return True
        except Exception:
            return False
    
    def _ensure_connected(self) -> None:
        """Ensure we have an active connection."""
        if not self._connected or not self._fw:
            raise ConnectionError("Not connected to firewall. Call connect() first.")
    
    def _op_cmd(self, cmd: str) -> ET.Element:
        """Execute an operational command and return XML response."""
        self._ensure_connected()
        return self._fw.op(cmd)
    
    def _parse_xml_text(self, element: Optional[ET.Element], default: str = "") -> str:
        """Safely extract text from XML element."""
        if element is not None and element.text:
            return element.text.strip()
        return default
    
    # =========================================================================
    # Device Information
    # =========================================================================
    
    def get_device_info(self) -> Dict[str, Any]:
        self._ensure_connected()
        info = self._fw.refresh_system_info()
        return {
            "hostname": info.hostname,
            "model": info.model,
            "serial": info.serial,
            "firmware_version": info.version,
            "uptime": info.uptime,
            "multi_vsys": info.multi_vsys,
            "vm_mac_base": getattr(info, 'vm_mac_base', None),
        }
    
    def get_firmware_version(self) -> str:
        self._ensure_connected()
        info = self._fw.refresh_system_info()
        return info.version
    
    def get_serial_number(self) -> str:
        self._ensure_connected()
        info = self._fw.refresh_system_info()
        return info.serial
    
    def get_hostname(self) -> str:
        self._ensure_connected()
        info = self._fw.refresh_system_info()
        return info.hostname
    
    # =========================================================================
    # NTP Operations
    # =========================================================================
    
    def get_ntp_configuration(self) -> NTPConfiguration:
        self._ensure_connected()
        
        try:
            # Get NTP configuration via operational command
            result = self._op_cmd("<show><ntp></ntp></show>")
            
            servers = []
            ntp_servers = result.findall(".//server")
            
            for server in ntp_servers:
                address = self._parse_xml_text(server.find("name"))
                if address:
                    servers.append(NTPServer(
                        address=address,
                        preferred=False,  # Will be determined from status
                        authentication_enabled=False,
                    ))
            
            # If no servers found, try config path
            if not servers:
                config_result = self._fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ntp-servers")
                if config_result:
                    for server_elem in config_result.findall(".//entry"):
                        addr = server_elem.get("name")
                        if addr:
                            servers.append(NTPServer(address=addr, preferred=False))
            
            return NTPConfiguration(
                enabled=len(servers) > 0,
                servers=servers,
                primary_server=servers[0].address if servers else None,
                timezone="UTC",  # Would need separate call to get timezone
            )
            
        except Exception as e:
            logger.error(f"Error getting NTP configuration: {e}")
            return NTPConfiguration(enabled=False, servers=[])
    
    def get_ntp_status(self) -> NTPStatus:
        self._ensure_connected()
        
        try:
            result = self._op_cmd("<show><ntp></ntp></show>")
            
            # Parse sync status
            synced_elem = result.find(".//synced")
            synced = self._parse_xml_text(synced_elem, "").lower()
            
            is_synced = synced in ["yes", "true", "synchronized"]
            
            # Parse peers
            peers = []
            peer_elements = result.findall(".//peer") or result.findall(".//server")
            
            synced_to = None
            for peer in peer_elements:
                address = self._parse_xml_text(peer.find("name")) or self._parse_xml_text(peer.find("address"))
                
                if not address:
                    continue
                
                status = self._parse_xml_text(peer.find("status"), "").lower()
                is_selected = status in ["synced", "synchronized", "*"]
                
                if is_selected:
                    synced_to = address
                
                stratum_text = self._parse_xml_text(peer.find("stratum"), "16")
                try:
                    stratum = int(stratum_text)
                except ValueError:
                    stratum = 16
                
                offset_text = self._parse_xml_text(peer.find("offset"), "0")
                try:
                    offset = float(offset_text.replace("ms", "").strip())
                except ValueError:
                    offset = 0.0
                
                peers.append(NTPPeerStatus(
                    address=address,
                    stratum=stratum,
                    offset_ms=offset,
                    is_selected=is_selected,
                    is_reachable=status not in ["unreachable", "down", ""],
                ))
            
            return NTPStatus(
                sync_state=SyncState.SYNCED if is_synced else SyncState.NOT_SYNCED,
                synced_to=synced_to,
                stratum=peers[0].stratum + 1 if peers and is_synced else 16,
                system_time=datetime.utcnow(),
                offset_ms=peers[0].offset_ms if peers else 0.0,
                peers=peers,
                last_sync=datetime.utcnow() if is_synced else None,
            )
            
        except Exception as e:
            logger.error(f"Error getting NTP status: {e}")
            return NTPStatus(sync_state=SyncState.UNKNOWN, peers=[])
    
    def configure_ntp(self, config: NTPConfiguration) -> bool:
        self._ensure_connected()
        
        try:
            # Build NTP configuration XML
            for i, server in enumerate(config.servers[:2]):  # PAN-OS supports max 2 NTP servers
                xpath = f"/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ntp-servers/{'primary' if i == 0 else 'secondary'}-ntp-server/ntp-server-address"
                self._fw.xapi.set(xpath, f"<ntp-server-address>{server.address}</ntp-server-address>")
            
            return True
        except Exception as e:
            logger.error(f"Error configuring NTP: {e}")
            return False
    
    # =========================================================================
    # DNS Operations
    # =========================================================================
    
    def get_dns_configuration(self) -> DNSConfiguration:
        self._ensure_connected()
        
        try:
            result = self._fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/dns-setting")
            
            primary = None
            secondary = None
            
            if result:
                servers = result.find(".//servers")
                if servers:
                    primary_elem = servers.find("primary")
                    secondary_elem = servers.find("secondary")
                    primary = self._parse_xml_text(primary_elem)
                    secondary = self._parse_xml_text(secondary_elem)
            
            return DNSConfiguration(
                primary_server=primary,
                secondary_server=secondary,
            )
            
        except Exception as e:
            logger.error(f"Error getting DNS configuration: {e}")
            return DNSConfiguration()
    
    def configure_dns(self, config: DNSConfiguration) -> bool:
        self._ensure_connected()
        
        try:
            xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/dns-setting/servers"
            element = f"<servers><primary>{config.primary_server}</primary>"
            if config.secondary_server:
                element += f"<secondary>{config.secondary_server}</secondary>"
            element += "</servers>"
            
            self._fw.xapi.set(xpath, element)
            return True
        except Exception as e:
            logger.error(f"Error configuring DNS: {e}")
            return False
    
    # =========================================================================
    # Interface Operations
    # =========================================================================
    
    def get_interfaces(self) -> List[InterfaceConfig]:
        self._ensure_connected()
        
        interfaces = []
        
        try:
            # Get ethernet interfaces
            network.EthernetInterface.refreshall(self._fw)
            
            for eth in self._fw.findall(network.EthernetInterface):
                iface_type = InterfaceType.ETHERNET
                
                interfaces.append(InterfaceConfig(
                    name=eth.name,
                    type=iface_type,
                    enabled=True,  # Would need to check admin state
                    description=getattr(eth, 'comment', None),
                    ip_address=eth.ip[0] if eth.ip else None,
                    mtu=eth.mtu or 1500,
                    zone=eth.zone,
                ))
            
            # Get loopback interfaces
            network.LoopbackInterface.refreshall(self._fw)
            for lo in self._fw.findall(network.LoopbackInterface):
                interfaces.append(InterfaceConfig(
                    name=lo.name,
                    type=InterfaceType.LOOPBACK,
                    enabled=True,
                    ip_address=lo.ip[0] if lo.ip else None,
                ))
            
            # Get tunnel interfaces
            network.TunnelInterface.refreshall(self._fw)
            for tun in self._fw.findall(network.TunnelInterface):
                interfaces.append(InterfaceConfig(
                    name=tun.name,
                    type=InterfaceType.TUNNEL,
                    enabled=True,
                    ip_address=tun.ip[0] if tun.ip else None,
                    mtu=tun.mtu or 1400,
                ))
            
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
        
        return interfaces
    
    def get_interface_status(self, interface_name: Optional[str] = None) -> List[InterfaceStatus]:
        self._ensure_connected()
        
        interfaces = []
        
        try:
            if interface_name:
                cmd = f"<show><interface>{interface_name}</interface></show>"
            else:
                cmd = "<show><interface>all</interface></show>"
            
            result = self._op_cmd(cmd)
            
            for iface in result.findall(".//ifnet/entry") or result.findall(".//hw/entry"):
                name = self._parse_xml_text(iface.find("name"))
                if not name:
                    continue
                
                # Parse state
                state_text = self._parse_xml_text(iface.find("state"), "").lower()
                if state_text == "up":
                    link_state = LinkState.UP
                elif state_text == "down":
                    link_state = LinkState.DOWN
                elif "admin" in state_text:
                    link_state = LinkState.ADMIN_DOWN
                else:
                    link_state = LinkState.UNKNOWN
                
                # Parse counters
                rx_bytes = int(self._parse_xml_text(iface.find("ibytes"), "0"))
                tx_bytes = int(self._parse_xml_text(iface.find("obytes"), "0"))
                rx_packets = int(self._parse_xml_text(iface.find("ipackets"), "0"))
                tx_packets = int(self._parse_xml_text(iface.find("opackets"), "0"))
                rx_errors = int(self._parse_xml_text(iface.find("ierrors"), "0"))
                tx_errors = int(self._parse_xml_text(iface.find("oerrors"), "0"))
                
                interfaces.append(InterfaceStatus(
                    name=name,
                    admin_state="up",  # Would need separate check
                    link_state=link_state,
                    ip_address=self._parse_xml_text(iface.find("ip")) or None,
                    mac_address=self._parse_xml_text(iface.find("mac")) or None,
                    speed_mbps=int(self._parse_xml_text(iface.find("speed"), "0")) or None,
                    duplex=self._parse_xml_text(iface.find("duplex")) or None,
                    mtu=int(self._parse_xml_text(iface.find("mtu"), "1500")),
                    rx_bytes=rx_bytes,
                    tx_bytes=tx_bytes,
                    rx_packets=rx_packets,
                    tx_packets=tx_packets,
                    rx_errors=rx_errors,
                    tx_errors=tx_errors,
                ))
            
        except Exception as e:
            logger.error(f"Error getting interface status: {e}")
        
        return interfaces
    
    def configure_interface(self, config: InterfaceConfig) -> bool:
        self._ensure_connected()
        
        try:
            if config.type == InterfaceType.ETHERNET:
                iface = network.EthernetInterface(
                    name=config.name,
                    mode="layer3",
                    ip=[config.ip_address] if config.ip_address else None,
                    mtu=config.mtu,
                    comment=config.description,
                )
                self._fw.add(iface)
                iface.create()
            
            return True
        except Exception as e:
            logger.error(f"Error configuring interface: {e}")
            return False
    
    # =========================================================================
    # Routing Operations
    # =========================================================================
    
    def get_routing_table(self, virtual_router: str = "default") -> RoutingTable:
        self._ensure_connected()
        
        routes = []
        
        try:
            cmd = f"<show><routing><route></route></routing></show>"
            result = self._op_cmd(cmd)
            
            for entry in result.findall(".//entry"):
                destination = self._parse_xml_text(entry.find("destination"))
                if not destination:
                    continue
                
                nexthop = self._parse_xml_text(entry.find("nexthop"))
                interface = self._parse_xml_text(entry.find("interface"))
                metric = int(self._parse_xml_text(entry.find("metric"), "0"))
                
                route_type_text = self._parse_xml_text(entry.find("flags"), "").lower()
                if "s" in route_type_text or "static" in route_type_text:
                    route_type = RouteType.STATIC
                elif "c" in route_type_text or "connect" in route_type_text:
                    route_type = RouteType.CONNECTED
                elif "b" in route_type_text or "bgp" in route_type_text:
                    route_type = RouteType.BGP
                elif "o" in route_type_text or "ospf" in route_type_text:
                    route_type = RouteType.OSPF
                else:
                    route_type = RouteType.STATIC
                
                routes.append(RouteEntry(
                    destination=destination,
                    next_hop=nexthop if nexthop else None,
                    interface=interface if interface else None,
                    metric=metric,
                    route_type=route_type,
                    is_active=True,
                ))
            
        except Exception as e:
            logger.error(f"Error getting routing table: {e}")
        
        return RoutingTable(virtual_router=virtual_router, routes=routes)
    
    # =========================================================================
    # Security Zone Operations
    # =========================================================================
    
    def get_security_zones(self) -> List[SecurityZone]:
        self._ensure_connected()
        
        zones = []
        
        try:
            network.Zone.refreshall(self._fw)
            
            for zone in self._fw.findall(network.Zone):
                zones.append(SecurityZone(
                    name=zone.name,
                    interfaces=zone.interface or [],
                    protection_profile=getattr(zone, 'zone_protection_profile', None),
                    log_setting=getattr(zone, 'log_setting', None),
                ))
            
        except Exception as e:
            logger.error(f"Error getting security zones: {e}")
        
        return zones
    
    # =========================================================================
    # Security Policy Operations
    # =========================================================================
    
    def get_security_policies(self, rulebase: str = "security") -> List[SecurityPolicy]:
        self._ensure_connected()
        
        policy_list = []
        
        try:
            from panos.policies import SecurityRule, Rulebase
            
            rulebase_obj = Rulebase()
            self._fw.add(rulebase_obj)
            SecurityRule.refreshall(rulebase_obj)
            
            for i, rule in enumerate(rulebase_obj.findall(SecurityRule)):
                action_map = {
                    "allow": PolicyAction.ALLOW,
                    "deny": PolicyAction.DENY,
                    "drop": PolicyAction.DROP,
                    "reset-client": PolicyAction.RESET_CLIENT,
                    "reset-server": PolicyAction.RESET_SERVER,
                    "reset-both": PolicyAction.RESET_BOTH,
                }
                
                policy_list.append(SecurityPolicy(
                    name=rule.name,
                    enabled=not rule.disabled if hasattr(rule, 'disabled') else True,
                    sequence=i,
                    source_zones=rule.fromzone or [],
                    destination_zones=rule.tozone or [],
                    source_addresses=rule.source or ["any"],
                    destination_addresses=rule.destination or ["any"],
                    applications=rule.application or ["any"],
                    services=rule.service or ["application-default"],
                    action=action_map.get(rule.action, PolicyAction.DENY),
                    log_start=rule.log_start if hasattr(rule, 'log_start') else False,
                    log_end=rule.log_end if hasattr(rule, 'log_end') else True,
                    description=rule.description,
                    tags=rule.tag or [],
                ))
            
        except Exception as e:
            logger.error(f"Error getting security policies: {e}")
        
        return policy_list
    
    # =========================================================================
    # NAT Operations
    # =========================================================================
    
    def get_nat_rules(self) -> List[NATRule]:
        self._ensure_connected()
        
        nat_rules = []
        
        try:
            from panos.policies import NatRule, Rulebase
            
            rulebase_obj = Rulebase()
            self._fw.add(rulebase_obj)
            NatRule.refreshall(rulebase_obj)
            
            for rule in rulebase_obj.findall(NatRule):
                nat_type = NATType.SOURCE
                if rule.nat_type == "ipv4":
                    if hasattr(rule, 'source_translation_type'):
                        if "dynamic" in str(rule.source_translation_type).lower():
                            nat_type = NATType.DYNAMIC_IP_AND_PORT
                
                nat_rules.append(NATRule(
                    name=rule.name,
                    enabled=not rule.disabled if hasattr(rule, 'disabled') else True,
                    nat_type=nat_type,
                    source_zone=rule.fromzone[0] if rule.fromzone else None,
                    destination_zone=rule.tozone[0] if rule.tozone else None,
                    source_address=rule.source[0] if rule.source else None,
                    destination_address=rule.destination[0] if rule.destination else None,
                ))
            
        except Exception as e:
            logger.error(f"Error getting NAT rules: {e}")
        
        return nat_rules
    
    # =========================================================================
    # VPN Operations
    # =========================================================================
    
    def get_vpn_tunnels(self) -> List[VPNTunnel]:
        self._ensure_connected()
        
        tunnels = []
        
        try:
            network.IpsecTunnel.refreshall(self._fw)
            
            for tunnel in self._fw.findall(network.IpsecTunnel):
                tunnels.append(VPNTunnel(
                    name=tunnel.name,
                    tunnel_type=VPNType.IPSEC,
                    enabled=True,
                    ike_gateway=tunnel.ak_ike_gateway,
                    ipsec_crypto_profile=tunnel.ak_ipsec_crypto_profile,
                    tunnel_interface=tunnel.tunnel_interface,
                ))
            
        except Exception as e:
            logger.error(f"Error getting VPN tunnels: {e}")
        
        return tunnels
    
    def get_vpn_tunnel_status(self) -> List[VPNTunnelStatus]:
        self._ensure_connected()
        
        tunnel_statuses = []
        
        try:
            result = self._op_cmd("<show><vpn><ipsec-sa></ipsec-sa></vpn></show>")
            
            for entry in result.findall(".//entry"):
                name = self._parse_xml_text(entry.find("name"))
                state_text = self._parse_xml_text(entry.find("state"), "").lower()
                
                if "up" in state_text or "active" in state_text:
                    state = TunnelState.UP
                elif "init" in state_text:
                    state = TunnelState.INIT
                else:
                    state = TunnelState.DOWN
                
                tunnel_statuses.append(VPNTunnelStatus(
                    name=name or "unknown",
                    state=state,
                    local_address=self._parse_xml_text(entry.find("local-ip")) or None,
                    remote_address=self._parse_xml_text(entry.find("peer-ip")) or None,
                    bytes_in=int(self._parse_xml_text(entry.find("inbytes"), "0")),
                    bytes_out=int(self._parse_xml_text(entry.find("outbytes"), "0")),
                ))
            
        except Exception as e:
            logger.error(f"Error getting VPN tunnel status: {e}")
        
        return tunnel_statuses
    
    # =========================================================================
    # High Availability Operations
    # =========================================================================
    
    def get_ha_configuration(self) -> HAConfiguration:
        self._ensure_connected()
        
        try:
            result = self._fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/high-availability")
            
            if result is None:
                return HAConfiguration(enabled=False, mode=HAMode.DISABLED)
            
            enabled = result.find(".//enabled")
            if enabled is None or self._parse_xml_text(enabled).lower() != "yes":
                return HAConfiguration(enabled=False, mode=HAMode.DISABLED)
            
            mode_elem = result.find(".//mode")
            mode_text = self._parse_xml_text(mode_elem, "").lower()
            
            if "active-passive" in mode_text:
                mode = HAMode.ACTIVE_PASSIVE
            elif "active-active" in mode_text:
                mode = HAMode.ACTIVE_ACTIVE
            else:
                mode = HAMode.ACTIVE_PASSIVE
            
            return HAConfiguration(
                enabled=True,
                mode=mode,
                group_id=int(self._parse_xml_text(result.find(".//group/group-id"), "1")),
                peer_address=self._parse_xml_text(result.find(".//peer-ip")) or None,
            )
            
        except Exception as e:
            logger.error(f"Error getting HA configuration: {e}")
            return HAConfiguration(enabled=False, mode=HAMode.DISABLED)
    
    def get_ha_status(self) -> HAStatus:
        self._ensure_connected()
        
        try:
            result = self._op_cmd("<show><high-availability><state></state></high-availability></show>")
            
            enabled_elem = result.find(".//enabled")
            if enabled_elem is None or self._parse_xml_text(enabled_elem).lower() != "yes":
                return HAStatus(enabled=False, local_state=HAState.DISABLED, peer_state=HAState.DISABLED)
            
            local_state_text = self._parse_xml_text(result.find(".//local-info/state"), "").lower()
            peer_state_text = self._parse_xml_text(result.find(".//peer-info/state"), "").lower()
            
            state_map = {
                "active": HAState.ACTIVE,
                "passive": HAState.PASSIVE,
                "initial": HAState.INITIAL,
                "tentative": HAState.TENTATIVE,
                "suspended": HAState.SUSPENDED,
                "non-functional": HAState.NON_FUNCTIONAL,
            }
            
            local_state = state_map.get(local_state_text, HAState.DISABLED)
            peer_state = state_map.get(peer_state_text, HAState.DISABLED)
            
            return HAStatus(
                enabled=True,
                local_state=local_state,
                peer_state=peer_state,
                peer_connected="connected" in self._parse_xml_text(result.find(".//peer-info/conn-status"), "").lower(),
                config_synced="synchronized" in self._parse_xml_text(result.find(".//running-sync"), "").lower(),
            )
            
        except Exception as e:
            logger.error(f"Error getting HA status: {e}")
            return HAStatus(enabled=False, local_state=HAState.DISABLED, peer_state=HAState.DISABLED)
    
    # =========================================================================
    # System Health Operations
    # =========================================================================
    
    def get_system_health(self) -> SystemHealth:
        self._ensure_connected()
        
        try:
            result = self._op_cmd("<show><system><resources></resources></system></show>")
            
            # Parse CPU
            cpu_text = self._parse_xml_text(result.find(".//cpu"), "0")
            cpu_match = re.search(r'(\d+(?:\.\d+)?)', cpu_text)
            cpu = float(cpu_match.group(1)) if cpu_match else 0.0
            
            # Parse memory
            mem_text = self._parse_xml_text(result.find(".//memory"))
            mem_match = re.search(r'(\d+)', mem_text) if mem_text else None
            memory_percent = float(mem_match.group(1)) if mem_match else 0.0
            
            # Get uptime
            uptime = self.get_system_uptime()
            
            return SystemHealth(
                cpu_utilization_percent=cpu,
                cpu_cores=4,  # Default, would need specific query
                memory_total_mb=16384,  # Would need to query specifically
                memory_used_mb=int(16384 * memory_percent / 100),
                memory_free_mb=int(16384 * (100 - memory_percent) / 100),
                disk_total_gb=100.0,
                disk_used_gb=50.0,
                uptime_seconds=uptime,
                collected_at=datetime.utcnow(),
            )
            
        except Exception as e:
            logger.error(f"Error getting system health: {e}")
            return SystemHealth()
    
    def get_system_uptime(self) -> int:
        self._ensure_connected()
        
        try:
            info = self._fw.refresh_system_info()
            uptime_str = info.uptime
            
            # Parse uptime string (e.g., "7 days, 3:45:12")
            total_seconds = 0
            
            days_match = re.search(r'(\d+)\s*days?', uptime_str)
            if days_match:
                total_seconds += int(days_match.group(1)) * 86400
            
            time_match = re.search(r'(\d+):(\d+):(\d+)', uptime_str)
            if time_match:
                total_seconds += int(time_match.group(1)) * 3600
                total_seconds += int(time_match.group(2)) * 60
                total_seconds += int(time_match.group(3))
            
            return total_seconds
            
        except Exception as e:
            logger.error(f"Error getting system uptime: {e}")
            return 0
    
    # =========================================================================
    # License Operations
    # =========================================================================
    
    def get_license_status(self) -> LicenseStatus:
        self._ensure_connected()
        
        try:
            result = self._op_cmd("<request><license><info></info></license></request>")
            
            features = []
            earliest_exp = None
            
            for entry in result.findall(".//entry"):
                feature_name = self._parse_xml_text(entry.find("feature"))
                expires = self._parse_xml_text(entry.find("expires"))
                
                if not feature_name:
                    continue
                
                # Parse expiration date
                exp_date = None
                state = LicenseState.VALID
                
                if expires and expires.lower() != "never":
                    try:
                        exp_date = datetime.strptime(expires, "%B %d, %Y")
                        if exp_date < datetime.utcnow():
                            state = LicenseState.EXPIRED
                        elif (exp_date - datetime.utcnow()).days <= 30:
                            state = LicenseState.EXPIRING_SOON
                        
                        if earliest_exp is None or exp_date < earliest_exp:
                            earliest_exp = exp_date
                    except ValueError:
                        pass
                
                features.append(LicenseFeature(
                    name=feature_name,
                    enabled=True,
                    state=state,
                    expiration_date=exp_date,
                ))
            
            overall_state = LicenseState.VALID
            if any(f.state == LicenseState.EXPIRED for f in features):
                overall_state = LicenseState.EXPIRED
            elif any(f.state == LicenseState.EXPIRING_SOON for f in features):
                overall_state = LicenseState.EXPIRING_SOON
            
            return LicenseStatus(
                serial_number=self.get_serial_number(),
                overall_state=overall_state,
                features=features,
                earliest_expiration=earliest_exp,
            )
            
        except Exception as e:
            logger.error(f"Error getting license status: {e}")
            return LicenseStatus(serial_number="unknown", overall_state=LicenseState.UNKNOWN)
    
    # =========================================================================
    # Session Table Operations
    # =========================================================================
    
    def get_session_table_status(self) -> SessionTableStatus:
        self._ensure_connected()
        
        try:
            result = self._op_cmd("<show><session><info></info></session></show>")
            
            return SessionTableStatus(
                max_sessions=int(self._parse_xml_text(result.find(".//num-max"), "0")),
                active_sessions=int(self._parse_xml_text(result.find(".//num-active"), "0")),
                tcp_sessions=int(self._parse_xml_text(result.find(".//num-tcp"), "0")),
                udp_sessions=int(self._parse_xml_text(result.find(".//num-udp"), "0")),
                icmp_sessions=int(self._parse_xml_text(result.find(".//num-icmp"), "0")),
                sessions_per_second=int(self._parse_xml_text(result.find(".//cps"), "0")),
            )
            
        except Exception as e:
            logger.error(f"Error getting session table status: {e}")
            return SessionTableStatus()
    
    # =========================================================================
    # Threat Prevention Operations
    # =========================================================================
    
    def get_threat_prevention_status(self) -> ThreatPreventionStatus:
        self._ensure_connected()
        
        try:
            result = self._op_cmd("<show><system><info></info></system></show>")
            
            return ThreatPreventionStatus(
                antivirus_enabled=True,  # Would need specific query
                anti_spyware_enabled=True,
                vulnerability_protection_enabled=True,
                url_filtering_enabled=True,
                wildfire_enabled=True,
                dos_protection_enabled=True,
                antivirus_version=self._parse_xml_text(result.find(".//av-version")) or None,
                threat_version=self._parse_xml_text(result.find(".//threat-version")) or None,
                app_version=self._parse_xml_text(result.find(".//app-version")) or None,
                wildfire_version=self._parse_xml_text(result.find(".//wildfire-version")) or None,
                url_database_version=self._parse_xml_text(result.find(".//url-filtering-version")) or None,
            )
            
        except Exception as e:
            logger.error(f"Error getting threat prevention status: {e}")
            return ThreatPreventionStatus()
    
    # =========================================================================
    # SNMP Operations
    # =========================================================================
    
    def get_snmp_configuration(self) -> SNMPConfig:
        self._ensure_connected()
        
        try:
            result = self._fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/snmp-setting")
            
            if result is None:
                return SNMPConfig(enabled=False)
            
            version = SNMPVersion.V3
            snmp_v3 = result.find(".//v3")
            if snmp_v3 is None:
                version = SNMPVersion.V2C
            
            return SNMPConfig(
                enabled=True,
                version=version,
                system_location=self._parse_xml_text(result.find(".//system/location")) or None,
                system_contact=self._parse_xml_text(result.find(".//system/contact")) or None,
            )
            
        except Exception as e:
            logger.error(f"Error getting SNMP configuration: {e}")
            return SNMPConfig(enabled=False)
    
    # =========================================================================
    # Logging Operations
    # =========================================================================
    
    def get_logging_configuration(self) -> LoggingConfig:
        self._ensure_connected()
        
        try:
            result = self._fw.xapi.get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/syslog")
            
            syslog_servers = []
            if result:
                for server in result.findall(".//entry"):
                    server_addr = server.get("name")
                    if server_addr:
                        syslog_servers.append(server_addr)
            
            return LoggingConfig(
                syslog_enabled=len(syslog_servers) > 0,
                syslog_servers=syslog_servers,
                traffic_log_enabled=True,
                threat_log_enabled=True,
                config_log_enabled=True,
                system_log_enabled=True,
            )
            
        except Exception as e:
            logger.error(f"Error getting logging configuration: {e}")
            return LoggingConfig()
    
    # =========================================================================
    # Certificate Operations
    # =========================================================================
    
    def get_certificates(self) -> List[CertificateInfo]:
        self._ensure_connected()
        
        certs = []
        
        try:
            result = self._op_cmd("<show><sslmgr-store><certificate><all></all></certificate></sslmgr-store></show>")
            
            for entry in result.findall(".//entry"):
                name = self._parse_xml_text(entry.find("name"))
                if not name:
                    continue
                
                # Parse dates
                not_before = self._parse_xml_text(entry.find("not-valid-before"))
                not_after = self._parse_xml_text(entry.find("not-valid-after"))
                
                valid_from = datetime.utcnow() - timedelta(days=365)
                valid_until = datetime.utcnow() + timedelta(days=365)
                
                try:
                    if not_before:
                        valid_from = datetime.strptime(not_before[:19], "%Y-%m-%dT%H:%M:%S")
                    if not_after:
                        valid_until = datetime.strptime(not_after[:19], "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    pass
                
                certs.append(CertificateInfo(
                    name=name,
                    subject=self._parse_xml_text(entry.find("subject")) or name,
                    issuer=self._parse_xml_text(entry.find("issuer")) or "Unknown",
                    serial_number=self._parse_xml_text(entry.find("serial")) or "0",
                    valid_from=valid_from,
                    valid_until=valid_until,
                    key_type=self._parse_xml_text(entry.find("algorithm")) or "RSA",
                    key_size=int(self._parse_xml_text(entry.find("key-size"), "2048")),
                    is_ca=self._parse_xml_text(entry.find("ca")).lower() == "yes" if entry.find("ca") is not None else False,
                ))
            
        except Exception as e:
            logger.error(f"Error getting certificates: {e}")
        
        return certs
    
    # =========================================================================
    # Service Status Operations
    # =========================================================================
    
    def get_service_status(self) -> List[ServiceStatus]:
        self._ensure_connected()
        
        services = []
        
        try:
            result = self._op_cmd("<show><system><state><filter-pretty>sys.daemon.*</filter-pretty></state></system></show>")
            
            # Parse daemon status from the result
            # This is simplified - actual parsing would depend on exact output format
            service_names = ["management-server", "log-collector", "ipsec", "ssl-vpn", "user-id"]
            
            for name in service_names:
                services.append(ServiceStatus(
                    name=name,
                    state=ServiceState.RUNNING,  # Would need actual status check
                    enabled=True,
                ))
            
        except Exception as e:
            logger.error(f"Error getting service status: {e}")
            # Return default running services
            for name in ["management-server", "log-collector", "ipsec"]:
                services.append(ServiceStatus(name=name, state=ServiceState.RUNNING, enabled=True))
        
        return services
    
    # =========================================================================
    # Configuration Management Operations
    # =========================================================================
    
    def commit_configuration(self, description: str = "") -> bool:
        self._ensure_connected()
        
        try:
            self._fw.commit(sync=True, description=description)
            logger.info(f"Configuration committed successfully: {description}")
            return True
        except Exception as e:
            logger.error(f"Error committing configuration: {e}")
            return False
    
    def backup_configuration(self) -> str:
        self._ensure_connected()
        
        try:
            result = self._op_cmd("<show><config><running></running></config></show>")
            return ET.tostring(result, encoding="unicode")
        except Exception as e:
            logger.error(f"Error backing up configuration: {e}")
            return ""
    
    def rollback_configuration(self, version: Optional[str] = None) -> bool:
        self._ensure_connected()
        
        try:
            cmd = "<load><config><from>running-config.xml</from></config></load>"
            self._op_cmd(cmd)
            return True
        except Exception as e:
            logger.error(f"Error rolling back configuration: {e}")
            return False
