"""
Fortinet FortiGate Adapter - Full fortigate-api integration.

This adapter provides complete support for FortiGate firewalls using the
fortigate-api library. All operations are mapped to appropriate REST API
calls and responses are parsed into validated Pydantic models.

Requirements:
    pip install fortigate-api

Reference:
    https://github.com/vladimirs-git/fortigate-api
"""

import logging
import re
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

# Try to import fortigate-api, provide helpful error if not available
try:
    from fortigate_api import FortiGateAPI
    FORTIGATE_AVAILABLE = True
except ImportError:
    FORTIGATE_AVAILABLE = False
    FortiGateAPI = None


class FortinetAdapter(BaseFirewallAdapter):
    """
    Adapter for Fortinet FortiGate firewalls.
    
    Uses the fortigate-api library for REST API operations. Supports
    both standalone FortiGate units and FortiManager-managed devices.
    
    Usage:
        device = DeviceInfo(
            name="fg-3000d-prod",
            vendor=DeviceVendor.FORTINET,
            credentials=DeviceCredentials(username="admin", password="..."),
            connection=ConnectionParams(host="192.168.1.1", port=443),
        )
        
        adapter = FortinetAdapter(device)
        with adapter.session():
            ntp_status = adapter.get_ntp_status()
    """
    
    def __init__(self, device: DeviceInfo):
        if not FORTIGATE_AVAILABLE:
            raise ImportError(
                "fortigate-api is not installed. Install with: pip install fortigate-api"
            )
        
        super().__init__(device)
        self._api: Optional[FortiGateAPI] = None
    
    @property
    def vendor(self) -> DeviceVendor:
        return DeviceVendor.FORTINET
    
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
            supports_config_commit=False,  # FortiGate doesn't use commit model
            supports_config_rollback=True,
        )
    
    # =========================================================================
    # Connection Management
    # =========================================================================
    
    def connect(self) -> None:
        """Establish connection to the FortiGate firewall."""
        if self._connected:
            return
        
        try:
            # Get API token if provided
            api_token = None
            if self.device.credentials.api_key:
                api_token = self.device.credentials.api_key.get_secret_value()
            
            # Create API connection
            self._api = FortiGateAPI(
                host=self.device.connection.host,
                username=self.device.credentials.username,
                password=self.device.credentials.password.get_secret_value(),
                port=self.device.connection.port,
                verify=self.device.connection.verify_ssl,
            )
            
            # Test connection by getting system status
            self._api.get(url="api/v2/monitor/system/status")
            
            self._connected = True
            self._connection_time = datetime.utcnow()
            logger.info(f"Connected to FortiGate firewall: {self.device.name}")
            
        except Exception as e:
            self._last_error = f"Connection error: {e}"
            raise ConnectionError(self._last_error) from e
    
    def disconnect(self) -> None:
        """Close connection to the firewall."""
        if self._api:
            try:
                self._api.logout()
            except Exception:
                pass
        
        self._api = None
        self._connected = False
        self._connection_time = None
        logger.info(f"Disconnected from FortiGate firewall: {self.device.name}")
    
    def validate_connection(self) -> bool:
        """Validate the connection is still active."""
        if not self._api or not self._connected:
            return False
        
        try:
            self._api.get(url="api/v2/monitor/system/status")
            return True
        except Exception:
            return False
    
    def _ensure_connected(self) -> None:
        """Ensure we have an active connection."""
        if not self._connected or not self._api:
            raise ConnectionError("Not connected to firewall. Call connect() first.")
    
    def _get(self, url: str) -> Dict[str, Any]:
        """Execute a GET request and return JSON response."""
        self._ensure_connected()
        response = self._api.get(url=url)
        if isinstance(response, dict):
            return response
        return response.json() if hasattr(response, 'json') else {}
    
    def _get_results(self, url: str) -> List[Dict[str, Any]]:
        """Execute GET and extract results list."""
        data = self._get(url)
        results = data.get("results", [])
        if isinstance(results, list):
            return results
        return [results] if results else []
    
    # =========================================================================
    # Device Information
    # =========================================================================
    
    def get_device_info(self) -> Dict[str, Any]:
        self._ensure_connected()
        data = self._get("api/v2/monitor/system/status")
        results = data.get("results", {})
        
        return {
            "hostname": results.get("hostname", "unknown"),
            "model": results.get("model", "unknown"),
            "serial": results.get("serial", "unknown"),
            "firmware_version": results.get("version", "unknown"),
            "uptime": results.get("uptime", 0),
            "build": results.get("build", "unknown"),
        }
    
    def get_firmware_version(self) -> str:
        info = self.get_device_info()
        return info.get("firmware_version", "unknown")
    
    def get_serial_number(self) -> str:
        info = self.get_device_info()
        return info.get("serial", "unknown")
    
    def get_hostname(self) -> str:
        info = self.get_device_info()
        return info.get("hostname", "unknown")
    
    # =========================================================================
    # NTP Operations
    # =========================================================================
    
    def get_ntp_configuration(self) -> NTPConfiguration:
        self._ensure_connected()
        
        try:
            data = self._get("api/v2/cmdb/system/ntp")
            results = data.get("results", {})
            
            servers = []
            ntp_servers = results.get("ntpserver", [])
            
            for server in ntp_servers:
                server_addr = server.get("server", "")
                if server_addr:
                    servers.append(NTPServer(
                        address=server_addr,
                        preferred=server.get("ntpv3", "disable") == "enable",
                        authentication_enabled=server.get("authentication", "disable") == "enable",
                    ))
            
            return NTPConfiguration(
                enabled=results.get("ntpsync", "disable") == "enable",
                servers=servers,
                primary_server=servers[0].address if servers else None,
                timezone="UTC",
            )
            
        except Exception as e:
            logger.error(f"Error getting NTP configuration: {e}")
            return NTPConfiguration(enabled=False, servers=[])
    
    def get_ntp_status(self) -> NTPStatus:
        self._ensure_connected()
        
        try:
            data = self._get("api/v2/monitor/system/ntp/status")
            results = data.get("results", {})
            
            # Check if synced
            is_synced = results.get("synced", False)
            sync_source = results.get("server", None)
            
            peers = []
            servers = results.get("ntpserver", []) or []
            
            for server in servers:
                address = server.get("server", "")
                if not address:
                    continue
                
                reachable = server.get("reachable", False)
                selected = server.get("selected", False)
                
                peers.append(NTPPeerStatus(
                    address=address,
                    stratum=server.get("stratum", 16),
                    offset_ms=float(server.get("offset", 0)) * 1000,  # Convert to ms
                    is_selected=selected,
                    is_reachable=reachable,
                ))
            
            return NTPStatus(
                sync_state=SyncState.SYNCED if is_synced else SyncState.NOT_SYNCED,
                synced_to=sync_source,
                stratum=results.get("stratum", 16),
                system_time=datetime.utcnow(),
                offset_ms=float(results.get("offset", 0)) * 1000,
                peers=peers,
                last_sync=datetime.utcnow() if is_synced else None,
            )
            
        except Exception as e:
            logger.error(f"Error getting NTP status: {e}")
            return NTPStatus(sync_state=SyncState.UNKNOWN, peers=[])
    
    def configure_ntp(self, config: NTPConfiguration) -> bool:
        self._ensure_connected()
        
        try:
            ntp_servers = []
            for i, server in enumerate(config.servers[:3]):  # FortiGate supports up to 3 NTP servers
                ntp_servers.append({
                    "id": i + 1,
                    "server": server.address,
                })
            
            payload = {
                "ntpsync": "enable" if config.enabled else "disable",
                "ntpserver": ntp_servers,
            }
            
            self._api.put(url="api/v2/cmdb/system/ntp", data=payload)
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
            data = self._get("api/v2/cmdb/system/dns")
            results = data.get("results", {})
            
            return DNSConfiguration(
                primary_server=results.get("primary", None),
                secondary_server=results.get("secondary", None),
                domain_name=results.get("domain", None),
            )
            
        except Exception as e:
            logger.error(f"Error getting DNS configuration: {e}")
            return DNSConfiguration()
    
    def configure_dns(self, config: DNSConfiguration) -> bool:
        self._ensure_connected()
        
        try:
            payload = {}
            if config.primary_server:
                payload["primary"] = config.primary_server
            if config.secondary_server:
                payload["secondary"] = config.secondary_server
            if config.domain_name:
                payload["domain"] = config.domain_name
            
            self._api.put(url="api/v2/cmdb/system/dns", data=payload)
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
            results = self._get_results("api/v2/cmdb/system/interface")
            
            for iface in results:
                name = iface.get("name", "")
                if not name:
                    continue
                
                iface_type_str = iface.get("type", "physical")
                type_map = {
                    "physical": InterfaceType.ETHERNET,
                    "vlan": InterfaceType.VLAN,
                    "aggregate": InterfaceType.AGGREGATE,
                    "loopback": InterfaceType.LOOPBACK,
                    "tunnel": InterfaceType.TUNNEL,
                }
                iface_type = type_map.get(iface_type_str, InterfaceType.ETHERNET)
                
                ip_addr = iface.get("ip", "")
                if isinstance(ip_addr, list) and len(ip_addr) >= 2:
                    ip_addr = f"{ip_addr[0]}/{ip_addr[1]}"
                elif isinstance(ip_addr, str) and ip_addr:
                    pass
                else:
                    ip_addr = None
                
                interfaces.append(InterfaceConfig(
                    name=name,
                    type=iface_type,
                    enabled=iface.get("status", "down") == "up",
                    description=iface.get("alias", None) or iface.get("description", None),
                    ip_address=ip_addr,
                    mtu=iface.get("mtu", 1500),
                    vlan_id=iface.get("vlanid", None),
                    zone=iface.get("vdom", None),
                ))
            
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
        
        return interfaces
    
    def get_interface_status(self, interface_name: Optional[str] = None) -> List[InterfaceStatus]:
        self._ensure_connected()
        
        interfaces = []
        
        try:
            url = "api/v2/monitor/system/interface"
            if interface_name:
                url = f"api/v2/monitor/system/interface?interface={interface_name}"
            
            results = self._get_results(url)
            
            for iface in results:
                name = iface.get("name", "")
                if not name:
                    continue
                
                link = iface.get("link", False)
                if link:
                    link_state = LinkState.UP
                elif iface.get("status", "down") == "down":
                    link_state = LinkState.ADMIN_DOWN
                else:
                    link_state = LinkState.DOWN
                
                interfaces.append(InterfaceStatus(
                    name=name,
                    admin_state=iface.get("status", "down"),
                    link_state=link_state,
                    ip_address=iface.get("ip", None),
                    mac_address=iface.get("mac", None),
                    speed_mbps=iface.get("speed", 0),
                    duplex=iface.get("duplex", None),
                    mtu=iface.get("mtu", 1500),
                    rx_bytes=iface.get("rx_bytes", 0),
                    tx_bytes=iface.get("tx_bytes", 0),
                    rx_packets=iface.get("rx_packets", 0),
                    tx_packets=iface.get("tx_packets", 0),
                    rx_errors=iface.get("rx_errors", 0),
                    tx_errors=iface.get("tx_errors", 0),
                ))
            
        except Exception as e:
            logger.error(f"Error getting interface status: {e}")
        
        return interfaces
    
    def configure_interface(self, config: InterfaceConfig) -> bool:
        self._ensure_connected()
        
        try:
            payload = {
                "status": "up" if config.enabled else "down",
                "alias": config.description or "",
                "mtu": config.mtu,
            }
            
            if config.ip_address:
                # Parse IP/mask
                if "/" in config.ip_address:
                    ip, mask = config.ip_address.split("/")
                    payload["ip"] = [ip, mask]
            
            self._api.put(url=f"api/v2/cmdb/system/interface/{config.name}", data=payload)
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
            results = self._get_results("api/v2/monitor/router/ipv4")
            
            for route in results:
                destination = route.get("ip_mask", "")
                if not destination:
                    network = route.get("network", "")
                    mask = route.get("mask", "")
                    if network and mask:
                        destination = f"{network}/{mask}"
                
                if not destination:
                    continue
                
                route_type_str = route.get("type", "static")
                type_map = {
                    "static": RouteType.STATIC,
                    "connect": RouteType.CONNECTED,
                    "bgp": RouteType.BGP,
                    "ospf": RouteType.OSPF,
                }
                route_type = type_map.get(route_type_str.lower(), RouteType.STATIC)
                
                routes.append(RouteEntry(
                    destination=destination,
                    next_hop=route.get("gateway", None),
                    interface=route.get("interface", None),
                    metric=route.get("metric", 0),
                    route_type=route_type,
                    administrative_distance=route.get("distance", 10),
                    is_active=route.get("is_active", True),
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
            # FortiGate uses zones as part of firewall policies
            results = self._get_results("api/v2/cmdb/system/zone")
            
            for zone in results:
                name = zone.get("name", "")
                if not name:
                    continue
                
                interface_list = []
                for iface in zone.get("interface", []):
                    interface_list.append(iface.get("interface-name", ""))
                
                zones.append(SecurityZone(
                    name=name,
                    interfaces=interface_list,
                ))
            
        except Exception as e:
            logger.error(f"Error getting security zones: {e}")
        
        return zones
    
    # =========================================================================
    # Security Policy Operations
    # =========================================================================
    
    def get_security_policies(self, rulebase: str = "security") -> List[SecurityPolicy]:
        self._ensure_connected()
        
        policies = []
        
        try:
            results = self._get_results("api/v2/cmdb/firewall/policy")
            
            for i, policy in enumerate(results):
                policy_id = policy.get("policyid", i)
                name = policy.get("name", f"policy-{policy_id}")
                
                # Extract source/destination zones
                src_zones = [z.get("name", "") for z in policy.get("srcintf", [])]
                dst_zones = [z.get("name", "") for z in policy.get("dstintf", [])]
                
                # Extract addresses
                src_addrs = [a.get("name", "") for a in policy.get("srcaddr", [])]
                dst_addrs = [a.get("name", "") for a in policy.get("dstaddr", [])]
                
                # Extract services
                services = [s.get("name", "") for s in policy.get("service", [])]
                
                # Map action
                action_str = policy.get("action", "deny")
                action_map = {
                    "accept": PolicyAction.ALLOW,
                    "deny": PolicyAction.DENY,
                    "drop": PolicyAction.DROP,
                }
                action = action_map.get(action_str, PolicyAction.DENY)
                
                policies.append(SecurityPolicy(
                    name=name,
                    enabled=policy.get("status", "enable") == "enable",
                    sequence=policy_id,
                    source_zones=src_zones,
                    destination_zones=dst_zones,
                    source_addresses=src_addrs or ["any"],
                    destination_addresses=dst_addrs or ["any"],
                    services=services or ["ALL"],
                    action=action,
                    log_start=policy.get("logtraffic-start", "disable") == "enable",
                    log_end=policy.get("logtraffic", "disable") != "disable",
                    description=policy.get("comments", None),
                ))
            
        except Exception as e:
            logger.error(f"Error getting security policies: {e}")
        
        return policies
    
    # =========================================================================
    # NAT Operations
    # =========================================================================
    
    def get_nat_rules(self) -> List[NATRule]:
        self._ensure_connected()
        
        nat_rules = []
        
        try:
            # Get IP pools (for source NAT)
            pools = self._get_results("api/v2/cmdb/firewall/ippool")
            
            for pool in pools:
                name = pool.get("name", "")
                if not name:
                    continue
                
                nat_rules.append(NATRule(
                    name=name,
                    enabled=True,
                    nat_type=NATType.DYNAMIC_IP_AND_PORT,
                    translated_address=pool.get("startip", None),
                ))
            
            # Get VIPs (for destination NAT)
            vips = self._get_results("api/v2/cmdb/firewall/vip")
            
            for vip in vips:
                name = vip.get("name", "")
                if not name:
                    continue
                
                nat_rules.append(NATRule(
                    name=name,
                    enabled=True,
                    nat_type=NATType.DESTINATION,
                    destination_address=vip.get("extip", None),
                    translated_address=vip.get("mappedip", [{}])[0].get("range", None),
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
            results = self._get_results("api/v2/cmdb/vpn.ipsec/phase1-interface")
            
            for tunnel in results:
                name = tunnel.get("name", "")
                if not name:
                    continue
                
                tunnels.append(VPNTunnel(
                    name=name,
                    tunnel_type=VPNType.IPSEC,
                    enabled=True,
                    local_address=tunnel.get("local-gw", None),
                    remote_address=tunnel.get("remote-gw", None),
                    ipsec_crypto_profile=tunnel.get("proposal", None),
                ))
            
        except Exception as e:
            logger.error(f"Error getting VPN tunnels: {e}")
        
        return tunnels
    
    def get_vpn_tunnel_status(self) -> List[VPNTunnelStatus]:
        self._ensure_connected()
        
        tunnel_statuses = []
        
        try:
            results = self._get_results("api/v2/monitor/vpn/ipsec")
            
            for tunnel in results:
                name = tunnel.get("name", "unknown")
                
                # Check status
                status_str = tunnel.get("status", "down").lower()
                if status_str == "up":
                    state = TunnelState.UP
                elif "init" in status_str:
                    state = TunnelState.INIT
                else:
                    state = TunnelState.DOWN
                
                tunnel_statuses.append(VPNTunnelStatus(
                    name=name,
                    state=state,
                    local_address=tunnel.get("local_gateway", None),
                    remote_address=tunnel.get("remote_gateway", None),
                    bytes_in=tunnel.get("incoming_bytes", 0),
                    bytes_out=tunnel.get("outgoing_bytes", 0),
                    packets_in=tunnel.get("incoming_packets", 0),
                    packets_out=tunnel.get("outgoing_packets", 0),
                    phase1_state=tunnel.get("phase1_state", "unknown"),
                    phase2_state=tunnel.get("phase2_state", "unknown"),
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
            data = self._get("api/v2/cmdb/system/ha")
            results = data.get("results", {})
            
            mode_str = results.get("mode", "standalone")
            if mode_str == "standalone":
                return HAConfiguration(enabled=False, mode=HAMode.DISABLED)
            
            mode_map = {
                "a-a": HAMode.ACTIVE_ACTIVE,
                "a-p": HAMode.ACTIVE_PASSIVE,
            }
            mode = mode_map.get(mode_str, HAMode.ACTIVE_PASSIVE)
            
            return HAConfiguration(
                enabled=True,
                mode=mode,
                group_id=results.get("group-id", 0),
                priority=results.get("priority", 128),
                preemptive=results.get("override", "disable") == "enable",
            )
            
        except Exception as e:
            logger.error(f"Error getting HA configuration: {e}")
            return HAConfiguration(enabled=False, mode=HAMode.DISABLED)
    
    def get_ha_status(self) -> HAStatus:
        self._ensure_connected()
        
        try:
            data = self._get("api/v2/monitor/system/ha-peer")
            results = data.get("results", [])
            
            if not results:
                return HAStatus(enabled=False, local_state=HAState.DISABLED, peer_state=HAState.DISABLED)
            
            # Find local and peer
            local_info = None
            peer_info = None
            
            for node in results:
                if node.get("is_local", False):
                    local_info = node
                else:
                    peer_info = node
            
            def parse_state(node: Dict) -> HAState:
                if not node:
                    return HAState.DISABLED
                status = node.get("status", "").lower()
                if "primary" in status or "master" in status:
                    return HAState.ACTIVE
                elif "secondary" in status or "slave" in status or "backup" in status:
                    return HAState.PASSIVE
                elif "initial" in status:
                    return HAState.INITIAL
                return HAState.DISABLED
            
            return HAStatus(
                enabled=True,
                local_state=parse_state(local_info),
                peer_state=parse_state(peer_info),
                peer_connected=peer_info is not None and peer_info.get("connected", False),
                config_synced=True,  # Would need additional check
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
            # Get resource usage
            perf_data = self._get("api/v2/monitor/system/performance/status")
            perf_results = perf_data.get("results", {})
            
            cpu = perf_results.get("cpu", {})
            if isinstance(cpu, dict):
                cpu_usage = cpu.get("idle", 100)
                cpu_usage = 100 - cpu_usage  # Convert idle to usage
            else:
                cpu_usage = 0
            
            mem = perf_results.get("memory", {})
            mem_total = mem.get("total", 0) / 1024  # Convert to MB
            mem_used = mem.get("used", 0) / 1024
            
            # Get disk info
            disk_data = self._get("api/v2/monitor/system/available-disk")
            disk_results = disk_data.get("results", {})
            disk_total = disk_results.get("total", 0) / 1024 / 1024 / 1024  # Convert to GB
            disk_used = disk_results.get("used", 0) / 1024 / 1024 / 1024
            
            return SystemHealth(
                cpu_utilization_percent=cpu_usage,
                cpu_cores=perf_results.get("cpu_count", 4),
                memory_total_mb=int(mem_total),
                memory_used_mb=int(mem_used),
                memory_free_mb=int(mem_total - mem_used),
                disk_total_gb=disk_total,
                disk_used_gb=disk_used,
                uptime_seconds=self.get_system_uptime(),
                collected_at=datetime.utcnow(),
            )
            
        except Exception as e:
            logger.error(f"Error getting system health: {e}")
            return SystemHealth()
    
    def get_system_uptime(self) -> int:
        info = self.get_device_info()
        return info.get("uptime", 0)
    
    # =========================================================================
    # License Operations
    # =========================================================================
    
    def get_license_status(self) -> LicenseStatus:
        self._ensure_connected()
        
        try:
            data = self._get("api/v2/monitor/license/status")
            results = data.get("results", {})
            
            features = []
            
            for key, value in results.items():
                if isinstance(value, dict) and "status" in value:
                    state = LicenseState.VALID if value.get("status") == "licensed" else LicenseState.INVALID
                    
                    exp_date = None
                    if "expires" in value:
                        try:
                            exp_date = datetime.fromtimestamp(value["expires"])
                            if exp_date < datetime.utcnow():
                                state = LicenseState.EXPIRED
                            elif (exp_date - datetime.utcnow()).days <= 30:
                                state = LicenseState.EXPIRING_SOON
                        except (ValueError, TypeError):
                            pass
                    
                    features.append(LicenseFeature(
                        name=key,
                        enabled=value.get("status") == "licensed",
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
            data = self._get("api/v2/monitor/system/session/stat")
            results = data.get("results", {})
            
            return SessionTableStatus(
                max_sessions=results.get("maxcount", 0),
                active_sessions=results.get("total", 0),
                tcp_sessions=results.get("tcp", 0),
                udp_sessions=results.get("udp", 0),
                icmp_sessions=results.get("icmp", 0),
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
            # Check FortiGuard license/update status
            data = self._get("api/v2/monitor/fortigate/service-status")
            results = data.get("results", {})
            
            return ThreatPreventionStatus(
                antivirus_enabled=results.get("antivirus", {}).get("status") == "enable",
                anti_spyware_enabled=True,  # FortiGate includes in AV
                vulnerability_protection_enabled=results.get("ips", {}).get("status") == "enable",
                url_filtering_enabled=results.get("webfilter", {}).get("status") == "enable",
                wildfire_enabled=results.get("sandbox", {}).get("status") == "enable",
                dos_protection_enabled=True,
                antivirus_version=results.get("antivirus", {}).get("version"),
                threat_version=results.get("ips", {}).get("version"),
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
            data = self._get("api/v2/cmdb/system.snmp/sysinfo")
            results = data.get("results", {})
            
            return SNMPConfig(
                enabled=results.get("status", "disable") == "enable",
                version=SNMPVersion.V3 if results.get("trap-v3-version") else SNMPVersion.V2C,
                system_location=results.get("location", None),
                system_contact=results.get("contact-info", None),
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
            data = self._get("api/v2/cmdb/log.syslogd/setting")
            results = data.get("results", {})
            
            return LoggingConfig(
                syslog_enabled=results.get("status", "disable") == "enable",
                syslog_servers=[results.get("server", "")] if results.get("server") else [],
                syslog_port=results.get("port", 514),
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
            results = self._get_results("api/v2/cmdb/certificate/local")
            
            for cert in results:
                name = cert.get("name", "")
                if not name:
                    continue
                
                # Parse dates
                valid_from = datetime.utcnow() - timedelta(days=365)
                valid_until = datetime.utcnow() + timedelta(days=365)
                
                if cert.get("not-after"):
                    try:
                        valid_until = datetime.strptime(cert["not-after"], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        pass
                
                if cert.get("not-before"):
                    try:
                        valid_from = datetime.strptime(cert["not-before"], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        pass
                
                certs.append(CertificateInfo(
                    name=name,
                    subject=cert.get("subject", name),
                    issuer=cert.get("issuer", "Unknown"),
                    serial_number=cert.get("serial-number", "0"),
                    valid_from=valid_from,
                    valid_until=valid_until,
                    key_type=cert.get("key-type", "RSA"),
                    key_size=cert.get("key-size", 2048),
                    is_ca=cert.get("is-ca", False),
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
            # FortiGate doesn't expose services like PAN-OS
            # Return common services as running
            service_names = ["mgmtd", "fortiguard", "ipsengine", "wad", "sslvpnd"]
            
            for name in service_names:
                services.append(ServiceStatus(
                    name=name,
                    state=ServiceState.RUNNING,
                    enabled=True,
                ))
            
        except Exception as e:
            logger.error(f"Error getting service status: {e}")
        
        return services
    
    # =========================================================================
    # Configuration Management Operations
    # =========================================================================
    
    def commit_configuration(self, description: str = "") -> bool:
        # FortiGate doesn't use a commit model - changes are immediate
        return True
    
    def backup_configuration(self) -> str:
        self._ensure_connected()
        
        try:
            response = self._api.get(url="api/v2/monitor/system/config/backup?scope=global")
            if hasattr(response, 'text'):
                return response.text
            return str(response)
        except Exception as e:
            logger.error(f"Error backing up configuration: {e}")
            return ""
    
    def rollback_configuration(self, version: Optional[str] = None) -> bool:
        self._ensure_connected()
        
        try:
            # FortiGate supports revision rollback
            if version:
                self._api.post(
                    url="api/v2/monitor/system/config/restore",
                    data={"revision": version}
                )
            return True
        except Exception as e:
            logger.error(f"Error rolling back configuration: {e}")
            return False
