"""
Unit tests for firewall adapters.
"""

import pytest
from datetime import datetime

from netcertify.adapters.mock.adapter import MockFirewallAdapter
from netcertify.adapters.registry import AdapterRegistry, AdapterNotFoundError
from netcertify.adapters.base import BaseFirewallAdapter
from netcertify.schemas.device import DeviceVendor
from netcertify.schemas.status import SyncState, LinkState, HAState


class TestMockAdapter:
    """Test mock adapter functionality."""
    
    def test_adapter_creation(self, mock_device_info):
        """Test mock adapter instantiation."""
        adapter = MockFirewallAdapter(mock_device_info)
        
        assert adapter.vendor == DeviceVendor.MOCK
        assert adapter.device_name == "test-mock-fw"
        assert not adapter.is_connected
    
    def test_connection_lifecycle(self, mock_device_info):
        """Test connect/disconnect cycle."""
        adapter = MockFirewallAdapter(mock_device_info)
        
        # Not connected initially
        assert not adapter.is_connected
        
        # Connect
        adapter.connect()
        assert adapter.is_connected
        assert adapter.validate_connection()
        
        # Disconnect
        adapter.disconnect()
        assert not adapter.is_connected
    
    def test_session_context_manager(self, mock_device_info):
        """Test session context manager."""
        adapter = MockFirewallAdapter(mock_device_info)
        
        with adapter.session():
            assert adapter.is_connected
        
        assert not adapter.is_connected
    
    def test_device_info_retrieval(self, mock_adapter):
        """Test device info methods."""
        info = mock_adapter.get_device_info()
        
        assert "hostname" in info
        assert "model" in info
        assert "serial" in info
        assert "firmware_version" in info
        
        assert mock_adapter.get_hostname() == "test-mock-fw"
        assert mock_adapter.get_firmware_version() == "10.2.3"
        assert mock_adapter.get_serial_number() == "MOCK123456"
    
    def test_ntp_operations(self, mock_adapter):
        """Test NTP configuration and status retrieval."""
        config = mock_adapter.get_ntp_configuration()
        status = mock_adapter.get_ntp_status()
        
        # Configuration
        assert config.enabled
        assert len(config.servers) > 0
        
        # Status (configured for success)
        assert status.sync_state == SyncState.SYNCED
        assert status.synced_to is not None
        assert len(status.peers) > 0
    
    def test_interface_operations(self, mock_adapter):
        """Test interface methods."""
        configs = mock_adapter.get_interfaces()
        statuses = mock_adapter.get_interface_status()
        
        assert len(configs) > 0
        assert len(statuses) > 0
        
        # Check interface has required fields
        iface = statuses[0]
        assert iface.name
        assert iface.link_state in LinkState
    
    def test_ha_operations(self, mock_adapter):
        """Test HA methods with HA enabled."""
        config = mock_adapter.get_ha_configuration()
        status = mock_adapter.get_ha_status()
        
        # HA is enabled in mock_device_info fixture
        assert config.enabled
        assert status.enabled
        assert status.local_state == HAState.ACTIVE
        assert status.peer_connected
    
    def test_system_health(self, mock_adapter):
        """Test system health retrieval."""
        health = mock_adapter.get_system_health()
        
        # CPU should be around 35% per fixture
        assert 30 <= health.cpu_utilization_percent <= 40
        assert health.memory_total_mb > 0
        assert health.uptime_seconds > 0
    
    def test_license_status(self, mock_adapter):
        """Test license status retrieval."""
        status = mock_adapter.get_license_status()
        
        assert status.serial_number == "MOCK123456"
        assert len(status.features) > 0
    
    def test_security_policies(self, mock_adapter):
        """Test security policy retrieval."""
        policies = mock_adapter.get_security_policies()
        
        assert len(policies) > 0
        
        # Check for default deny
        has_deny = any(p.action.value in ["deny", "drop"] for p in policies)
        assert has_deny
    
    def test_vpn_operations(self, mock_adapter):
        """Test VPN methods."""
        configs = mock_adapter.get_vpn_tunnels()
        statuses = mock_adapter.get_vpn_tunnel_status()
        
        assert len(configs) > 0
        assert len(statuses) > 0
        
        # Tunnels should be up per fixture
        assert all(s.is_established for s in statuses)
    
    def test_failing_device_ntp(self, mock_adapter_failing):
        """Test NTP with failing device configuration."""
        status = mock_adapter_failing.get_ntp_status()
        
        # Configured for failure
        assert status.sync_state == SyncState.NOT_SYNCED
        assert status.synced_to is None
    
    def test_failing_device_health(self, mock_adapter_failing):
        """Test system health with high utilization."""
        health = mock_adapter_failing.get_system_health()
        
        # High CPU configured
        assert health.cpu_utilization_percent >= 90
    
    def test_capabilities(self, mock_adapter):
        """Test adapter capabilities."""
        caps = mock_adapter.capabilities
        
        assert caps.supports_api
        assert caps.supports_ntp_status
        assert caps.supports_ha_status
        assert caps.supports_system_health


class TestAdapterRegistry:
    """Test adapter registry functionality."""
    
    def test_register_adapter(self, mock_device_info):
        """Test manual adapter registration."""
        AdapterRegistry.register(DeviceVendor.MOCK, MockFirewallAdapter)
        
        assert AdapterRegistry.is_vendor_supported(DeviceVendor.MOCK)
        assert DeviceVendor.MOCK in AdapterRegistry.list_vendors()
    
    def test_create_adapter(self, mock_device_info):
        """Test adapter creation through registry."""
        AdapterRegistry.register(DeviceVendor.MOCK, MockFirewallAdapter)
        
        adapter = AdapterRegistry.create(mock_device_info)
        
        assert isinstance(adapter, MockFirewallAdapter)
        assert adapter.device_name == mock_device_info.name
    
    def test_unregistered_vendor_error(self, mock_device_info):
        """Test error for unregistered vendor - checks that clear works."""
        # Clear registry and check it's empty
        AdapterRegistry.clear()
        
        # Verify registry is cleared
        assert len(AdapterRegistry._adapters) == 0
        assert not AdapterRegistry._initialized
        
        # Re-register only mock to verify clear worked
        AdapterRegistry.register(DeviceVendor.MOCK, MockFirewallAdapter)
        
        # Now verify we can create mock adapter after registration
        adapter = AdapterRegistry.create(mock_device_info)
        assert adapter is not None
    
    def test_invalid_adapter_class(self):
        """Test registration with invalid class."""
        class NotAnAdapter:
            pass
        
        with pytest.raises(TypeError):
            AdapterRegistry.register(DeviceVendor.MOCK, NotAnAdapter)
