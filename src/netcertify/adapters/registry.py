"""
Adapter Registry - Factory for creating vendor-specific adapters.

Provides a centralized registry for adapter types and factory methods
for instantiating adapters based on device configuration.
"""

from typing import Dict, Type, Optional
import logging

from netcertify.schemas.device import DeviceInfo, DeviceVendor
from netcertify.adapters.base import BaseFirewallAdapter

logger = logging.getLogger(__name__)


class AdapterNotFoundError(Exception):
    """Raised when no adapter is registered for a vendor."""
    pass


class AdapterRegistry:
    """
    Central registry for firewall adapters.
    
    Manages the mapping between vendors and their adapter implementations.
    New vendors can be added by registering their adapter class.
    
    Usage:
        # Register adapters (typically done at startup)
        AdapterRegistry.register(DeviceVendor.PALO_ALTO, PaloAltoAdapter)
        AdapterRegistry.register(DeviceVendor.FORTINET, FortinetAdapter)
        AdapterRegistry.register(DeviceVendor.MOCK, MockAdapter)
        
        # Create adapter for a device
        adapter = AdapterRegistry.create(device_info)
    """
    
    _adapters: Dict[DeviceVendor, Type[BaseFirewallAdapter]] = {}
    _initialized: bool = False
    
    @classmethod
    def register(cls, vendor: DeviceVendor, adapter_class: Type[BaseFirewallAdapter]) -> None:
        """
        Register an adapter class for a vendor.
        
        Args:
            vendor: The vendor type
            adapter_class: The adapter class to register
        """
        if not issubclass(adapter_class, BaseFirewallAdapter):
            raise TypeError(f"{adapter_class} must be a subclass of BaseFirewallAdapter")
        
        cls._adapters[vendor] = adapter_class
        logger.debug(f"Registered adapter {adapter_class.__name__} for vendor {vendor.value}")
    
    @classmethod
    def unregister(cls, vendor: DeviceVendor) -> None:
        """
        Unregister an adapter for a vendor.
        
        Args:
            vendor: The vendor type to unregister
        """
        if vendor in cls._adapters:
            del cls._adapters[vendor]
            logger.debug(f"Unregistered adapter for vendor {vendor.value}")
    
    @classmethod
    def get_adapter_class(cls, vendor: DeviceVendor) -> Type[BaseFirewallAdapter]:
        """
        Get the adapter class for a vendor.
        
        Args:
            vendor: The vendor type
            
        Returns:
            The adapter class
            
        Raises:
            AdapterNotFoundError: If no adapter is registered for the vendor
        """
        cls._ensure_initialized()
        
        if vendor not in cls._adapters:
            raise AdapterNotFoundError(
                f"No adapter registered for vendor '{vendor.value}'. "
                f"Available vendors: {list(cls._adapters.keys())}"
            )
        
        return cls._adapters[vendor]
    
    @classmethod
    def create(cls, device: DeviceInfo) -> BaseFirewallAdapter:
        """
        Create an adapter instance for a device.
        
        Args:
            device: The device information
            
        Returns:
            An adapter instance for the device's vendor
            
        Raises:
            AdapterNotFoundError: If no adapter is registered for the device's vendor
        """
        adapter_class = cls.get_adapter_class(device.vendor)
        adapter = adapter_class(device)
        logger.info(f"Created {adapter_class.__name__} for device {device.name}")
        return adapter
    
    @classmethod
    def list_vendors(cls) -> list[DeviceVendor]:
        """
        List all registered vendor types.
        
        Returns:
            List of registered vendors
        """
        cls._ensure_initialized()
        return list(cls._adapters.keys())
    
    @classmethod
    def is_vendor_supported(cls, vendor: DeviceVendor) -> bool:
        """
        Check if a vendor has a registered adapter.
        
        Args:
            vendor: The vendor type
            
        Returns:
            True if the vendor has a registered adapter
        """
        cls._ensure_initialized()
        return vendor in cls._adapters
    
    @classmethod
    def clear(cls) -> None:
        """Clear all registered adapters. Primarily for testing."""
        cls._adapters.clear()
        cls._initialized = False
    
    @classmethod
    def _ensure_initialized(cls) -> None:
        """Ensure default adapters are registered."""
        if cls._initialized:
            return
        
        # Import and register default adapters
        try:
            from netcertify.adapters.mock.adapter import MockFirewallAdapter
            cls.register(DeviceVendor.MOCK, MockFirewallAdapter)
        except ImportError:
            logger.warning("Mock adapter not available")
        
        try:
            from netcertify.adapters.paloalto.adapter import PaloAltoAdapter
            cls.register(DeviceVendor.PALO_ALTO, PaloAltoAdapter)
        except ImportError:
            logger.warning("Palo Alto adapter not available - pan-os-python may not be installed")
        
        try:
            from netcertify.adapters.fortinet.adapter import FortinetAdapter
            cls.register(DeviceVendor.FORTINET, FortinetAdapter)
        except ImportError:
            logger.warning("Fortinet adapter not available - fortigate-api may not be installed")
        
        cls._initialized = True


def get_adapter(device: DeviceInfo) -> BaseFirewallAdapter:
    """
    Convenience function to create an adapter for a device.
    
    This is the primary entry point for creating adapters.
    
    Args:
        device: The device information
        
    Returns:
        An adapter instance for the device
        
    Example:
        device = DeviceInfo(
            name="fw-prod-01",
            vendor=DeviceVendor.PALO_ALTO,
            credentials=DeviceCredentials(...),
            connection=ConnectionParams(...)
        )
        
        adapter = get_adapter(device)
        with adapter.session():
            ntp_status = adapter.get_ntp_status()
    """
    return AdapterRegistry.create(device)


def create_adapter_for_testbed_device(
    device_name: str,
    device_data: Dict,
) -> BaseFirewallAdapter:
    """
    Create an adapter from testbed device data.
    
    This function parses device data from a PyATS testbed and creates
    the appropriate adapter.
    
    Args:
        device_name: Name of the device
        device_data: Device configuration dictionary from testbed
        
    Returns:
        An adapter instance
    """
    from netcertify.schemas.device import (
        DeviceCredentials,
        ConnectionParams,
    )
    from pydantic import SecretStr
    
    # Parse vendor
    vendor_str = device_data.get("vendor", device_data.get("os", "mock")).lower()
    vendor_map = {
        "paloalto": DeviceVendor.PALO_ALTO,
        "palo_alto": DeviceVendor.PALO_ALTO,
        "pan": DeviceVendor.PALO_ALTO,
        "fortinet": DeviceVendor.FORTINET,
        "fortigate": DeviceVendor.FORTINET,
        "forti": DeviceVendor.FORTINET,
        "mock": DeviceVendor.MOCK,
    }
    vendor = vendor_map.get(vendor_str, DeviceVendor.MOCK)
    
    # Parse credentials
    creds_data = device_data.get("credentials", {})
    if isinstance(creds_data, dict):
        default_creds = creds_data.get("default", creds_data)
    else:
        default_creds = {"username": "admin", "password": "admin"}
    
    credentials = DeviceCredentials(
        username=default_creds.get("username", "admin"),
        password=SecretStr(default_creds.get("password", "admin")),
        api_key=SecretStr(default_creds.get("api_key")) if default_creds.get("api_key") else None,
    )
    
    # Parse connection parameters
    conn_data = device_data.get("connections", {})
    if isinstance(conn_data, dict):
        default_conn = conn_data.get("default", conn_data)
        if isinstance(default_conn, dict):
            host = default_conn.get("ip", default_conn.get("host", "127.0.0.1"))
            port = default_conn.get("port", 443)
            protocol = default_conn.get("protocol", "https")
        else:
            host = "127.0.0.1"
            port = 443
            protocol = "https"
    else:
        host = "127.0.0.1"
        port = 443
        protocol = "https"
    
    connection = ConnectionParams(
        host=host,
        port=port,
        protocol=protocol,
        verify_ssl=device_data.get("verify_ssl", False),
    )
    
    # Create device info
    device_info = DeviceInfo(
        name=device_name,
        vendor=vendor,
        credentials=credentials,
        connection=connection,
        model=device_data.get("model"),
        serial_number=device_data.get("serial_number"),
        firmware_version=device_data.get("firmware_version"),
        environment=device_data.get("environment", "lab"),
        location=device_data.get("location"),
        tags=device_data.get("tags", []),
    )
    
    return get_adapter(device_info)
