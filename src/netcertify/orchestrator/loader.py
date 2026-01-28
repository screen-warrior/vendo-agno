"""
Testbed Loader - Parse PyATS testbed YAML into Pydantic models.

Converts PyATS testbed definitions into validated NetCertify models
for use with the certification framework.
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, SecretStr
import yaml

from netcertify.schemas.device import (
    DeviceInfo,
    DeviceCredentials,
    ConnectionParams,
    DeviceVendor,
    DeviceType,
    DeviceInventory,
)
from netcertify.adapters.base import BaseFirewallAdapter
from netcertify.adapters.registry import AdapterRegistry

logger = logging.getLogger(__name__)


class TestbedConfig(BaseModel):
    """
    Parsed testbed configuration.
    
    Contains all devices and metadata from a PyATS testbed file.
    """
    name: str = Field(..., description="Testbed name")
    description: Optional[str] = Field(None, description="Testbed description")
    source_file: Optional[str] = Field(None, description="Source YAML file path")
    devices: Dict[str, DeviceInfo] = Field(default_factory=dict, description="Device configurations")
    
    # Global testbed settings
    credentials: Optional[Dict[str, Any]] = Field(None, description="Default credentials")
    custom_data: Dict[str, Any] = Field(default_factory=dict, description="Custom testbed data")
    
    model_config = {"extra": "forbid"}
    
    def get_device(self, name: str) -> Optional[DeviceInfo]:
        """Get a device by name."""
        return self.devices.get(name)
    
    def get_devices_by_vendor(self, vendor: DeviceVendor) -> List[DeviceInfo]:
        """Get all devices for a specific vendor."""
        return [d for d in self.devices.values() if d.vendor == vendor]
    
    def get_device_names(self) -> List[str]:
        """Get list of all device names."""
        return list(self.devices.keys())
    
    def to_inventory(self) -> DeviceInventory:
        """Convert to DeviceInventory model."""
        return DeviceInventory(
            name=self.name,
            description=self.description,
            devices=list(self.devices.values()),
        )


class TestbedLoader:
    """
    Load and parse PyATS testbed YAML files.
    
    Converts YAML testbed definitions into validated Pydantic models,
    with support for credential resolution and adapter creation.
    
    Usage:
        loader = TestbedLoader()
        testbed = loader.load("testbeds/production.yaml")
        
        for device in testbed.devices.values():
            adapter = loader.create_adapter(device)
    """
    
    # Vendor name mappings
    VENDOR_MAPPING = {
        "paloalto": DeviceVendor.PALO_ALTO,
        "palo_alto": DeviceVendor.PALO_ALTO,
        "pan": DeviceVendor.PALO_ALTO,
        "panos": DeviceVendor.PALO_ALTO,
        "fortinet": DeviceVendor.FORTINET,
        "fortigate": DeviceVendor.FORTINET,
        "forti": DeviceVendor.FORTINET,
        "fortios": DeviceVendor.FORTINET,
        "mock": DeviceVendor.MOCK,
        "test": DeviceVendor.MOCK,
    }
    
    def __init__(self, default_credentials: Optional[Dict[str, str]] = None):
        """
        Initialize the testbed loader.
        
        Args:
            default_credentials: Default credentials to use when not specified
        """
        self.default_credentials = default_credentials or {
            "username": "admin",
            "password": "admin",
        }
    
    def load(self, filepath: str) -> TestbedConfig:
        """
        Load a testbed from a YAML file.
        
        Args:
            filepath: Path to the testbed YAML file
            
        Returns:
            TestbedConfig with validated device information
        """
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"Testbed file not found: {filepath}")
        
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        return self.parse(data, source_file=str(path))
    
    def parse(self, data: Dict[str, Any], source_file: Optional[str] = None) -> TestbedConfig:
        """
        Parse testbed data from a dictionary.
        
        Args:
            data: Testbed data dictionary (from YAML)
            source_file: Optional source file path for reference
            
        Returns:
            TestbedConfig with validated device information
        """
        # Extract testbed metadata
        testbed_name = data.get("testbed", {}).get("name", "unnamed-testbed")
        testbed_desc = data.get("testbed", {}).get("description")
        
        # Global credentials
        global_creds = data.get("testbed", {}).get("credentials", {})
        
        # Parse devices
        devices = {}
        devices_data = data.get("devices", {})
        
        for device_name, device_data in devices_data.items():
            try:
                device_info = self._parse_device(
                    device_name, 
                    device_data, 
                    global_creds
                )
                devices[device_name] = device_info
                logger.info(f"Loaded device: {device_name} ({device_info.vendor.value})")
            except Exception as e:
                logger.error(f"Error parsing device {device_name}: {e}")
                raise ValueError(f"Failed to parse device '{device_name}': {e}") from e
        
        return TestbedConfig(
            name=testbed_name,
            description=testbed_desc,
            source_file=source_file,
            devices=devices,
            credentials=global_creds,
            custom_data=data.get("custom", {}),
        )
    
    def _parse_device(
        self,
        name: str,
        data: Dict[str, Any],
        global_creds: Dict[str, Any],
    ) -> DeviceInfo:
        """Parse a single device from testbed data."""
        
        # Determine vendor
        vendor_str = (
            data.get("vendor") or 
            data.get("os") or 
            data.get("type", "mock")
        ).lower()
        vendor = self.VENDOR_MAPPING.get(vendor_str, DeviceVendor.MOCK)
        
        # Parse credentials
        credentials = self._parse_credentials(data, global_creds)
        
        # Parse connection parameters
        connection = self._parse_connection(data)
        
        # Determine device type
        device_type = DeviceType.PHYSICAL
        type_str = data.get("device_type", "physical").lower()
        if type_str == "virtual" or "vm" in type_str:
            device_type = DeviceType.VIRTUAL
        elif type_str == "cloud":
            device_type = DeviceType.CLOUD
        elif vendor == DeviceVendor.MOCK:
            device_type = DeviceType.MOCK
        
        # Build custom attributes from extra data
        custom_attrs = {}
        known_keys = {
            "vendor", "os", "type", "device_type", "credentials", "connections",
            "model", "serial_number", "firmware_version", "environment", "location",
            "tags", "description", "owner",
        }
        for key, value in data.items():
            if key not in known_keys:
                custom_attrs[key] = value
        
        return DeviceInfo(
            name=name,
            vendor=vendor,
            device_type=device_type,
            model=data.get("model"),
            serial_number=data.get("serial_number"),
            firmware_version=data.get("firmware_version"),
            credentials=credentials,
            connection=connection,
            environment=data.get("environment", "lab"),
            location=data.get("location"),
            tags=data.get("tags", []),
            description=data.get("description"),
            owner=data.get("owner"),
            custom_attributes=custom_attrs,
        )
    
    def _parse_credentials(
        self,
        device_data: Dict[str, Any],
        global_creds: Dict[str, Any],
    ) -> DeviceCredentials:
        """Parse device credentials with fallback to global/defaults."""
        
        # Priority: device-specific > global > defaults
        creds_data = device_data.get("credentials", {})
        
        # Handle nested credentials format (PyATS style)
        if isinstance(creds_data, dict):
            if "default" in creds_data:
                creds_data = creds_data["default"]
            elif not any(k in creds_data for k in ["username", "password"]):
                # Try to find first credential set
                for key, value in creds_data.items():
                    if isinstance(value, dict) and "username" in value:
                        creds_data = value
                        break
        
        # Get values with fallback
        username = (
            creds_data.get("username") or
            global_creds.get("default", {}).get("username") or
            global_creds.get("username") or
            self.default_credentials["username"]
        )
        
        password = (
            creds_data.get("password") or
            global_creds.get("default", {}).get("password") or
            global_creds.get("password") or
            self.default_credentials["password"]
        )
        
        api_key = creds_data.get("api_key") or global_creds.get("api_key")
        
        return DeviceCredentials(
            username=username,
            password=SecretStr(password),
            api_key=SecretStr(api_key) if api_key else None,
            private_key_path=creds_data.get("private_key_path"),
        )
    
    def _parse_connection(self, device_data: Dict[str, Any]) -> ConnectionParams:
        """Parse connection parameters from device data."""
        
        conn_data = device_data.get("connections", {})
        
        # Handle PyATS connection format
        if isinstance(conn_data, dict):
            # Try 'default' connection first, then 'cli', then any connection
            if "default" in conn_data:
                conn_data = conn_data["default"]
            elif "cli" in conn_data:
                conn_data = conn_data["cli"]
            elif "api" in conn_data:
                conn_data = conn_data["api"]
            elif conn_data:
                # Use first available connection
                first_key = next(iter(conn_data))
                if isinstance(conn_data[first_key], dict):
                    conn_data = conn_data[first_key]
        
        # Extract host - multiple possible keys
        host = (
            conn_data.get("ip") or
            conn_data.get("host") or
            conn_data.get("hostname") or
            device_data.get("ip") or
            device_data.get("host") or
            "127.0.0.1"
        )
        
        # Extract port
        port = conn_data.get("port", 443)
        if isinstance(port, str):
            port = int(port)
        
        # Protocol
        protocol = conn_data.get("protocol", "https")
        
        # SSL verification
        verify_ssl = conn_data.get("verify_ssl", conn_data.get("verify", False))
        
        return ConnectionParams(
            host=host,
            port=port,
            protocol=protocol,
            verify_ssl=verify_ssl,
            timeout=conn_data.get("timeout", 30),
            ssh_port=conn_data.get("ssh_port", 22),
        )
    
    def create_adapter(self, device: DeviceInfo) -> BaseFirewallAdapter:
        """
        Create an adapter for a device.
        
        Args:
            device: Device information
            
        Returns:
            Appropriate adapter instance for the device's vendor
        """
        return AdapterRegistry.create(device)
    
    def create_adapters(self, testbed: TestbedConfig) -> Dict[str, BaseFirewallAdapter]:
        """
        Create adapters for all devices in a testbed.
        
        Args:
            testbed: Testbed configuration
            
        Returns:
            Dictionary mapping device names to adapters
        """
        adapters = {}
        for name, device in testbed.devices.items():
            adapters[name] = self.create_adapter(device)
        return adapters


def load_testbed(filepath: str) -> TestbedConfig:
    """
    Convenience function to load a testbed file.
    
    Args:
        filepath: Path to testbed YAML file
        
    Returns:
        TestbedConfig
    """
    loader = TestbedLoader()
    return loader.load(filepath)
