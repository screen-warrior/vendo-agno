"""
Device Schemas - Pydantic models for device metadata, credentials, and connectivity.

These models define the contract for device information throughout the framework.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


class DeviceVendor(str, Enum):
    """Supported firewall vendors."""
    PALO_ALTO = "paloalto"
    FORTINET = "fortinet"
    MOCK = "mock"


class DeviceType(str, Enum):
    """Device deployment types."""
    PHYSICAL = "physical"
    VIRTUAL = "virtual"
    CLOUD = "cloud"
    MOCK = "mock"


class DeviceCredentials(BaseModel):
    """
    Secure credential storage for device authentication.
    
    Passwords are stored as SecretStr to prevent accidental logging.
    """
    username: str = Field(..., min_length=1, description="Authentication username")
    password: SecretStr = Field(..., description="Authentication password")
    api_key: Optional[SecretStr] = Field(None, description="API key for REST authentication")
    private_key_path: Optional[str] = Field(None, description="Path to SSH private key")
    enable_password: Optional[SecretStr] = Field(None, description="Enable/privilege password")
    
    model_config = {
        "extra": "forbid",
        "json_schema_extra": {
            "example": {
                "username": "admin",
                "password": "secure_password",
                "api_key": "LUFRPT..."
            }
        }
    }


class ConnectionParams(BaseModel):
    """
    Network connection parameters for device communication.
    
    Supports multiple connection methods: API, SSH, HTTPS.
    """
    host: str = Field(..., description="Device hostname or IP address")
    port: int = Field(443, ge=1, le=65535, description="Connection port")
    protocol: str = Field("https", pattern=r"^(https?|ssh)$", description="Connection protocol")
    timeout: int = Field(30, ge=5, le=300, description="Connection timeout in seconds")
    verify_ssl: bool = Field(True, description="Verify SSL certificates")
    ssl_cert_path: Optional[str] = Field(None, description="Custom CA certificate path")
    
    # SSH-specific parameters
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port if different from main port")
    ssh_timeout: int = Field(30, ge=5, le=300, description="SSH connection timeout")
    
    # API-specific parameters
    api_version: Optional[str] = Field(None, description="API version to use")
    base_path: str = Field("/api", description="API base path")
    
    model_config = {"extra": "forbid"}
    
    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        """Validate hostname is not empty and has no spaces."""
        v = v.strip()
        if not v:
            raise ValueError("Host cannot be empty")
        if " " in v:
            raise ValueError("Host cannot contain spaces")
        return v


class DeviceInfo(BaseModel):
    """
    Complete device information model.
    
    This is the primary model for representing a firewall device in the system.
    Contains all metadata, credentials, and connection details.
    """
    # Identity
    name: str = Field(..., min_length=1, max_length=64, description="Unique device name")
    vendor: DeviceVendor = Field(..., description="Firewall vendor")
    device_type: DeviceType = Field(DeviceType.PHYSICAL, description="Deployment type")
    model: Optional[str] = Field(None, description="Hardware/VM model")
    serial_number: Optional[str] = Field(None, description="Device serial number")
    
    # Software
    firmware_version: Optional[str] = Field(None, description="Current firmware version")
    minimum_firmware: Optional[str] = Field(None, description="Minimum required firmware")
    
    # Connectivity
    credentials: DeviceCredentials = Field(..., description="Authentication credentials")
    connection: ConnectionParams = Field(..., description="Connection parameters")
    
    # Classification
    environment: str = Field("production", description="Environment: production, staging, lab")
    location: Optional[str] = Field(None, description="Physical or logical location")
    tags: List[str] = Field(default_factory=list, description="Custom tags for filtering")
    
    # Metadata
    description: Optional[str] = Field(None, description="Device description")
    owner: Optional[str] = Field(None, description="Device owner/team")
    last_seen: Optional[datetime] = Field(None, description="Last successful connection")
    custom_attributes: Dict[str, Any] = Field(default_factory=dict, description="Custom attributes")
    
    model_config = {
        "extra": "forbid",
        "json_schema_extra": {
            "example": {
                "name": "fw-prod-east-01",
                "vendor": "paloalto",
                "device_type": "physical",
                "model": "PA-5220",
                "credentials": {
                    "username": "admin",
                    "password": "********"
                },
                "connection": {
                    "host": "192.168.1.1",
                    "port": 443
                },
                "environment": "production",
                "location": "DC-East"
            }
        }
    }
    
    @model_validator(mode="after")
    def validate_mock_device(self) -> "DeviceInfo":
        """Ensure mock devices have mock device type."""
        if self.vendor == DeviceVendor.MOCK and self.device_type != DeviceType.MOCK:
            self.device_type = DeviceType.MOCK
        return self
    
    @property
    def display_name(self) -> str:
        """Human-readable device identifier."""
        return f"{self.name} ({self.vendor.value})"
    
    @property
    def is_mock(self) -> bool:
        """Check if this is a mock device."""
        return self.vendor == DeviceVendor.MOCK


class DeviceInventory(BaseModel):
    """
    Collection of devices for batch operations.
    
    Used for testbed definitions and multi-device certification runs.
    """
    name: str = Field(..., description="Inventory name")
    description: Optional[str] = Field(None, description="Inventory description")
    devices: List[DeviceInfo] = Field(default_factory=list, description="List of devices")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = Field(None)
    
    model_config = {"extra": "forbid"}
    
    @property
    def device_count(self) -> int:
        """Total number of devices in inventory."""
        return len(self.devices)
    
    @property
    def vendors(self) -> List[DeviceVendor]:
        """Unique vendors in this inventory."""
        return list(set(d.vendor for d in self.devices))
    
    def get_device(self, name: str) -> Optional[DeviceInfo]:
        """Retrieve a device by name."""
        for device in self.devices:
            if device.name == name:
                return device
        return None
    
    def filter_by_vendor(self, vendor: DeviceVendor) -> List[DeviceInfo]:
        """Get devices filtered by vendor."""
        return [d for d in self.devices if d.vendor == vendor]
    
    def filter_by_environment(self, environment: str) -> List[DeviceInfo]:
        """Get devices filtered by environment."""
        return [d for d in self.devices if d.environment == environment]
    
    def filter_by_tags(self, tags: List[str]) -> List[DeviceInfo]:
        """Get devices that have all specified tags."""
        return [d for d in self.devices if all(t in d.tags for t in tags)]
