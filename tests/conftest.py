"""
Pytest configuration and shared fixtures.
"""

import sys
import os
import pytest
from pydantic import SecretStr

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from netcertify.schemas.device import (
    DeviceInfo,
    DeviceCredentials,
    ConnectionParams,
    DeviceVendor,
    DeviceType,
)
from netcertify.adapters.mock.adapter import MockFirewallAdapter
from netcertify.adapters.registry import AdapterRegistry


@pytest.fixture
def mock_credentials():
    """Create mock device credentials."""
    return DeviceCredentials(
        username="admin",
        password=SecretStr("admin"),
    )


@pytest.fixture
def mock_connection():
    """Create mock connection parameters."""
    return ConnectionParams(
        host="127.0.0.1",
        port=443,
        protocol="https",
        verify_ssl=False,
    )


@pytest.fixture
def mock_device_info(mock_credentials, mock_connection):
    """Create a mock device info object."""
    return DeviceInfo(
        name="test-mock-fw",
        vendor=DeviceVendor.MOCK,
        device_type=DeviceType.MOCK,
        model="MockFW-5000",
        serial_number="MOCK123456",
        firmware_version="10.2.3",
        credentials=mock_credentials,
        connection=mock_connection,
        environment="test",
        tags=["test", "mock"],
        custom_attributes={
            "mock_ntp_synced": True,
            "mock_ha_enabled": True,
            "mock_cpu_usage": 35.0,
            "mock_license_valid": True,
        },
    )


@pytest.fixture
def mock_device_failing(mock_credentials, mock_connection):
    """Create a mock device configured to fail tests."""
    return DeviceInfo(
        name="test-mock-failing",
        vendor=DeviceVendor.MOCK,
        device_type=DeviceType.MOCK,
        model="MockFW-3000",
        credentials=mock_credentials,
        connection=mock_connection,
        custom_attributes={
            "mock_ntp_synced": False,
            "mock_ha_enabled": False,
            "mock_cpu_usage": 95.0,
            "mock_license_valid": False,
            "mock_license_days": -30,
        },
    )


@pytest.fixture
def mock_adapter(mock_device_info):
    """Create a connected mock adapter."""
    adapter = MockFirewallAdapter(mock_device_info)
    adapter.connect()
    yield adapter
    adapter.disconnect()


@pytest.fixture
def mock_adapter_failing(mock_device_failing):
    """Create a mock adapter configured for failures."""
    adapter = MockFirewallAdapter(mock_device_failing)
    adapter.connect()
    yield adapter
    adapter.disconnect()


@pytest.fixture(autouse=True)
def reset_adapter_registry():
    """Reset adapter registry before each test."""
    AdapterRegistry.clear()
    yield
    AdapterRegistry.clear()
