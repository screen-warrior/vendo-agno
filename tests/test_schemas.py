"""
Unit tests for Pydantic schemas.
"""

import pytest
from datetime import datetime, timedelta
from pydantic import ValidationError, SecretStr

from netcertify.schemas.device import (
    DeviceInfo,
    DeviceCredentials,
    ConnectionParams,
    DeviceVendor,
    DeviceType,
    DeviceInventory,
)
from netcertify.schemas.configuration import (
    NTPConfiguration,
    NTPServer,
    InterfaceConfig,
    SecurityPolicy,
    PolicyAction,
)
from netcertify.schemas.status import (
    NTPStatus,
    SyncState,
    SystemHealth,
    LicenseStatus,
    LicenseFeature,
    LicenseState,
)
from netcertify.schemas.results import (
    AssertionResult,
    TestResult,
    ResultStatus,
    Severity,
    CertificationReport,
    ReportMetadata,
)


class TestDeviceSchemas:
    """Test device-related schemas."""
    
    def test_device_credentials_password_hidden(self):
        """Verify password is stored as SecretStr."""
        creds = DeviceCredentials(
            username="admin",
            password=SecretStr("secret123"),
        )
        
        assert creds.username == "admin"
        assert str(creds.password) == "**********"
        assert creds.password.get_secret_value() == "secret123"
    
    def test_connection_params_validation(self):
        """Test connection parameter validation."""
        # Valid connection
        conn = ConnectionParams(host="192.168.1.1", port=443)
        assert conn.host == "192.168.1.1"
        assert conn.port == 443
        
        # Invalid port
        with pytest.raises(ValidationError):
            ConnectionParams(host="192.168.1.1", port=99999)
        
        # Empty host
        with pytest.raises(ValidationError):
            ConnectionParams(host="", port=443)
    
    def test_device_info_creation(self, mock_credentials, mock_connection):
        """Test complete device info creation."""
        device = DeviceInfo(
            name="test-fw",
            vendor=DeviceVendor.PALO_ALTO,
            credentials=mock_credentials,
            connection=mock_connection,
        )
        
        assert device.name == "test-fw"
        assert device.vendor == DeviceVendor.PALO_ALTO
        assert device.display_name == "test-fw (paloalto)"
        assert not device.is_mock
    
    def test_device_info_mock_auto_type(self, mock_credentials, mock_connection):
        """Test that mock vendor forces mock device type."""
        device = DeviceInfo(
            name="mock-fw",
            vendor=DeviceVendor.MOCK,
            device_type=DeviceType.PHYSICAL,  # Should be overridden
            credentials=mock_credentials,
            connection=mock_connection,
        )
        
        assert device.device_type == DeviceType.MOCK
        assert device.is_mock
    
    def test_device_inventory_operations(self, mock_credentials, mock_connection):
        """Test device inventory functionality."""
        devices = [
            DeviceInfo(
                name=f"fw-{i}",
                vendor=DeviceVendor.PALO_ALTO if i % 2 == 0 else DeviceVendor.FORTINET,
                credentials=mock_credentials,
                connection=mock_connection,
                environment="production" if i < 2 else "staging",
                tags=["test"],
            )
            for i in range(4)
        ]
        
        inventory = DeviceInventory(
            name="test-inventory",
            devices=devices,
        )
        
        assert inventory.device_count == 4
        assert len(inventory.vendors) == 2
        assert inventory.get_device("fw-0") is not None
        assert len(inventory.filter_by_vendor(DeviceVendor.PALO_ALTO)) == 2
        assert len(inventory.filter_by_environment("production")) == 2


class TestConfigurationSchemas:
    """Test configuration schemas."""
    
    def test_ntp_configuration(self):
        """Test NTP configuration model."""
        config = NTPConfiguration(
            enabled=True,
            servers=[
                NTPServer(address="0.pool.ntp.org", preferred=True),
                NTPServer(address="1.pool.ntp.org"),
            ],
            primary_server="0.pool.ntp.org",
        )
        
        assert config.enabled
        assert config.server_count == 2
        assert config.servers[0].preferred
    
    def test_interface_config_validation(self):
        """Test interface configuration validation."""
        iface = InterfaceConfig(
            name="ethernet1/1",
            enabled=True,
            ip_address="10.0.0.1/24",
            mtu=1500,
        )
        
        assert iface.name == "ethernet1/1"
        assert iface.mtu == 1500
        
        # Invalid MTU
        with pytest.raises(ValidationError):
            InterfaceConfig(name="eth0", mtu=100)  # Below minimum
    
    def test_security_policy(self):
        """Test security policy model."""
        policy = SecurityPolicy(
            name="allow-web",
            enabled=True,
            sequence=1,
            source_zones=["trust"],
            destination_zones=["untrust"],
            source_addresses=["any"],
            destination_addresses=["any"],
            applications=["web-browsing", "ssl"],
            action=PolicyAction.ALLOW,
            log_end=True,
        )
        
        assert policy.name == "allow-web"
        assert policy.action == PolicyAction.ALLOW
        assert "trust" in policy.source_zones


class TestStatusSchemas:
    """Test status schemas."""
    
    def test_ntp_status_properties(self):
        """Test NTP status computed properties."""
        status = NTPStatus(
            sync_state=SyncState.SYNCED,
            synced_to="0.pool.ntp.org",
            stratum=3,
            offset_ms=0.5,
        )
        
        assert status.is_synchronized
        assert status.reachable_peers == 0
    
    def test_system_health_computed_properties(self):
        """Test system health computed values."""
        health = SystemHealth(
            cpu_utilization_percent=45.0,
            memory_total_mb=16384,
            memory_used_mb=8192,
            memory_free_mb=8192,
            disk_total_gb=500.0,
            disk_used_gb=250.0,
            uptime_seconds=864000,
        )
        
        assert health.memory_utilization_percent == 50.0
        assert health.disk_utilization_percent == 50.0
        assert health.uptime_days == 10.0
    
    def test_license_status_expiring(self):
        """Test license expiration detection."""
        expiry = datetime.utcnow() + timedelta(days=15)
        
        status = LicenseStatus(
            serial_number="TEST123",
            overall_state=LicenseState.VALID,
            features=[
                LicenseFeature(
                    name="Threat Prevention",
                    enabled=True,
                    state=LicenseState.EXPIRING_SOON,
                    expiration_date=expiry,
                ),
            ],
        )
        
        assert len(status.expiring_features) == 1
        assert status.features[0].days_until_expiry == 15


class TestResultSchemas:
    """Test result schemas."""
    
    def test_assertion_result_properties(self):
        """Test assertion result computed properties."""
        passed = AssertionResult(
            assertion_id="test-1",
            name="Test Assertion",
            status=ResultStatus.PASSED,
            expected="true",
            actual=True,
            message="Test passed",
        )
        
        assert passed.passed
        assert not passed.failed
        
        failed = AssertionResult(
            assertion_id="test-2",
            name="Failed Assertion",
            status=ResultStatus.FAILED,
            expected="true",
            actual=False,
            message="Test failed",
            severity=Severity.CRITICAL,
        )
        
        assert not failed.passed
        assert failed.failed
    
    def test_test_result_aggregation(self):
        """Test test result aggregate calculations."""
        from netcertify.schemas.results import TestStepResult
        
        result = TestResult(
            test_id="test-1",
            name="Sample Test",
            status=ResultStatus.PASSED,
            device_name="test-device",
            device_vendor="mock",
            steps=[
                TestStepResult(
                    step_id="step-1",
                    name="Step 1",
                    status=ResultStatus.PASSED,
                    assertions=[
                        AssertionResult(
                            assertion_id="a1",
                            name="Assertion 1",
                            status=ResultStatus.PASSED,
                            message="OK",
                        ),
                        AssertionResult(
                            assertion_id="a2",
                            name="Assertion 2",
                            status=ResultStatus.FAILED,
                            message="Failed",
                            severity=Severity.CRITICAL,
                        ),
                    ],
                ),
            ],
        )
        
        result.calculate_aggregates()
        
        assert result.total_assertions == 2
        assert result.passed_assertions == 1
        assert result.failed_assertions == 1
        assert result.pass_rate == 50.0
        assert len(result.critical_failures) == 1
    
    def test_certification_report_summary(self):
        """Test certification report summary generation."""
        from netcertify.schemas.results import CertificationSuiteResult
        
        report = CertificationReport(
            metadata=ReportMetadata(
                report_id="test-report",
                report_title="Test Report",
            ),
            overall_status=ResultStatus.PASSED,
            suites=[
                CertificationSuiteResult(
                    suite_id="suite-1",
                    name="Test Suite",
                    status=ResultStatus.PASSED,
                    tests=[
                        TestResult(
                            test_id="test-1",
                            name="Test 1",
                            status=ResultStatus.PASSED,
                            device_name="device-1",
                            device_vendor="mock",
                            total_assertions=5,
                            passed_assertions=5,
                        ),
                    ],
                ),
            ],
        )
        
        report.calculate_aggregates()
        summary = report.generate_executive_summary()
        
        assert "PASSED" in summary
        assert report.total_tests == 1
        assert report.overall_pass_rate == 100.0
