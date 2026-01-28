"""
Unit tests for certification tests.
"""

import pytest

from netcertify.certifications.ntp_sync import NTPCertificationTest
from netcertify.certifications.interface_status import InterfaceCertificationTest
from netcertify.certifications.ha_status import HACertificationTest
from netcertify.certifications.system_health import SystemHealthCertificationTest
from netcertify.certifications.license_compliance import LicenseCertificationTest
from netcertify.schemas.results import ResultStatus


class TestNTPCertification:
    """Test NTP certification test."""
    
    def test_ntp_passes_with_synced_device(self, mock_device_info, mock_adapter):
        """Test NTP certification passes when device is synced."""
        test = NTPCertificationTest(mock_device_info, mock_adapter)
        result = test.execute()
        
        assert result.status == ResultStatus.PASSED
        assert result.total_assertions > 0
        assert result.failed_assertions == 0
    
    def test_ntp_fails_with_unsynced_device(self, mock_device_failing, mock_adapter_failing):
        """Test NTP certification fails when device is not synced."""
        test = NTPCertificationTest(mock_device_failing, mock_adapter_failing)
        result = test.execute()
        
        assert result.status == ResultStatus.FAILED
        assert result.failed_assertions > 0


class TestInterfaceCertification:
    """Test interface certification test."""
    
    def test_interface_passes_with_healthy_device(self, mock_device_info, mock_adapter):
        """Test interface certification passes with operational interfaces."""
        test = InterfaceCertificationTest(mock_device_info, mock_adapter)
        result = test.execute()
        
        assert result.status == ResultStatus.PASSED
        assert result.total_assertions > 0


class TestHACertification:
    """Test HA certification test."""
    
    def test_ha_passes_with_enabled_ha(self, mock_device_info, mock_adapter):
        """Test HA certification passes with HA enabled."""
        test = HACertificationTest(mock_device_info, mock_adapter)
        result = test.execute()
        
        assert result.status == ResultStatus.PASSED
    
    def test_ha_skipped_when_disabled(self, mock_device_failing, mock_adapter_failing):
        """Test HA certification skips when HA is disabled."""
        test = HACertificationTest(mock_device_failing, mock_adapter_failing)
        result = test.execute()
        
        # Should skip since HA is disabled
        assert result.skipped_assertions > 0 or result.status == ResultStatus.PASSED


class TestSystemHealthCertification:
    """Test system health certification test."""
    
    def test_health_passes_with_normal_resources(self, mock_device_info, mock_adapter):
        """Test health certification passes with normal utilization."""
        test = SystemHealthCertificationTest(mock_device_info, mock_adapter)
        result = test.execute()
        
        assert result.status == ResultStatus.PASSED
        assert result.total_assertions > 0
    
    def test_health_fails_with_high_utilization(self, mock_device_failing, mock_adapter_failing):
        """Test health certification fails with high CPU."""
        test = SystemHealthCertificationTest(mock_device_failing, mock_adapter_failing)
        result = test.execute()
        
        # Should fail due to high CPU
        assert result.status == ResultStatus.FAILED
        assert result.failed_assertions > 0


class TestLicenseCertification:
    """Test license certification test."""
    
    def test_license_passes_with_valid_licenses(self, mock_device_info, mock_adapter):
        """Test license certification passes with valid licenses."""
        test = LicenseCertificationTest(mock_device_info, mock_adapter)
        result = test.execute()
        
        assert result.status == ResultStatus.PASSED
    
    def test_license_fails_with_expired(self, mock_device_failing, mock_adapter_failing):
        """Test license certification fails with expired license."""
        test = LicenseCertificationTest(mock_device_failing, mock_adapter_failing)
        result = test.execute()
        
        assert result.status == ResultStatus.FAILED
