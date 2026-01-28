"""
End-to-end integration tests.
"""

import pytest
import os
import tempfile

from netcertify.orchestrator.loader import TestbedLoader, load_testbed
from netcertify.orchestrator.runner import CertificationRunner
from netcertify.certifications import BASIC_TESTS
from netcertify.reporters.html_generator import HTMLReportGenerator
from netcertify.schemas.results import ResultStatus


@pytest.fixture
def testbed_yaml():
    """Create a temporary testbed YAML file."""
    yaml_content = """
testbed:
  name: Test Environment
  
devices:
  mock-test-device:
    vendor: mock
    device_type: mock
    
    credentials:
      default:
        username: admin
        password: admin
    
    connections:
      default:
        host: 127.0.0.1
        port: 443
    
    mock_ntp_synced: true
    mock_ha_enabled: false
    mock_cpu_usage: 25.0
    mock_license_valid: true
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(yaml_content)
        f.flush()
        yield f.name
    os.unlink(f.name)


class TestTestbedLoader:
    """Test testbed loading functionality."""
    
    def test_load_testbed(self, testbed_yaml):
        """Test loading a testbed from YAML."""
        testbed = load_testbed(testbed_yaml)
        
        assert testbed.name == "Test Environment"
        assert "mock-test-device" in testbed.devices
        
        device = testbed.get_device("mock-test-device")
        assert device is not None
        assert device.vendor.value == "mock"
    
    def test_create_adapter_from_testbed(self, testbed_yaml):
        """Test creating adapter from loaded testbed."""
        loader = TestbedLoader()
        testbed = loader.load(testbed_yaml)
        
        device = testbed.get_device("mock-test-device")
        adapter = loader.create_adapter(device)
        
        assert adapter is not None
        adapter.connect()
        assert adapter.is_connected
        adapter.disconnect()


class TestCertificationRunner:
    """Test certification runner."""
    
    def test_full_run(self, testbed_yaml):
        """Test complete certification run."""
        runner = CertificationRunner(name="Integration Test")
        runner.load_testbed(testbed_yaml)
        runner.add_test_classes(BASIC_TESTS)
        
        report = runner.run()
        
        assert report is not None
        assert report.total_tests > 0
        assert report.total_devices == 1
    
    def test_generate_report(self, testbed_yaml):
        """Test report generation."""
        runner = CertificationRunner(name="Report Test")
        runner.load_testbed(testbed_yaml)
        runner.add_test_classes(BASIC_TESTS)
        
        report = runner.run()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "test_report.html")
            output_path = runner.generate_report(report, report_path)
            
            assert os.path.exists(output_path)
            
            with open(output_path, 'r') as f:
                content = f.read()
                assert "<!DOCTYPE html>" in content
                assert report.metadata.report_title in content


class TestHTMLReportGenerator:
    """Test HTML report generation."""
    
    def test_generate_report(self):
        """Test basic report generation."""
        from netcertify.schemas.results import (
            CertificationReport,
            CertificationSuiteResult,
            TestResult,
            ReportMetadata,
        )
        
        report = CertificationReport(
            metadata=ReportMetadata(
                report_id="test-123",
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
                            name="Sample Test",
                            status=ResultStatus.PASSED,
                            device_name="test-device",
                            device_vendor="mock",
                            total_assertions=5,
                            passed_assertions=5,
                        ),
                    ],
                ),
            ],
        )
        
        generator = HTMLReportGenerator()
        html = generator.generate(report)
        
        assert "<!DOCTYPE html>" in html
        assert "Test Report" in html
        assert "PASSED" in html
    
    def test_save_report(self):
        """Test saving report to file."""
        from netcertify.schemas.results import (
            CertificationReport,
            ReportMetadata,
        )
        
        report = CertificationReport(
            metadata=ReportMetadata(
                report_id="test-123",
                report_title="Save Test",
            ),
            overall_status=ResultStatus.PASSED,
            suites=[],
        )
        
        generator = HTMLReportGenerator()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.html")
            output = generator.save(report, path)
            
            assert os.path.exists(output)
