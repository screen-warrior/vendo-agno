"""
Certification Runner - Orchestrate test execution.

Manages the execution of certification tests across devices,
collecting results and generating reports.
"""

import logging
import time
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any, Type
from contextlib import contextmanager

from netcertify.schemas.device import DeviceInfo, DeviceVendor
from netcertify.schemas.results import (
    TestResult,
    TestStepResult,
    CertificationSuiteResult,
    CertificationReport,
    ReportMetadata,
    ResultStatus,
)
from netcertify.adapters.base import BaseFirewallAdapter
from netcertify.adapters.registry import AdapterRegistry
from netcertify.validators.engine import ValidationEngine, ValidationContext
from netcertify.orchestrator.loader import TestbedConfig, TestbedLoader
from netcertify.reporters.html_generator import HTMLReportGenerator

logger = logging.getLogger(__name__)


class CertificationTest:
    """
    Base class for certification tests.
    
    Subclass this to create specific certification tests (NTP, HA, etc.)
    """
    
    # Test metadata
    name: str = "Base Test"
    description: str = "Base certification test"
    category: str = "general"
    tags: List[str] = []
    
    def __init__(self, device: DeviceInfo, adapter: BaseFirewallAdapter):
        """
        Initialize the test.
        
        Args:
            device: Device under test
            adapter: Adapter for device communication
        """
        self.device = device
        self.adapter = adapter
        self._engine: Optional[ValidationEngine] = None
        self._result: Optional[TestResult] = None
    
    @property
    def engine(self) -> ValidationEngine:
        """Get the validation engine."""
        if self._engine is None:
            context = ValidationContext(
                device_name=self.device.name,
                test_name=self.name,
                category=self.category,
                tags=self.tags,
            )
            self._engine = ValidationEngine(context)
        return self._engine
    
    def setup(self) -> bool:
        """
        Test setup - called before run().
        
        Override to perform any necessary setup.
        Returns True if setup succeeded.
        """
        return True
    
    def run(self) -> None:
        """
        Execute the test.
        
        Override this method to implement test logic.
        Use self.engine for assertions.
        """
        raise NotImplementedError("Subclasses must implement run()")
    
    def teardown(self) -> bool:
        """
        Test teardown - called after run().
        
        Override to perform any cleanup.
        Returns True if teardown succeeded.
        """
        return True
    
    def execute(self) -> TestResult:
        """
        Execute the complete test lifecycle.
        
        Returns:
            TestResult with all assertions and metadata
        """
        start_time = time.time()
        started_at = datetime.utcnow()
        
        # Initialize result
        self._result = TestResult(
            test_id=str(uuid.uuid4()),
            name=self.name,
            description=self.description,
            category=self.category,
            tags=self.tags,
            status=ResultStatus.PASSED,
            device_name=self.device.name,
            device_vendor=self.device.vendor.value,
            started_at=started_at,
        )
        
        try:
            # Setup
            logger.info(f"Setting up test: {self.name}")
            setup_success = self.setup()
            self._result.setup_success = setup_success
            
            if not setup_success:
                self._result.status = ResultStatus.ERROR
                self._result.error_message = "Test setup failed"
                return self._finalize_result(start_time)
            
            # Run test
            logger.info(f"Running test: {self.name}")
            self.run()
            
        except Exception as e:
            logger.exception(f"Test failed with exception: {e}")
            self._result.status = ResultStatus.ERROR
            self._result.error_message = str(e)
            
        finally:
            # Teardown
            try:
                logger.info(f"Tearing down test: {self.name}")
                teardown_success = self.teardown()
                self._result.teardown_success = teardown_success
            except Exception as e:
                logger.error(f"Teardown failed: {e}")
                self._result.teardown_success = False
        
        return self._finalize_result(start_time)
    
    def _finalize_result(self, start_time: float) -> TestResult:
        """Finalize the test result with timing and status."""
        # Calculate duration
        self._result.duration_ms = (time.time() - start_time) * 1000
        self._result.ended_at = datetime.utcnow()
        
        # Copy step results
        self._result.steps = self.engine.get_step_results()
        
        # Calculate assertion counts
        self._result.calculate_aggregates()
        
        # Determine final status
        if self._result.status != ResultStatus.ERROR:
            if self._result.failed_assertions > 0:
                self._result.status = ResultStatus.FAILED
            elif self._result.total_assertions == 0:
                self._result.status = ResultStatus.SKIPPED
            else:
                self._result.status = ResultStatus.PASSED
        
        logger.info(
            f"Test {self.name} completed: {self._result.status.value} "
            f"({self._result.passed_assertions}/{self._result.total_assertions} assertions)"
        )
        
        return self._result


class CertificationRunner:
    """
    Orchestrate certification test execution.
    
    Manages loading testbeds, executing tests, and generating reports.
    
    Usage:
        runner = CertificationRunner()
        runner.load_testbed("testbeds/production.yaml")
        runner.add_test_class(NTPCertificationTest)
        runner.add_test_class(HACertificationTest)
        
        report = runner.run()
        runner.generate_report(report, "reports/certification.html")
    """
    
    def __init__(self, name: str = "Certification Suite"):
        """
        Initialize the certification runner.
        
        Args:
            name: Name for this certification run
        """
        self.name = name
        self.testbed: Optional[TestbedConfig] = None
        self.test_classes: List[Type[CertificationTest]] = []
        self.adapters: Dict[str, BaseFirewallAdapter] = {}
        
        # Configuration
        self.continue_on_failure = True
        self.connect_timeout = 30
        
        # Results
        self.suite_results: List[CertificationSuiteResult] = []
    
    def load_testbed(self, filepath: str) -> TestbedConfig:
        """
        Load a testbed from YAML file.
        
        Args:
            filepath: Path to testbed YAML
            
        Returns:
            Loaded TestbedConfig
        """
        loader = TestbedLoader()
        self.testbed = loader.load(filepath)
        logger.info(f"Loaded testbed: {self.testbed.name} with {len(self.testbed.devices)} devices")
        return self.testbed
    
    def add_test_class(self, test_class: Type[CertificationTest]) -> None:
        """
        Add a test class to be executed.
        
        Args:
            test_class: CertificationTest subclass
        """
        if not issubclass(test_class, CertificationTest):
            raise TypeError(f"{test_class} must be a subclass of CertificationTest")
        
        self.test_classes.append(test_class)
        logger.info(f"Added test class: {test_class.name}")
    
    def add_test_classes(self, test_classes: List[Type[CertificationTest]]) -> None:
        """Add multiple test classes."""
        for tc in test_classes:
            self.add_test_class(tc)
    
    @contextmanager
    def _adapter_session(self, device: DeviceInfo):
        """Context manager for adapter connection."""
        adapter = AdapterRegistry.create(device)
        try:
            adapter.connect()
            yield adapter
        finally:
            adapter.disconnect()
    
    def run(
        self,
        devices: Optional[List[str]] = None,
        tests: Optional[List[str]] = None,
    ) -> CertificationReport:
        """
        Execute certification tests.
        
        Args:
            devices: Optional list of device names to test (default: all)
            tests: Optional list of test names to run (default: all)
            
        Returns:
            CertificationReport with all results
        """
        if not self.testbed:
            raise RuntimeError("No testbed loaded. Call load_testbed() first.")
        
        if not self.test_classes:
            raise RuntimeError("No tests added. Call add_test_class() first.")
        
        # Filter devices
        target_devices = self.testbed.devices
        if devices:
            target_devices = {
                name: dev for name, dev in target_devices.items()
                if name in devices
            }
        
        # Filter tests
        target_tests = self.test_classes
        if tests:
            target_tests = [tc for tc in target_tests if tc.name in tests]
        
        logger.info(
            f"Starting certification run: {len(target_devices)} devices, "
            f"{len(target_tests)} tests"
        )
        
        # Execute tests per device
        start_time = datetime.utcnow()
        all_results = []
        
        for device_name, device in target_devices.items():
            logger.info(f"Testing device: {device_name}")
            
            try:
                with self._adapter_session(device) as adapter:
                    for test_class in target_tests:
                        # Check if adapter supports the test
                        test = test_class(device, adapter)
                        
                        try:
                            result = test.execute()
                            all_results.append(result)
                        except Exception as e:
                            logger.error(f"Test {test_class.name} failed: {e}")
                            
                            # Create error result
                            error_result = TestResult(
                                test_id=str(uuid.uuid4()),
                                name=test_class.name,
                                status=ResultStatus.ERROR,
                                device_name=device_name,
                                device_vendor=device.vendor.value,
                                error_message=str(e),
                                started_at=datetime.utcnow(),
                            )
                            all_results.append(error_result)
                            
                            if not self.continue_on_failure:
                                raise
                            
            except Exception as e:
                logger.error(f"Failed to connect to device {device_name}: {e}")
                
                # Create error results for all tests
                for test_class in target_tests:
                    error_result = TestResult(
                        test_id=str(uuid.uuid4()),
                        name=test_class.name,
                        status=ResultStatus.ERROR,
                        device_name=device_name,
                        device_vendor=device.vendor.value,
                        error_message=f"Connection failed: {e}",
                        started_at=datetime.utcnow(),
                    )
                    all_results.append(error_result)
                
                if not self.continue_on_failure:
                    raise
        
        # Create suite result
        suite = CertificationSuiteResult(
            suite_id=str(uuid.uuid4()),
            name=self.name,
            status=ResultStatus.PASSED,
            started_at=start_time,
            ended_at=datetime.utcnow(),
            tests=all_results,
        )
        suite.calculate_aggregates()
        
        if suite.failed_tests > 0 or suite.error_tests > 0:
            suite.status = ResultStatus.FAILED
        
        suite.duration_ms = (suite.ended_at - suite.started_at).total_seconds() * 1000
        
        # Create report
        report = CertificationReport(
            metadata=ReportMetadata(
                report_id=str(uuid.uuid4()),
                report_title=f"{self.name} - {self.testbed.name}",
            ),
            overall_status=suite.status,
            suites=[suite],
        )
        report.calculate_aggregates()
        report.generate_executive_summary()
        
        logger.info(
            f"Certification run complete: {report.passed_tests}/{report.total_tests} passed "
            f"({report.overall_pass_rate:.1f}%)"
        )
        
        return report
    
    def generate_report(
        self,
        report: CertificationReport,
        filepath: str,
    ) -> str:
        """
        Generate HTML report.
        
        Args:
            report: Certification report
            filepath: Output file path
            
        Returns:
            Path to generated report
        """
        generator = HTMLReportGenerator()
        output_path = generator.save(report, filepath)
        logger.info(f"Report generated: {output_path}")
        return output_path


def create_runner(
    testbed_path: str,
    test_classes: List[Type[CertificationTest]],
    name: str = "Certification Suite",
) -> CertificationRunner:
    """
    Convenience function to create a configured runner.
    
    Args:
        testbed_path: Path to testbed YAML
        test_classes: List of test classes to run
        name: Suite name
        
    Returns:
        Configured CertificationRunner
    """
    runner = CertificationRunner(name=name)
    runner.load_testbed(testbed_path)
    runner.add_test_classes(test_classes)
    return runner
