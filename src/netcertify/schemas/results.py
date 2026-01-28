"""
Results Schemas - Pydantic models for test results, assertions, and reports.

These models capture the outcome of certification tests and enable rich reporting.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Generic, TypeVar
from pydantic import BaseModel, Field, computed_field


class Severity(str, Enum):
    """Result severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResultStatus(str, Enum):
    """Test/assertion result status."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    WARNING = "warning"


T = TypeVar('T')


class AssertionResult(BaseModel, Generic[T]):
    """
    Result of a single assertion/validation.
    
    Captures expected vs actual values with context.
    """
    assertion_id: str = Field(..., description="Unique assertion identifier")
    name: str = Field(..., description="Human-readable assertion name")
    description: Optional[str] = Field(None, description="Assertion description")
    
    # Status
    status: ResultStatus = Field(..., description="Assertion result")
    severity: Severity = Field(Severity.MEDIUM, description="Failure severity")
    
    # Values
    expected: Optional[Any] = Field(None, description="Expected value")
    actual: Optional[Any] = Field(None, description="Actual value")
    
    # Context
    message: str = Field("", description="Result message")
    reason: Optional[str] = Field(None, description="Failure reason if applicable")
    remediation: Optional[str] = Field(None, description="Suggested remediation")
    
    # Metadata
    category: str = Field("general", description="Assertion category")
    tags: List[str] = Field(default_factory=list, description="Tags for filtering")
    
    # Timing
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: float = Field(0.0, ge=0, description="Execution duration in ms")
    
    # Device context
    device_name: Optional[str] = Field(None, description="Device this assertion ran on")
    
    # Raw data for debugging
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Raw data for debugging")
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def passed(self) -> bool:
        """Check if assertion passed."""
        return self.status == ResultStatus.PASSED
    
    @computed_field
    @property
    def failed(self) -> bool:
        """Check if assertion failed."""
        return self.status == ResultStatus.FAILED


class TestStepResult(BaseModel):
    """
    Result of a single test step within a test case.
    
    A test case may have multiple steps (configure, validate, break, recover, etc.)
    """
    step_id: str = Field(..., description="Step identifier")
    name: str = Field(..., description="Step name")
    description: Optional[str] = Field(None, description="Step description")
    
    # Status
    status: ResultStatus = Field(..., description="Step result")
    
    # Timing
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = Field(None)
    duration_ms: float = Field(0.0, ge=0, description="Step duration in ms")
    
    # Assertions within this step
    assertions: List[AssertionResult] = Field(default_factory=list)
    
    # Logging
    logs: List[str] = Field(default_factory=list, description="Step execution logs")
    
    # Error handling
    error_message: Optional[str] = Field(None, description="Error if step failed")
    stack_trace: Optional[str] = Field(None, description="Stack trace on error")
    
    model_config = {"extra": "forbid"}
    
    @computed_field
    @property
    def assertion_count(self) -> int:
        """Total number of assertions in this step."""
        return len(self.assertions)
    
    @computed_field
    @property
    def passed_assertions(self) -> int:
        """Count of passed assertions."""
        return sum(1 for a in self.assertions if a.passed)
    
    @computed_field
    @property
    def failed_assertions(self) -> int:
        """Count of failed assertions."""
        return sum(1 for a in self.assertions if a.failed)


class TestResult(BaseModel):
    """
    Complete result of a single test case.
    
    Aggregates all steps and their assertions for a certification test.
    """
    test_id: str = Field(..., description="Unique test identifier")
    name: str = Field(..., description="Test name")
    description: Optional[str] = Field(None, description="Test description")
    
    # Classification
    category: str = Field("general", description="Test category (ntp, ha, security, etc.)")
    tags: List[str] = Field(default_factory=list, description="Test tags")
    
    # Status
    status: ResultStatus = Field(..., description="Overall test result")
    
    # Device
    device_name: str = Field(..., description="Target device name")
    device_vendor: str = Field(..., description="Device vendor")
    
    # Timing
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = Field(None)
    duration_ms: float = Field(0.0, ge=0, description="Total test duration in ms")
    
    # Steps
    steps: List[TestStepResult] = Field(default_factory=list)
    
    # Aggregate assertions (flattened from steps)
    total_assertions: int = Field(0, ge=0)
    passed_assertions: int = Field(0, ge=0)
    failed_assertions: int = Field(0, ge=0)
    skipped_assertions: int = Field(0, ge=0)
    
    # Error handling
    error_message: Optional[str] = Field(None)
    setup_success: bool = Field(True, description="Test setup succeeded")
    teardown_success: bool = Field(True, description="Test teardown succeeded")
    
    # Metadata
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Test parameters")
    environment: Dict[str, str] = Field(default_factory=dict, description="Environment info")
    
    model_config = {"extra": "forbid"}
    
    def calculate_aggregates(self) -> None:
        """Calculate aggregate assertion counts from steps."""
        self.total_assertions = sum(s.assertion_count for s in self.steps)
        self.passed_assertions = sum(s.passed_assertions for s in self.steps)
        self.failed_assertions = sum(s.failed_assertions for s in self.steps)
        self.skipped_assertions = sum(
            1 for s in self.steps 
            for a in s.assertions 
            if a.status == ResultStatus.SKIPPED
        )
    
    @computed_field
    @property
    def pass_rate(self) -> float:
        """Calculate assertion pass rate."""
        if self.total_assertions == 0:
            return 0.0
        return (self.passed_assertions / self.total_assertions) * 100
    
    @computed_field
    @property
    def step_count(self) -> int:
        """Total number of steps."""
        return len(self.steps)
    
    @computed_field
    @property
    def all_assertions(self) -> List[AssertionResult]:
        """Flatten all assertions from all steps."""
        return [a for s in self.steps for a in s.assertions]
    
    @computed_field
    @property
    def critical_failures(self) -> List[AssertionResult]:
        """Get critical severity failures."""
        return [
            a for a in self.all_assertions 
            if a.failed and a.severity == Severity.CRITICAL
        ]


class CertificationSuiteResult(BaseModel):
    """
    Result of a certification test suite (multiple tests).
    
    Aggregates results across multiple test cases for a device or group.
    """
    suite_id: str = Field(..., description="Unique suite identifier")
    name: str = Field(..., description="Suite name")
    description: Optional[str] = Field(None, description="Suite description")
    
    # Status
    status: ResultStatus = Field(..., description="Overall suite result")
    
    # Timing
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = Field(None)
    duration_ms: float = Field(0.0, ge=0)
    
    # Test results
    tests: List[TestResult] = Field(default_factory=list)
    
    # Aggregates
    total_tests: int = Field(0, ge=0)
    passed_tests: int = Field(0, ge=0)
    failed_tests: int = Field(0, ge=0)
    skipped_tests: int = Field(0, ge=0)
    error_tests: int = Field(0, ge=0)
    
    # Device summary
    devices_tested: List[str] = Field(default_factory=list)
    
    # Environment
    environment: Dict[str, str] = Field(default_factory=dict)
    
    model_config = {"extra": "forbid"}
    
    def calculate_aggregates(self) -> None:
        """Calculate aggregate test counts."""
        self.total_tests = len(self.tests)
        self.passed_tests = sum(1 for t in self.tests if t.status == ResultStatus.PASSED)
        self.failed_tests = sum(1 for t in self.tests if t.status == ResultStatus.FAILED)
        self.skipped_tests = sum(1 for t in self.tests if t.status == ResultStatus.SKIPPED)
        self.error_tests = sum(1 for t in self.tests if t.status == ResultStatus.ERROR)
        self.devices_tested = list(set(t.device_name for t in self.tests))
    
    @computed_field
    @property
    def pass_rate(self) -> float:
        """Calculate test pass rate."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests / self.total_tests) * 100
    
    @computed_field
    @property
    def total_assertions(self) -> int:
        """Total assertions across all tests."""
        return sum(t.total_assertions for t in self.tests)
    
    @computed_field
    @property
    def passed_assertions(self) -> int:
        """Passed assertions across all tests."""
        return sum(t.passed_assertions for t in self.tests)


class ReportMetadata(BaseModel):
    """Metadata for certification reports."""
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str = Field("NetCertify", description="Report generator")
    version: str = Field("1.0.0", description="Framework version")
    
    # Report identification
    report_id: str = Field(..., description="Unique report ID")
    report_title: str = Field(..., description="Report title")
    
    # Organization
    organization: Optional[str] = Field(None, description="Organization name")
    department: Optional[str] = Field(None, description="Department")
    author: Optional[str] = Field(None, description="Report author")
    
    # Classification
    classification: str = Field("internal", description="Report classification")
    
    model_config = {"extra": "forbid"}


class CertificationReport(BaseModel):
    """
    Complete certification report model.
    
    This is the top-level model for generating certification reports.
    Contains all data needed to render HTML reports.
    """
    metadata: ReportMetadata = Field(..., description="Report metadata")
    
    # Executive summary
    executive_summary: str = Field("", description="Executive summary text")
    overall_status: ResultStatus = Field(..., description="Overall certification status")
    
    # Suite results
    suites: List[CertificationSuiteResult] = Field(default_factory=list)
    
    # Aggregated statistics
    total_devices: int = Field(0, ge=0)
    total_tests: int = Field(0, ge=0)
    total_assertions: int = Field(0, ge=0)
    passed_tests: int = Field(0, ge=0)
    failed_tests: int = Field(0, ge=0)
    overall_pass_rate: float = Field(0.0, ge=0, le=100)
    
    # Critical findings
    critical_findings: List[AssertionResult] = Field(
        default_factory=list, 
        description="Critical severity failures"
    )
    
    # Recommendations
    recommendations: List[str] = Field(default_factory=list)
    
    # Timing
    total_duration_ms: float = Field(0.0, ge=0)
    
    model_config = {"extra": "forbid"}
    
    def calculate_aggregates(self) -> None:
        """Calculate all aggregate statistics."""
        for suite in self.suites:
            suite.calculate_aggregates()
        
        self.total_tests = sum(s.total_tests for s in self.suites)
        self.total_assertions = sum(s.total_assertions for s in self.suites)
        self.passed_tests = sum(s.passed_tests for s in self.suites)
        self.failed_tests = sum(s.failed_tests for s in self.suites)
        
        all_devices = set()
        for suite in self.suites:
            all_devices.update(suite.devices_tested)
        self.total_devices = len(all_devices)
        
        if self.total_tests > 0:
            self.overall_pass_rate = (self.passed_tests / self.total_tests) * 100
        
        # Collect critical findings
        self.critical_findings = []
        for suite in self.suites:
            for test in suite.tests:
                self.critical_findings.extend(test.critical_failures)
        
        # Determine overall status
        if self.failed_tests == 0 and self.total_tests > 0:
            self.overall_status = ResultStatus.PASSED
        elif self.critical_findings:
            self.overall_status = ResultStatus.FAILED
        elif self.failed_tests > 0:
            self.overall_status = ResultStatus.WARNING
        else:
            self.overall_status = ResultStatus.SKIPPED
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary text."""
        status_text = "PASSED" if self.overall_status == ResultStatus.PASSED else "FAILED"
        
        summary = f"""
Certification Status: {status_text}

This report summarizes the automated certification testing performed on {self.total_devices} device(s).

Key Metrics:
- Total Tests Executed: {self.total_tests}
- Tests Passed: {self.passed_tests}
- Tests Failed: {self.failed_tests}
- Overall Pass Rate: {self.overall_pass_rate:.1f}%
- Total Assertions: {self.total_assertions}
- Critical Findings: {len(self.critical_findings)}

"""
        if self.critical_findings:
            summary += "Critical issues require immediate attention before deployment.\n"
        elif self.overall_status == ResultStatus.PASSED:
            summary += "All certification tests passed. Device(s) meet operational requirements.\n"
        
        self.executive_summary = summary.strip()
        return self.executive_summary


class ComplianceRequirement(BaseModel):
    """Individual compliance requirement definition."""
    requirement_id: str = Field(..., description="Requirement ID (e.g., CIS-1.1)")
    title: str = Field(..., description="Requirement title")
    description: str = Field(..., description="Requirement description")
    category: str = Field(..., description="Requirement category")
    severity: Severity = Field(Severity.MEDIUM, description="Compliance severity")
    
    # Mapping to tests
    test_ids: List[str] = Field(default_factory=list, description="Related test IDs")
    
    model_config = {"extra": "forbid"}


class ComplianceResult(BaseModel):
    """Result of a compliance check."""
    requirement: ComplianceRequirement = Field(..., description="The requirement")
    status: ResultStatus = Field(..., description="Compliance status")
    evidence: List[AssertionResult] = Field(default_factory=list, description="Supporting evidence")
    notes: Optional[str] = Field(None, description="Additional notes")
    
    model_config = {"extra": "forbid"}
