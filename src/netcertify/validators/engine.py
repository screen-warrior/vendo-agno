"""
Validation Engine - Central assertion system for certification tests.

The engine provides a unified interface for executing validations and
collecting results as Pydantic models suitable for reporting.
"""

import uuid
import time
import logging
from datetime import datetime
from typing import Any, Optional, List, Dict, TypeVar, Callable
from contextlib import contextmanager
from pydantic import BaseModel, Field

from netcertify.schemas.results import (
    AssertionResult,
    ResultStatus,
    Severity,
    TestStepResult,
)
from netcertify.validators.rules import ValidationRule, RuleResult

logger = logging.getLogger(__name__)

T = TypeVar('T')


class ValidationContext(BaseModel):
    """
    Context for validation operations.
    
    Provides metadata and configuration for assertion execution.
    """
    device_name: str = Field(..., description="Device being validated")
    test_name: str = Field(..., description="Current test name")
    step_name: Optional[str] = Field(None, description="Current step name")
    category: str = Field("general", description="Validation category")
    tags: List[str] = Field(default_factory=list, description="Tags for filtering")
    
    model_config = {"extra": "forbid"}


class ValidationEngine:
    """
    Central validation engine for certification tests.
    
    Provides methods for executing assertions and collecting results
    in a structured format suitable for reporting.
    
    Usage:
        engine = ValidationEngine(context)
        
        # Simple assertions
        engine.assert_equals("NTP Sync", actual_value, expected_value)
        engine.assert_true("HA Enabled", device.ha_status.enabled)
        
        # With custom rules
        engine.assert_rule("CPU Usage", cpu_value, LessThanRule(80.0))
        
        # Get results
        results = engine.get_results()
    """
    
    def __init__(self, context: ValidationContext):
        """
        Initialize the validation engine.
        
        Args:
            context: Validation context with device and test info
        """
        self.context = context
        self._results: List[AssertionResult] = []
        self._step_results: List[TestStepResult] = []
        self._current_step: Optional[TestStepResult] = None
        self._step_start_time: Optional[float] = None
    
    @property
    def results(self) -> List[AssertionResult]:
        """Get all assertion results."""
        return self._results
    
    @property
    def step_results(self) -> List[TestStepResult]:
        """Get all step results."""
        return self._step_results
    
    @property
    def passed_count(self) -> int:
        """Count of passed assertions."""
        return sum(1 for r in self._results if r.status == ResultStatus.PASSED)
    
    @property
    def failed_count(self) -> int:
        """Count of failed assertions."""
        return sum(1 for r in self._results if r.status == ResultStatus.FAILED)
    
    @property
    def all_passed(self) -> bool:
        """Check if all assertions passed."""
        return all(r.status == ResultStatus.PASSED for r in self._results)
    
    @property
    def has_critical_failures(self) -> bool:
        """Check if there are any critical failures."""
        return any(
            r.status == ResultStatus.FAILED and r.severity == Severity.CRITICAL
            for r in self._results
        )
    
    # =========================================================================
    # Step Management
    # =========================================================================
    
    @contextmanager
    def step(self, name: str, description: Optional[str] = None):
        """
        Context manager for grouping assertions into a step.
        
        Usage:
            with engine.step("Configure NTP"):
                engine.assert_true(...)
                engine.assert_equals(...)
        """
        self._start_step(name, description)
        try:
            yield self
        finally:
            self._end_step()
    
    def _start_step(self, name: str, description: Optional[str] = None) -> None:
        """Start a new validation step."""
        self._current_step = TestStepResult(
            step_id=str(uuid.uuid4()),
            name=name,
            description=description,
            status=ResultStatus.PASSED,
            started_at=datetime.utcnow(),
            assertions=[],
            logs=[],
        )
        self._step_start_time = time.time()
        logger.info(f"Starting step: {name}")
    
    def _end_step(self) -> None:
        """End the current validation step."""
        if self._current_step is None:
            return
        
        # Calculate duration
        if self._step_start_time:
            self._current_step.duration_ms = (time.time() - self._step_start_time) * 1000
        
        self._current_step.ended_at = datetime.utcnow()
        
        # Determine step status based on assertions
        if any(a.status == ResultStatus.FAILED for a in self._current_step.assertions):
            self._current_step.status = ResultStatus.FAILED
        elif any(a.status == ResultStatus.ERROR for a in self._current_step.assertions):
            self._current_step.status = ResultStatus.ERROR
        
        self._step_results.append(self._current_step)
        logger.info(f"Completed step: {self._current_step.name} - {self._current_step.status.value}")
        
        self._current_step = None
        self._step_start_time = None
    
    def log(self, message: str) -> None:
        """Add a log message to the current step."""
        if self._current_step:
            self._current_step.logs.append(f"[{datetime.utcnow().isoformat()}] {message}")
        logger.info(message)
    
    # =========================================================================
    # Assertion Methods
    # =========================================================================
    
    def _create_result(
        self,
        name: str,
        passed: bool,
        expected: Any,
        actual: Any,
        message: str,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
        duration_ms: float = 0.0,
    ) -> AssertionResult:
        """Create an assertion result and add it to the collection."""
        
        status = ResultStatus.PASSED if passed else ResultStatus.FAILED
        
        result = AssertionResult(
            assertion_id=str(uuid.uuid4()),
            name=name,
            status=status,
            severity=severity,
            expected=expected,
            actual=actual,
            message=message,
            reason=reason if not passed else None,
            remediation=remediation if not passed else None,
            category=self.context.category,
            tags=self.context.tags.copy(),
            device_name=self.context.device_name,
            duration_ms=duration_ms,
            executed_at=datetime.utcnow(),
        )
        
        self._results.append(result)
        
        if self._current_step:
            self._current_step.assertions.append(result)
        
        log_level = logging.INFO if passed else logging.WARNING
        logger.log(log_level, f"Assertion '{name}': {status.value} - {message}")
        
        return result
    
    def assert_equals(
        self,
        name: str,
        actual: Any,
        expected: Any,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """
        Assert that actual equals expected.
        
        Args:
            name: Assertion name
            actual: Actual value to check
            expected: Expected value
            severity: Failure severity
            reason: Reason for failure
            remediation: Suggested fix
            
        Returns:
            AssertionResult
        """
        start = time.time()
        passed = actual == expected
        duration = (time.time() - start) * 1000
        
        message = f"Expected '{expected}', got '{actual}'"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=expected,
            actual=actual,
            message=message,
            severity=severity,
            reason=reason or f"Value mismatch: expected '{expected}' but got '{actual}'",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_not_equals(
        self,
        name: str,
        actual: Any,
        not_expected: Any,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert that actual does not equal not_expected."""
        start = time.time()
        passed = actual != not_expected
        duration = (time.time() - start) * 1000
        
        message = f"Value should not equal '{not_expected}', got '{actual}'"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=f"not {not_expected}",
            actual=actual,
            message=message,
            severity=severity,
            reason=reason or f"Value should not be '{not_expected}'",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_true(
        self,
        name: str,
        condition: bool,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert that a condition is True."""
        start = time.time()
        passed = condition is True
        duration = (time.time() - start) * 1000
        
        message = f"Condition is {condition}, expected True"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=True,
            actual=condition,
            message=message,
            severity=severity,
            reason=reason or "Condition is not True",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_false(
        self,
        name: str,
        condition: bool,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert that a condition is False."""
        start = time.time()
        passed = condition is False
        duration = (time.time() - start) * 1000
        
        message = f"Condition is {condition}, expected False"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=False,
            actual=condition,
            message=message,
            severity=severity,
            reason=reason or "Condition is not False",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_not_none(
        self,
        name: str,
        value: Any,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert that a value is not None."""
        start = time.time()
        passed = value is not None
        duration = (time.time() - start) * 1000
        
        message = f"Value is {'not None' if passed else 'None'}"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected="not None",
            actual=value,
            message=message,
            severity=severity,
            reason=reason or "Value is None",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_greater_than(
        self,
        name: str,
        actual: float,
        threshold: float,
        inclusive: bool = False,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert that actual is greater than threshold."""
        start = time.time()
        
        if inclusive:
            passed = actual >= threshold
            op = ">="
        else:
            passed = actual > threshold
            op = ">"
        
        duration = (time.time() - start) * 1000
        message = f"Value {actual} {op} {threshold}: {'True' if passed else 'False'}"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=f"{op} {threshold}",
            actual=actual,
            message=message,
            severity=severity,
            reason=reason or f"Value {actual} is not {op} {threshold}",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_less_than(
        self,
        name: str,
        actual: float,
        threshold: float,
        inclusive: bool = False,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert that actual is less than threshold."""
        start = time.time()
        
        if inclusive:
            passed = actual <= threshold
            op = "<="
        else:
            passed = actual < threshold
            op = "<"
        
        duration = (time.time() - start) * 1000
        message = f"Value {actual} {op} {threshold}: {'True' if passed else 'False'}"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=f"{op} {threshold}",
            actual=actual,
            message=message,
            severity=severity,
            reason=reason or f"Value {actual} is not {op} {threshold}",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_in_range(
        self,
        name: str,
        actual: float,
        min_value: float,
        max_value: float,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert that actual is within range [min_value, max_value]."""
        start = time.time()
        passed = min_value <= actual <= max_value
        duration = (time.time() - start) * 1000
        
        message = f"Value {actual} in [{min_value}, {max_value}]: {'True' if passed else 'False'}"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=f"[{min_value}, {max_value}]",
            actual=actual,
            message=message,
            severity=severity,
            reason=reason or f"Value {actual} is outside range [{min_value}, {max_value}]",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_contains(
        self,
        name: str,
        haystack: str,
        needle: str,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert that haystack contains needle."""
        start = time.time()
        passed = needle in haystack
        duration = (time.time() - start) * 1000
        
        message = f"'{needle}' {'found' if passed else 'not found'} in value"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=f"contains '{needle}'",
            actual=haystack,
            message=message,
            severity=severity,
            reason=reason or f"Value does not contain '{needle}'",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_in_list(
        self,
        name: str,
        item: Any,
        collection: List[Any],
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert that item is in collection."""
        start = time.time()
        passed = item in collection
        duration = (time.time() - start) * 1000
        
        message = f"Item '{item}' {'found' if passed else 'not found'} in list"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=f"in {collection}",
            actual=item,
            message=message,
            severity=severity,
            reason=reason or f"Item '{item}' not found in list",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_list_length(
        self,
        name: str,
        collection: List[Any],
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        exact_length: Optional[int] = None,
        severity: Severity = Severity.MEDIUM,
        reason: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """Assert list length constraints."""
        start = time.time()
        length = len(collection)
        passed = True
        expected_parts = []
        
        if exact_length is not None:
            passed = length == exact_length
            expected_parts.append(f"exactly {exact_length}")
        else:
            if min_length is not None:
                if length < min_length:
                    passed = False
                expected_parts.append(f">= {min_length}")
            if max_length is not None:
                if length > max_length:
                    passed = False
                expected_parts.append(f"<= {max_length}")
        
        duration = (time.time() - start) * 1000
        expected = " and ".join(expected_parts) if expected_parts else "any"
        message = f"List length {length} (expected {expected})"
        
        return self._create_result(
            name=name,
            passed=passed,
            expected=expected,
            actual=length,
            message=message,
            severity=severity,
            reason=reason or f"List length {length} does not match expected {expected}",
            remediation=remediation,
            duration_ms=duration,
        )
    
    def assert_rule(
        self,
        name: str,
        value: Any,
        rule: ValidationRule,
        severity: Optional[Severity] = None,
        remediation: Optional[str] = None,
    ) -> AssertionResult:
        """
        Assert using a custom validation rule.
        
        Args:
            name: Assertion name
            value: Value to validate
            rule: Validation rule to apply
            severity: Override rule severity
            remediation: Override rule remediation
            
        Returns:
            AssertionResult
        """
        start = time.time()
        result = rule.evaluate(value)
        duration = (time.time() - start) * 1000
        
        return self._create_result(
            name=name,
            passed=result.passed,
            expected=result.expected,
            actual=result.actual,
            message=result.message,
            severity=severity or rule.severity,
            reason=rule.description if not result.passed else None,
            remediation=remediation or rule.remediation,
            duration_ms=duration,
        )
    
    def skip(
        self,
        name: str,
        reason: str,
    ) -> AssertionResult:
        """Mark an assertion as skipped."""
        result = AssertionResult(
            assertion_id=str(uuid.uuid4()),
            name=name,
            status=ResultStatus.SKIPPED,
            severity=Severity.INFO,
            message=f"Skipped: {reason}",
            reason=reason,
            category=self.context.category,
            tags=self.context.tags.copy(),
            device_name=self.context.device_name,
            executed_at=datetime.utcnow(),
        )
        
        self._results.append(result)
        if self._current_step:
            self._current_step.assertions.append(result)
        
        logger.info(f"Assertion '{name}': SKIPPED - {reason}")
        return result
    
    # =========================================================================
    # Result Collection
    # =========================================================================
    
    def get_results(self) -> List[AssertionResult]:
        """Get all assertion results."""
        return self._results.copy()
    
    def get_step_results(self) -> List[TestStepResult]:
        """Get all step results."""
        return self._step_results.copy()
    
    def get_failures(self) -> List[AssertionResult]:
        """Get only failed assertions."""
        return [r for r in self._results if r.status == ResultStatus.FAILED]
    
    def get_critical_failures(self) -> List[AssertionResult]:
        """Get critical severity failures."""
        return [
            r for r in self._results 
            if r.status == ResultStatus.FAILED and r.severity == Severity.CRITICAL
        ]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of validation results."""
        return {
            "total": len(self._results),
            "passed": self.passed_count,
            "failed": self.failed_count,
            "skipped": sum(1 for r in self._results if r.status == ResultStatus.SKIPPED),
            "pass_rate": (self.passed_count / len(self._results) * 100) if self._results else 0.0,
            "critical_failures": len(self.get_critical_failures()),
            "device": self.context.device_name,
            "test": self.context.test_name,
        }
    
    def clear(self) -> None:
        """Clear all results."""
        self._results.clear()
        self._step_results.clear()
        self._current_step = None
