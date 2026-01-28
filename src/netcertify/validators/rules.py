"""
Validation Rules - Reusable validation rule definitions.

Rules are composable validation logic that can be applied to any value.
Each rule produces a structured result with pass/fail status and context.
"""

import re
from abc import ABC, abstractmethod
from typing import Any, Optional, List, TypeVar, Generic, Callable
from pydantic import BaseModel, Field

from netcertify.schemas.results import Severity


T = TypeVar('T')


class RuleResult(BaseModel):
    """Result of a validation rule evaluation."""
    passed: bool = Field(..., description="Whether the rule passed")
    message: str = Field(..., description="Human-readable result message")
    expected: Any = Field(None, description="Expected value")
    actual: Any = Field(None, description="Actual value")
    
    model_config = {"extra": "forbid"}


class ValidationRule(ABC, Generic[T]):
    """
    Abstract base class for validation rules.
    
    Rules encapsulate a single validation check that can be reused
    across different assertions and tests.
    """
    
    def __init__(
        self,
        name: str,
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        self.name = name
        self.description = description or name
        self.severity = severity
        self.remediation = remediation
    
    @abstractmethod
    def evaluate(self, value: T) -> RuleResult:
        """
        Evaluate the rule against a value.
        
        Args:
            value: The value to validate
            
        Returns:
            RuleResult with pass/fail status and context
        """
        pass
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}')"


class EqualsRule(ValidationRule[T]):
    """Validate that a value equals an expected value."""
    
    def __init__(
        self,
        expected: T,
        name: str = "equals",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.expected = expected
    
    def evaluate(self, value: T) -> RuleResult:
        passed = value == self.expected
        
        if passed:
            message = f"Value '{value}' equals expected '{self.expected}'"
        else:
            message = f"Value '{value}' does not equal expected '{self.expected}'"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=self.expected,
            actual=value,
        )


class NotEqualsRule(ValidationRule[T]):
    """Validate that a value does not equal a specific value."""
    
    def __init__(
        self,
        not_expected: T,
        name: str = "not_equals",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.not_expected = not_expected
    
    def evaluate(self, value: T) -> RuleResult:
        passed = value != self.not_expected
        
        if passed:
            message = f"Value '{value}' does not equal '{self.not_expected}' as expected"
        else:
            message = f"Value '{value}' equals '{self.not_expected}' but should not"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=f"not {self.not_expected}",
            actual=value,
        )


class GreaterThanRule(ValidationRule[float]):
    """Validate that a numeric value is greater than a threshold."""
    
    def __init__(
        self,
        threshold: float,
        inclusive: bool = False,
        name: str = "greater_than",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.threshold = threshold
        self.inclusive = inclusive
    
    def evaluate(self, value: float) -> RuleResult:
        if self.inclusive:
            passed = value >= self.threshold
            op_text = ">="
        else:
            passed = value > self.threshold
            op_text = ">"
        
        if passed:
            message = f"Value {value} is {op_text} {self.threshold}"
        else:
            message = f"Value {value} is not {op_text} {self.threshold}"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=f"{op_text} {self.threshold}",
            actual=value,
        )


class LessThanRule(ValidationRule[float]):
    """Validate that a numeric value is less than a threshold."""
    
    def __init__(
        self,
        threshold: float,
        inclusive: bool = False,
        name: str = "less_than",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.threshold = threshold
        self.inclusive = inclusive
    
    def evaluate(self, value: float) -> RuleResult:
        if self.inclusive:
            passed = value <= self.threshold
            op_text = "<="
        else:
            passed = value < self.threshold
            op_text = "<"
        
        if passed:
            message = f"Value {value} is {op_text} {self.threshold}"
        else:
            message = f"Value {value} is not {op_text} {self.threshold}"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=f"{op_text} {self.threshold}",
            actual=value,
        )


class InRangeRule(ValidationRule[float]):
    """Validate that a numeric value is within a range."""
    
    def __init__(
        self,
        min_value: float,
        max_value: float,
        inclusive_min: bool = True,
        inclusive_max: bool = True,
        name: str = "in_range",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.min_value = min_value
        self.max_value = max_value
        self.inclusive_min = inclusive_min
        self.inclusive_max = inclusive_max
    
    def evaluate(self, value: float) -> RuleResult:
        if self.inclusive_min:
            min_ok = value >= self.min_value
        else:
            min_ok = value > self.min_value
        
        if self.inclusive_max:
            max_ok = value <= self.max_value
        else:
            max_ok = value < self.max_value
        
        passed = min_ok and max_ok
        
        min_bracket = "[" if self.inclusive_min else "("
        max_bracket = "]" if self.inclusive_max else ")"
        range_str = f"{min_bracket}{self.min_value}, {self.max_value}{max_bracket}"
        
        if passed:
            message = f"Value {value} is within range {range_str}"
        else:
            message = f"Value {value} is outside range {range_str}"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=range_str,
            actual=value,
        )


class ContainsRule(ValidationRule[str]):
    """Validate that a string contains a substring."""
    
    def __init__(
        self,
        substring: str,
        case_sensitive: bool = True,
        name: str = "contains",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.substring = substring
        self.case_sensitive = case_sensitive
    
    def evaluate(self, value: str) -> RuleResult:
        if self.case_sensitive:
            passed = self.substring in value
        else:
            passed = self.substring.lower() in value.lower()
        
        if passed:
            message = f"Value contains '{self.substring}'"
        else:
            message = f"Value does not contain '{self.substring}'"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=f"contains '{self.substring}'",
            actual=value,
        )


class MatchesPatternRule(ValidationRule[str]):
    """Validate that a string matches a regex pattern."""
    
    def __init__(
        self,
        pattern: str,
        name: str = "matches_pattern",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.pattern = pattern
        self._compiled = re.compile(pattern)
    
    def evaluate(self, value: str) -> RuleResult:
        match = self._compiled.search(value)
        passed = match is not None
        
        if passed:
            message = f"Value matches pattern '{self.pattern}'"
        else:
            message = f"Value does not match pattern '{self.pattern}'"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=f"matches /{self.pattern}/",
            actual=value,
        )


class IsNotNoneRule(ValidationRule[Any]):
    """Validate that a value is not None."""
    
    def __init__(
        self,
        name: str = "is_not_none",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
    
    def evaluate(self, value: Any) -> RuleResult:
        passed = value is not None
        
        if passed:
            message = "Value is not None"
        else:
            message = "Value is None"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected="not None",
            actual=value,
        )


class IsTrueRule(ValidationRule[bool]):
    """Validate that a boolean value is True."""
    
    def __init__(
        self,
        name: str = "is_true",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
    
    def evaluate(self, value: bool) -> RuleResult:
        passed = value is True
        
        if passed:
            message = "Value is True"
        else:
            message = f"Value is {value}, expected True"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=True,
            actual=value,
        )


class IsFalseRule(ValidationRule[bool]):
    """Validate that a boolean value is False."""
    
    def __init__(
        self,
        name: str = "is_false",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
    
    def evaluate(self, value: bool) -> RuleResult:
        passed = value is False
        
        if passed:
            message = "Value is False"
        else:
            message = f"Value is {value}, expected False"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=False,
            actual=value,
        )


class ListContainsRule(ValidationRule[List[T]]):
    """Validate that a list contains a specific item."""
    
    def __init__(
        self,
        item: T,
        name: str = "list_contains",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.item = item
    
    def evaluate(self, value: List[T]) -> RuleResult:
        passed = self.item in value
        
        if passed:
            message = f"List contains '{self.item}'"
        else:
            message = f"List does not contain '{self.item}'"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=f"contains {self.item}",
            actual=value,
        )


class ListLengthRule(ValidationRule[List[Any]]):
    """Validate list length."""
    
    def __init__(
        self,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        exact_length: Optional[int] = None,
        name: str = "list_length",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.min_length = min_length
        self.max_length = max_length
        self.exact_length = exact_length
    
    def evaluate(self, value: List[Any]) -> RuleResult:
        length = len(value)
        passed = True
        expected_parts = []
        
        if self.exact_length is not None:
            passed = length == self.exact_length
            expected_parts.append(f"exactly {self.exact_length}")
        else:
            if self.min_length is not None:
                if length < self.min_length:
                    passed = False
                expected_parts.append(f">= {self.min_length}")
            
            if self.max_length is not None:
                if length > self.max_length:
                    passed = False
                expected_parts.append(f"<= {self.max_length}")
        
        expected = " and ".join(expected_parts) if expected_parts else "any length"
        
        if passed:
            message = f"List length {length} meets criteria ({expected})"
        else:
            message = f"List length {length} does not meet criteria ({expected})"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=expected,
            actual=length,
        )


class CustomRule(ValidationRule[T]):
    """Create a validation rule from a custom function."""
    
    def __init__(
        self,
        validator: Callable[[T], bool],
        message_fn: Optional[Callable[[T, bool], str]] = None,
        name: str = "custom",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.validator = validator
        self.message_fn = message_fn
    
    def evaluate(self, value: T) -> RuleResult:
        passed = self.validator(value)
        
        if self.message_fn:
            message = self.message_fn(value, passed)
        else:
            message = f"Custom validation {'passed' if passed else 'failed'}"
        
        return RuleResult(
            passed=passed,
            message=message,
            actual=value,
        )


class CompositeRule(ValidationRule[T]):
    """Combine multiple rules with AND/OR logic."""
    
    def __init__(
        self,
        rules: List[ValidationRule[T]],
        mode: str = "all",  # "all" (AND) or "any" (OR)
        name: str = "composite",
        description: Optional[str] = None,
        severity: Severity = Severity.MEDIUM,
        remediation: Optional[str] = None,
    ):
        super().__init__(name, description, severity, remediation)
        self.rules = rules
        self.mode = mode
    
    def evaluate(self, value: T) -> RuleResult:
        results = [rule.evaluate(value) for rule in self.rules]
        
        if self.mode == "all":
            passed = all(r.passed for r in results)
            mode_text = "all"
        else:
            passed = any(r.passed for r in results)
            mode_text = "any"
        
        passed_count = sum(1 for r in results if r.passed)
        total_count = len(results)
        
        message = f"{passed_count}/{total_count} rules passed (mode: {mode_text})"
        
        return RuleResult(
            passed=passed,
            message=message,
            expected=f"{mode_text} of {total_count} rules",
            actual=f"{passed_count} passed",
        )
