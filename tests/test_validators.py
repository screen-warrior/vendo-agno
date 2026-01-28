"""
Unit tests for validation engine and rules.
"""

import pytest

from netcertify.validators.engine import ValidationEngine, ValidationContext
from netcertify.validators.rules import (
    EqualsRule,
    NotEqualsRule,
    GreaterThanRule,
    LessThanRule,
    InRangeRule,
    ContainsRule,
    IsTrueRule,
    ListContainsRule,
    ListLengthRule,
    CompositeRule,
)
from netcertify.schemas.results import ResultStatus, Severity


@pytest.fixture
def validation_context():
    """Create a validation context for testing."""
    return ValidationContext(
        device_name="test-device",
        test_name="test-validation",
        category="test",
        tags=["unit-test"],
    )


@pytest.fixture
def engine(validation_context):
    """Create a validation engine."""
    return ValidationEngine(validation_context)


class TestValidationRules:
    """Test validation rules."""
    
    def test_equals_rule_pass(self):
        """Test equals rule passes on match."""
        rule = EqualsRule(expected="hello")
        result = rule.evaluate("hello")
        
        assert result.passed
        assert result.expected == "hello"
        assert result.actual == "hello"
    
    def test_equals_rule_fail(self):
        """Test equals rule fails on mismatch."""
        rule = EqualsRule(expected="hello")
        result = rule.evaluate("world")
        
        assert not result.passed
    
    def test_greater_than_rule(self):
        """Test greater than rule."""
        rule = GreaterThanRule(threshold=10)
        
        assert rule.evaluate(15).passed
        assert not rule.evaluate(5).passed
        assert not rule.evaluate(10).passed
        
        # Inclusive
        rule_inc = GreaterThanRule(threshold=10, inclusive=True)
        assert rule_inc.evaluate(10).passed
    
    def test_less_than_rule(self):
        """Test less than rule."""
        rule = LessThanRule(threshold=10)
        
        assert rule.evaluate(5).passed
        assert not rule.evaluate(15).passed
        assert not rule.evaluate(10).passed
        
        # Inclusive
        rule_inc = LessThanRule(threshold=10, inclusive=True)
        assert rule_inc.evaluate(10).passed
    
    def test_in_range_rule(self):
        """Test in range rule."""
        rule = InRangeRule(min_value=0, max_value=100)
        
        assert rule.evaluate(50).passed
        assert rule.evaluate(0).passed
        assert rule.evaluate(100).passed
        assert not rule.evaluate(-1).passed
        assert not rule.evaluate(101).passed
    
    def test_contains_rule(self):
        """Test contains rule."""
        rule = ContainsRule(substring="world")
        
        assert rule.evaluate("hello world").passed
        assert not rule.evaluate("hello").passed
        
        # Case insensitive
        rule_ci = ContainsRule(substring="WORLD", case_sensitive=False)
        assert rule_ci.evaluate("hello world").passed
    
    def test_list_contains_rule(self):
        """Test list contains rule."""
        rule = ListContainsRule(item="apple")
        
        assert rule.evaluate(["apple", "banana"]).passed
        assert not rule.evaluate(["orange", "banana"]).passed
    
    def test_list_length_rule(self):
        """Test list length rule."""
        # Exact length
        rule_exact = ListLengthRule(exact_length=3)
        assert rule_exact.evaluate([1, 2, 3]).passed
        assert not rule_exact.evaluate([1, 2]).passed
        
        # Min/max
        rule_range = ListLengthRule(min_length=2, max_length=5)
        assert rule_range.evaluate([1, 2, 3]).passed
        assert not rule_range.evaluate([1]).passed
        assert not rule_range.evaluate([1, 2, 3, 4, 5, 6]).passed
    
    def test_composite_rule_all(self):
        """Test composite rule with AND logic."""
        rules = [
            GreaterThanRule(threshold=0),
            LessThanRule(threshold=100),
        ]
        composite = CompositeRule(rules, mode="all")
        
        assert composite.evaluate(50).passed
        assert not composite.evaluate(-1).passed
        assert not composite.evaluate(101).passed
    
    def test_composite_rule_any(self):
        """Test composite rule with OR logic."""
        rules = [
            EqualsRule(expected="red"),
            EqualsRule(expected="blue"),
        ]
        composite = CompositeRule(rules, mode="any")
        
        assert composite.evaluate("red").passed
        assert composite.evaluate("blue").passed
        assert not composite.evaluate("green").passed


class TestValidationEngine:
    """Test validation engine."""
    
    def test_assert_equals(self, engine):
        """Test equals assertion."""
        result = engine.assert_equals("Test Equal", "hello", "hello")
        assert result.passed
        
        result = engine.assert_equals("Test Not Equal", "hello", "world")
        assert not result.passed
    
    def test_assert_true(self, engine):
        """Test true assertion."""
        result = engine.assert_true("Test True", True)
        assert result.passed
        
        result = engine.assert_true("Test False", False)
        assert not result.passed
    
    def test_assert_greater_than(self, engine):
        """Test greater than assertion."""
        result = engine.assert_greater_than("Test GT", 10, 5)
        assert result.passed
        
        result = engine.assert_greater_than("Test GT Fail", 5, 10)
        assert not result.passed
    
    def test_assert_less_than(self, engine):
        """Test less than assertion."""
        result = engine.assert_less_than("Test LT", 5, 10)
        assert result.passed
    
    def test_assert_in_range(self, engine):
        """Test in range assertion."""
        result = engine.assert_in_range("Test Range", 50, 0, 100)
        assert result.passed
        
        result = engine.assert_in_range("Test Range Fail", 150, 0, 100)
        assert not result.passed
    
    def test_assert_contains(self, engine):
        """Test contains assertion."""
        result = engine.assert_contains("Test Contains", "hello world", "world")
        assert result.passed
    
    def test_assert_not_none(self, engine):
        """Test not none assertion."""
        result = engine.assert_not_none("Test Not None", "value")
        assert result.passed
        
        result = engine.assert_not_none("Test Is None", None)
        assert not result.passed
    
    def test_skip_assertion(self, engine):
        """Test skipped assertion."""
        result = engine.skip("Skipped Test", "Not supported")
        
        assert result.status == ResultStatus.SKIPPED
        assert "Not supported" in result.reason
    
    def test_severity_levels(self, engine):
        """Test severity assignment."""
        result = engine.assert_true(
            "Critical Test",
            False,
            severity=Severity.CRITICAL,
        )
        
        assert result.severity == Severity.CRITICAL
    
    def test_step_grouping(self, engine):
        """Test step-based assertion grouping."""
        with engine.step("Test Step"):
            engine.assert_true("Step Assertion 1", True)
            engine.assert_true("Step Assertion 2", True)
        
        steps = engine.get_step_results()
        assert len(steps) == 1
        assert steps[0].name == "Test Step"
        assert steps[0].assertion_count == 2
    
    def test_results_collection(self, engine):
        """Test results collection."""
        engine.assert_true("Test 1", True)
        engine.assert_true("Test 2", False)
        engine.assert_true("Test 3", True)
        
        assert len(engine.results) == 3
        assert engine.passed_count == 2
        assert engine.failed_count == 1
        assert not engine.all_passed
    
    def test_summary(self, engine):
        """Test results summary."""
        engine.assert_true("Test 1", True)
        engine.assert_true("Test 2", True)
        
        summary = engine.get_summary()
        
        assert summary["total"] == 2
        assert summary["passed"] == 2
        assert summary["pass_rate"] == 100.0
    
    def test_custom_rule_assertion(self, engine):
        """Test assertion with custom rule."""
        rule = InRangeRule(min_value=0, max_value=100, severity=Severity.HIGH)
        
        result = engine.assert_rule("CPU Check", 45, rule)
        assert result.passed
        
        result = engine.assert_rule("CPU Critical", 150, rule)
        assert not result.passed
        assert result.severity == Severity.HIGH
