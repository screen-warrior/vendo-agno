# Contributing to NetCertify

Thank you for your interest in contributing to NetCertify! This document provides guidelines and instructions for contributing.

## 🚀 Getting Started

### Setting Up Development Environment

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/YOUR-USERNAME/vendo-agno.git
   cd vendo-agno
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Run tests to verify setup**
   ```bash
   pytest tests/ -v
   ```

## 📝 How to Contribute

### Reporting Bugs

- Use the GitHub Issues page
- Include Python version, OS, and full error traceback
- Provide steps to reproduce the issue
- Include relevant testbed configuration (sanitized)

### Suggesting Features

- Open a GitHub Issue with the "enhancement" label
- Describe the use case and expected behavior
- Explain why this would benefit other users

### Submitting Code

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests and linting**
   ```bash
   pytest tests/ -v
   mypy src/netcertify
   ```

4. **Commit with clear messages**
   ```bash
   git commit -m "feat: add bandwidth utilization certification test"
   ```

5. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## 🧪 Adding New Certification Tests

1. Create a new file in `src/netcertify/certifications/`
2. Inherit from `BaseCertificationTest`
3. Implement the `run()` method
4. Add to `__init__.py` exports
5. Add unit tests in `tests/test_certifications.py`

Example:
```python
from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity

class NewCertificationTest(BaseCertificationTest):
    name = "New Test Name"
    description = "What this test validates"
    category = "category"
    tags = ["tag1", "tag2"]
    
    def run(self):
        with self.engine.step("Step Name"):
            # Your validation logic
            self.engine.assert_true(
                "Assertion Name",
                condition,
                severity=Severity.HIGH,
                reason="Why this might fail",
                remediation="How to fix it"
            )
```

## 🔌 Adding New Vendor Adapters

1. Create a new directory in `src/netcertify/adapters/`
2. Inherit from `BaseFirewallAdapter`
3. Implement all abstract methods
4. Register in `AdapterRegistry`
5. Add comprehensive tests

## 📋 Code Style Guidelines

- Use type hints for all function parameters and returns
- Use Pydantic models for all structured data
- Write docstrings for public classes and methods
- Keep functions focused and under 50 lines
- Use meaningful variable names

## ✅ Pull Request Checklist

- [ ] All tests pass (`pytest tests/ -v`)
- [ ] Code follows existing style
- [ ] New functionality has tests
- [ ] Documentation is updated
- [ ] Commit messages are clear

## 📞 Questions?

Open a GitHub Issue or Discussion for any questions!

Thank you for contributing! 🎉
