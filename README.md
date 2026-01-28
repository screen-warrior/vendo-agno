# 🔥 NetCertify

### Enterprise Firewall Certification Automation Framework

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Pydantic v2](https://img.shields.io/badge/pydantic-v2-green.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/tests-70%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**NetCertify** is an enterprise-grade, vendor-agnostic firewall certification automation framework inspired by professional network automation platforms like Cisco PyATS. It automates device certification, compliance validation, and operational readiness testing across multiple firewall vendors.

<p align="center">
  <img src="https://img.shields.io/badge/Palo%20Alto-Supported-blue?style=for-the-badge&logo=paloaltonetworks" alt="Palo Alto"/>
  <img src="https://img.shields.io/badge/Fortinet-Supported-red?style=for-the-badge&logo=fortinet" alt="Fortinet"/>
  <img src="https://img.shields.io/badge/Mock-Testing-gray?style=for-the-badge" alt="Mock"/>
</p>

---

## ✨ Features

- **🔌 Vendor-Agnostic Architecture** - Unified interface for Palo Alto, Fortinet, and extensible to other vendors
- **📊 Type-Safe Data Flow** - All data modeled with Pydantic v2 for validation and documentation
- **🧪 17+ Certification Tests** - Pre-built tests covering NTP, HA, Security, VPN, Licensing, and more
- **📄 Interactive HTML Reports** - Professional, audit-ready certification reports
- **🎭 Mock Adapter** - Test framework logic without real hardware
- **🔗 PyATS Integration** - Full support for Cisco PyATS job orchestration
- **✅ 70 Unit Tests** - Comprehensive test coverage

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/screen-warrior/vendo-agno.git
cd vendo-agno

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .

# Or install with all optional dependencies
pip install -e ".[all]"
```

### Run Tests to Verify Installation

```bash
# Run all 70 unit tests
pytest tests/ -v

# Expected output: 70 passed
```

### Generate Your First Report

```python
from netcertify.orchestrator.runner import CertificationRunner
from netcertify.certifications import BASIC_TESTS

# Create runner and load mock testbed (no real devices needed!)
runner = CertificationRunner(name="My First Certification")
runner.load_testbed("testbeds/mock_lab.yaml")
runner.add_test_classes(BASIC_TESTS)

# Run certification
report = runner.run()

# Generate HTML report
runner.generate_report(report, "output/my_report.html")

print(f"✅ Status: {report.overall_status.value}")
print(f"📊 Pass Rate: {report.overall_pass_rate:.1f}%")
```

Then open `output/my_report.html` in your browser!

---

## 📁 Project Structure

```
vendo-agno/
├── src/netcertify/              # Main package
│   ├── schemas/                  # Pydantic data models
│   │   ├── device.py            # Device, credentials, connections
│   │   ├── configuration.py     # NTP, DNS, interfaces, policies
│   │   ├── status.py            # Runtime status models
│   │   └── results.py           # Test results, reports
│   │
│   ├── adapters/                 # Vendor-specific drivers
│   │   ├── base.py              # Abstract base (50+ methods)
│   │   ├── registry.py          # Adapter factory
│   │   ├── mock/                # Mock adapter for testing
│   │   ├── paloalto/            # Palo Alto (pan-os-python)
│   │   └── fortinet/            # FortiGate (fortigate-api)
│   │
│   ├── validators/               # Assertion framework
│   │   ├── engine.py            # Validation engine
│   │   └── rules.py             # 12+ reusable rules
│   │
│   ├── reporters/                # Report generation
│   │   └── html_generator.py    # Interactive HTML reports
│   │
│   ├── orchestrator/             # Test orchestration
│   │   ├── loader.py            # YAML testbed parser
│   │   └── runner.py            # Test execution engine
│   │
│   └── certifications/           # 17 certification tests
│       ├── ntp_sync.py
│       ├── interface_status.py
│       ├── ha_status.py
│       ├── system_health.py
│       └── ... (13 more)
│
├── jobs/                         # PyATS job files
├── testbeds/                     # YAML testbed configs
├── tests/                        # 70 unit/integration tests
├── output/                       # Generated reports
├── requirements.txt
├── setup.py
└── README.md
```

---

## 🧪 Available Certification Tests

| Category | Test | Description |
|----------|------|-------------|
| **Time** | NTP Synchronization | Validates NTP config, sync status, peer reachability |
| **Network** | Interface Status | Checks link state, error counters, drop rates |
| **Network** | Routing Validation | Verifies default route, active routes |
| **Network** | DNS Configuration | Validates resolver configuration |
| **Availability** | HA Status | Checks peer connectivity, synchronization |
| **Availability** | VPN Tunnel Status | Validates IPsec tunnel establishment |
| **Health** | System Health | Monitors CPU, memory, disk, temperature |
| **Health** | Session Table | Checks session utilization and capacity |
| **Security** | Security Policy | Validates default deny, logging, permissions |
| **Security** | Threat Prevention | Checks AV, IPS, URL filtering, signatures |
| **Security** | Certificate Validity | Monitors expiration and key strength |
| **Compliance** | License Compliance | Validates license validity and expiration |
| **Compliance** | Firmware Compliance | Checks version requirements |
| **Compliance** | Logging Configuration | Validates syslog and audit settings |
| **Management** | SNMP Configuration | Verifies secure SNMP settings |
| **Management** | Management Access | Validates connectivity and services |

---

## 📋 Testbed Configuration

Create a YAML testbed file to define your devices:

```yaml
# testbeds/my_testbed.yaml
testbed:
  name: Production Firewalls

devices:
  pa-firewall-01:
    vendor: paloalto
    model: PA-5220
    
    credentials:
      default:
        username: admin
        password: ${FIREWALL_PASSWORD}  # Use environment variable
    
    connections:
      default:
        host: 192.168.1.1
        port: 443
        verify_ssl: true
    
    environment: production
    tags:
      - primary
      - east-coast

  fg-firewall-01:
    vendor: fortinet
    model: FortiGate-3000D
    
    credentials:
      default:
        username: admin
        password: ${FORTIGATE_PASSWORD}
    
    connections:
      default:
        host: 192.168.2.1
        port: 443
```

---

## 🎯 Usage Examples

### Run All Certification Tests

```python
from netcertify.orchestrator.runner import CertificationRunner
from netcertify.certifications import ALL_TESTS

runner = CertificationRunner(name="Full Certification")
runner.load_testbed("testbeds/production.yaml")
runner.add_test_classes(ALL_TESTS)

report = runner.run()
runner.generate_report(report, "output/full_certification.html")
```

### Run Specific Test Categories

```python
from netcertify.certifications import (
    BASIC_TESTS,      # NTP, Interfaces, System Health
    SECURITY_TESTS,   # Security Policy, Threat Prevention, Certificates
    NETWORK_TESTS,    # Interfaces, Routing, VPN, DNS
    COMPLIANCE_TESTS, # License, Firmware, Logging, SNMP
)

runner.add_test_classes(SECURITY_TESTS)
```

### Run Tests on Specific Devices

```python
# Only test specific devices
report = runner.run(devices=["pa-firewall-01", "fg-firewall-01"])

# Only run specific tests
report = runner.run(tests=["NTP Synchronization", "System Health"])
```

### Using PyATS Jobs

```bash
# Full certification
pyats run job jobs/full_certification_job.py --testbed testbeds/my_testbed.yaml

# Quick health check
pyats run job jobs/basic_health_job.py --testbed testbeds/my_testbed.yaml

# Security audit
pyats run job jobs/security_audit_job.py --testbed testbeds/my_testbed.yaml
```

---

## 🛠️ Creating Custom Tests

Extend the framework with your own certification tests:

```python
from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity

class CustomBandwidthTest(BaseCertificationTest):
    name = "Bandwidth Utilization"
    description = "Check interface bandwidth usage"
    category = "performance"
    tags = ["bandwidth", "performance"]
    
    def run(self):
        interfaces = self.adapter.get_interface_status()
        
        with self.engine.step("Bandwidth Check"):
            for iface in interfaces:
                # Your custom validation logic
                self.engine.assert_less_than(
                    f"Interface {iface.name} Utilization",
                    iface.rx_bytes / 1e9,  # GB
                    100,  # threshold
                    severity=Severity.MEDIUM,
                    reason="High bandwidth utilization detected",
                    remediation="Consider upgrading link capacity"
                )
```

---

## 📊 Sample Report Output

The HTML report includes:

- **📈 Executive Summary** - Overall status and key metrics
- **🔢 Statistics Grid** - Devices tested, pass/fail counts
- **📉 Progress Bar** - Visual pass rate indicator
- **⚠️ Critical Findings** - Highlighted failures requiring attention
- **🔍 Detailed Results** - Expandable test results with assertion details

Reports are standalone HTML files - no external dependencies, easy to share!

---

## 🔧 Installation Options

```bash
# Basic installation (mock adapter only)
pip install -e .

# With Palo Alto support
pip install -e ".[paloalto]"

# With Fortinet support
pip install -e ".[fortinet]"

# With PyATS integration
pip install -e ".[pyats]"

# Full installation (all vendors + PyATS)
pip install -e ".[all]"

# Development installation (includes pytest, mypy)
pip install -e ".[dev]"
```

---

## 🧪 Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=src/netcertify --cov-report=html

# Run specific test file
pytest tests/test_schemas.py -v

# Run only fast unit tests
pytest tests/test_schemas.py tests/test_validators.py -v
```

---

## 📚 API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `CertificationRunner` | Main orchestrator for running tests |
| `TestbedLoader` | Parses YAML testbed files |
| `ValidationEngine` | Executes assertions and collects results |
| `HTMLReportGenerator` | Generates interactive HTML reports |
| `BaseFirewallAdapter` | Abstract base for vendor adapters |

### Pydantic Models

| Model | Description |
|-------|-------------|
| `DeviceInfo` | Complete device metadata |
| `DeviceCredentials` | Secure credential storage |
| `ConnectionParams` | Network connection parameters |
| `TestResult` | Individual test results |
| `CertificationReport` | Complete report with all results |

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by [Cisco PyATS](https://developer.cisco.com/docs/pyats/)
- Built with [Pydantic](https://docs.pydantic.dev/)
- Vendor SDKs: [pan-os-python](https://pan-os-python.readthedocs.io/), [fortigate-api](https://github.com/vladimirs-git/fortigate-api)

---

<p align="center">
  Made with ❤️ for Network Engineers
</p>
