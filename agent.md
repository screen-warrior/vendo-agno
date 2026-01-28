this prompt is explaining what we are trying to accomplish, you do not need to use the file schema and the directory scema below at all, you should actually come up with a different directory schema and names for files, below is jsut a reference it should not match, also you are a senior software engineer, you have 15 plus years experience and you will code this project with that experience in mind, you are coding for a enterprise grade software, you will code and test and make sure each component is working as your coding, the final product should have test cases as well to test out the main components of this project and they should run and work.

Design and implement an enterprise-grade, vendor-agnostic firewall certification automation framework, inspired by professional network automation platforms such as Cisco PyATS.

The framework must automate device certification, compliance validation, and operational readiness testing across multiple firewall vendors (initially Palo Alto and Fortinet), using a unified interface, repeatable test flows, rich reporting, and extensive use of Pydantic models for all data exchange.

This system should resemble the kind of scalable, maintainable automation infrastructure used by large network engineering teams and vendors.

Core Objectives

Vendor-Agnostic Automation

Abstract all firewall operations behind a unified interface.

Test logic must not contain vendor-specific code.

Vendor differences are handled exclusively via drivers.

Automated Certification Testing

Encode certification workflows (e.g., NTP sync validation) as automated, repeatable test suites.

Support multi-step flows such as:

Configure

Validate

Break

Recover

Re-validate

Extensibility & Modularity

New vendors can be added by implementing a common interface.

New certification tests can be added without modifying core logic.

Architecture must support growth in vendors, test types, and features.

Heavy Use of Pydantic Models (Mandatory)

All structured data must be represented using Pydantic models, including but not limited to:

Device metadata

Credentials and connection parameters

Test inputs and expected outcomes

Firewall configurations (e.g., NTP, interfaces, policies)

Runtime status and health data

Assertion results and failure reasons

Test execution summaries and report artifacts

Pydantic models must:

Enforce strict typing and validation

Define clear data contracts between components

Be reusable across drivers, tests, assertions, and reporting

Raw dictionaries or loosely typed data should be avoided except at system boundaries.

Type-Safe Data Flow

All data passed between:

Drivers

Test steps

Assertion framework

Reporting engine
must be strongly typed via Pydantic models.

Validation errors should be surfaced early and explicitly.

Rich Reporting & Traceability

Generate interactive HTML reports.

Reports must be backed by structured Pydantic result models capturing:

Test steps

Assertions

Pass/fail status

Timing

Failure context

Device interaction traces

Reports must be suitable for audits and compliance documentation.

Industry-Standard Automation Integration

Use PyATS for:

Job orchestration

Test execution

YAML-based testbed definitions

YAML inputs should be parsed into Pydantic models before use.

Assertion Framework

Every validation must use a centralized assertion system.

Assertion inputs and outputs must be represented as Pydantic models.

Each assertion must capture:

Expected vs actual values

Result (pass/fail)

Reason and contextual metadata

Separation of Concerns

Core logic must be isolated from vendor logic and test logic.

Data models must live in a dedicated models layer and be shared across the system.

Technology Stack

Python 3.8+

PyATS – test orchestration and execution

Pydantic – primary mechanism for:

Data modeling

Validation

Inter-module contracts

Vendor SDKs

Palo Alto: pan-os-python

Fortinet: fortigate_api

YAML – testbed and configuration input (parsed into Pydantic models)

HTML / CSS / JavaScript – report generation

Project Structure
src/firewall_certification/
├── core/
│   ├── models/          # Extensive Pydantic models (configs, statuses, results)
│   ├── interfaces/      # Abstract base classes
│   ├── assertions/      # Assertion framework (Pydantic-driven)
│   └── reporting/       # Report generation (model-backed)
│
├── drivers/
│   ├── paloalto/
│   ├── fortinet/
│   ├── mock/
│   └── factory.py
│
├── tests/
│   └── ntp/
│
├── jobs/
├── testbeds/
├── reports/
├── generate_mock_report.py
├── requirements.txt
└── README.md

Execution Flow (Type-Safe)

YAML Testbed → Pydantic Models

Parse device definitions into validated models

Job Execution

pyats run job jobs/ntp_certification_job.py --testbed testbeds/testbed.yaml


Driver Instantiation

Vendor detected via model metadata

Driver created via factory

Unified API Interaction

Drivers return structured Pydantic models

No raw vendor responses leak upward

Assertions

Compare model-to-model (expected vs actual)

Persist assertion results as models

Reporting

Reports rendered from structured result models

Expected Outcome

A production-quality firewall certification framework that:

Uses Pydantic everywhere it makes sense

Avoids untyped dictionaries and ad-hoc schemas

Is vendor-agnostic, extensible, and auditable

Produces traceable, model-backed test reports

Mirrors real-world enterprise network automation platforms

Optional (If the Agent Supports It)

Prefer composition of models over deeply nested dicts

Use BaseModel configs with Config(extra="forbid")

Centralize shared models (e.g., DeviceInfo, TestResult, AssertionResult)

Validate vendor SDK outputs before consuming them

If you want next, I can:

🔹 Define exact Pydantic model schemas to start with

🔹 Provide a reference models/ package layout

🔹 Convert this into incremental AI build steps

🔹 Rewrite this as a Cursor / Copilot / Claude system prompt

Just tell me the next move.