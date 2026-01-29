#!/usr/bin/env python3
"""
NetCertify - Run Certification Tests
=====================================

Usage:
    python run_certification.py                    # Run basic tests
    python run_certification.py --all              # Run all 17 tests
    python run_certification.py --security         # Run security tests only
    python run_certification.py --testbed custom.yaml  # Use custom testbed
"""

import argparse
import os
import webbrowser
from datetime import datetime

from netcertify.orchestrator.runner import CertificationRunner
from netcertify.certifications import (
    ALL_TESTS,
    BASIC_TESTS,
    SECURITY_TESTS,
    NETWORK_TESTS,
    COMPLIANCE_TESTS,
)


def main():
    parser = argparse.ArgumentParser(description="Run NetCertify firewall certification tests")
    parser.add_argument("--all", action="store_true", help="Run all 17 certification tests")
    parser.add_argument("--security", action="store_true", help="Run security-focused tests")
    parser.add_argument("--network", action="store_true", help="Run network-focused tests")
    parser.add_argument("--compliance", action="store_true", help="Run compliance-focused tests")
    parser.add_argument("--testbed", default="testbeds/mock_lab.yaml", help="Path to testbed YAML file")
    parser.add_argument("--output", default=None, help="Output report path")
    parser.add_argument("--no-open", action="store_true", help="Don't auto-open the report in browser")
    
    args = parser.parse_args()
    
    # Select test suite
    if args.all:
        tests = ALL_TESTS
        suite_name = "Full Certification"
    elif args.security:
        tests = SECURITY_TESTS
        suite_name = "Security Audit"
    elif args.network:
        tests = NETWORK_TESTS
        suite_name = "Network Validation"
    elif args.compliance:
        tests = COMPLIANCE_TESTS
        suite_name = "Compliance Check"
    else:
        tests = BASIC_TESTS
        suite_name = "Basic Health Check"
    
    # Generate output filename with timestamp
    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"output/certification_{timestamp}.html"
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    print(f"\n{'='*60}")
    print(f"  NetCertify - {suite_name}")
    print(f"{'='*60}")
    print(f"  Testbed: {args.testbed}")
    print(f"  Tests:   {len(tests)} certification tests")
    print(f"  Output:  {output_path}")
    print(f"{'='*60}\n")
    
    # Create and configure runner
    runner = CertificationRunner(name=suite_name)
    runner.load_testbed(args.testbed)
    runner.add_test_classes(tests)
    
    # Run certification
    print("Running certification tests...\n")
    report = runner.run()
    
    # Generate report
    runner.generate_report(report, output_path)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"  CERTIFICATION COMPLETE")
    print(f"{'='*60}")
    print(f"  Status:     {report.overall_status.value.upper()}")
    print(f"  Pass Rate:  {report.overall_pass_rate:.1f}%")
    print(f"  Tests:      {report.passed_tests}/{report.total_tests} passed")
    print(f"  Devices:    {report.total_devices}")
    print(f"  Duration:   {report.total_duration_ms/1000:.2f}s")
    print(f"{'='*60}")
    print(f"  Report:     {os.path.abspath(output_path)}")
    print(f"{'='*60}\n")
    
    # Open report in browser
    if not args.no_open:
        abs_path = os.path.abspath(output_path)
        print(f"Opening report in browser...")
        webbrowser.open(f"file://{abs_path}")
    
    return 0 if report.overall_status.value == "passed" else 1


if __name__ == "__main__":
    exit(main())
