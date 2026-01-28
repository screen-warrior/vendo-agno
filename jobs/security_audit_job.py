"""
Security Audit Job - Security-focused certification tests.

Validates security policies, threat prevention, and compliance.

Usage:
    pyats run job jobs/security_audit_job.py --testbed testbeds/testbed.yaml
"""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pyats.easypy import run
from netcertify.orchestrator.runner import CertificationRunner
from netcertify.certifications import SECURITY_TESTS


def main(runtime):
    """Execute security audit certification."""
    testbed_path = os.environ.get(
        'TESTBED_FILE',
        os.path.join(os.path.dirname(__file__), '..', 'testbeds', 'mock_lab.yaml')
    )
    
    runner = CertificationRunner(name="Security Audit")
    runner.load_testbed(testbed_path)
    runner.add_test_classes(SECURITY_TESTS)
    
    report = runner.run()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(
        os.path.dirname(__file__),
        '..',
        'output',
        f'security_audit_{timestamp}.html'
    )
    
    runner.generate_report(report, report_path)
    
    runtime.logger.info(f"Security Audit: {report.overall_status.value}")
    runtime.logger.info(f"Report: {report_path}")
    
    return report.overall_status.value == "passed"


if __name__ == '__main__':
    pass
