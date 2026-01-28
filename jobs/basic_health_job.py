"""
Basic Health Check Job - Quick certification for core functionality.

Runs a subset of critical tests for rapid validation.

Usage:
    pyats run job jobs/basic_health_job.py --testbed testbeds/testbed.yaml
"""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pyats.easypy import run
from netcertify.orchestrator.runner import CertificationRunner
from netcertify.certifications import BASIC_TESTS


def main(runtime):
    """Execute basic health certification."""
    testbed_path = os.environ.get(
        'TESTBED_FILE',
        os.path.join(os.path.dirname(__file__), '..', 'testbeds', 'mock_lab.yaml')
    )
    
    runner = CertificationRunner(name="Basic Health Check")
    runner.load_testbed(testbed_path)
    runner.add_test_classes(BASIC_TESTS)
    
    report = runner.run()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(
        os.path.dirname(__file__),
        '..',
        'output',
        f'health_check_{timestamp}.html'
    )
    
    runner.generate_report(report, report_path)
    
    runtime.logger.info(f"Health Check: {report.overall_status.value}")
    runtime.logger.info(f"Report: {report_path}")
    
    return report.overall_status.value == "passed"


if __name__ == '__main__':
    pass
