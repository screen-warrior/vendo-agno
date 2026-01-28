"""
Full Certification Job - PyATS job file for complete certification testing.

Execute all certification tests against all devices in testbed.

Usage:
    pyats run job jobs/full_certification_job.py --testbed testbeds/testbed.yaml
"""

import os
import sys
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pyats.easypy import run

# Import NetCertify components
from netcertify.orchestrator.runner import CertificationRunner
from netcertify.certifications import ALL_TESTS


def main(runtime):
    """
    Main job execution function.
    
    Args:
        runtime: PyATS runtime object with testbed information
    """
    # Get testbed path from runtime
    testbed_path = runtime.testbed.name if hasattr(runtime.testbed, 'name') else None
    
    if not testbed_path:
        # Look for testbed file
        testbed_path = os.environ.get(
            'TESTBED_FILE',
            os.path.join(os.path.dirname(__file__), '..', 'testbeds', 'mock_lab.yaml')
        )
    
    # Create certification runner
    runner = CertificationRunner(name="Full Certification Suite")
    
    # Load testbed
    runner.load_testbed(testbed_path)
    
    # Add all certification tests
    runner.add_test_classes(ALL_TESTS)
    
    # Run certification
    report = runner.run()
    
    # Generate report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(
        os.path.dirname(__file__), 
        '..', 
        'output',
        f'certification_report_{timestamp}.html'
    )
    
    runner.generate_report(report, report_path)
    
    # Log summary
    runtime.logger.info(f"Certification Complete: {report.overall_status.value}")
    runtime.logger.info(f"Pass Rate: {report.overall_pass_rate:.1f}%")
    runtime.logger.info(f"Report: {report_path}")
    
    # Return pass/fail for PyATS
    return report.overall_status.value == "passed"


# PyATS job file must have this
if __name__ == '__main__':
    pass
