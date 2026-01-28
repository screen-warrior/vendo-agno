"""
Session Table Certification Test.

Validates session table utilization and capacity.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity


class SessionTableCertificationTest(BaseCertificationTest):
    """
    Certification test for session table status.
    
    Validates:
    - Session utilization within bounds
    - Not approaching capacity limits
    """
    
    name = "Session Table Status"
    description = "Validate session table utilization"
    category = "performance"
    tags = ["sessions", "connections", "capacity", "performance"]
    
    WARNING_THRESHOLD = 70.0
    CRITICAL_THRESHOLD = 90.0
    
    def run(self) -> None:
        if self.skip_if_unsupported("supports_session_table", "Session Table Check"):
            return
        
        session_status = self.adapter.get_session_table_status()
        
        with self.engine.step("Session Table Utilization"):
            utilization = session_status.utilization_percent
            
            self.engine.assert_less_than(
                "Session Table Critical",
                utilization,
                self.CRITICAL_THRESHOLD,
                severity=Severity.CRITICAL,
                reason=f"Session table at {utilization:.1f}% capacity",
                remediation="Review session limits or scale hardware"
            )
            
            self.engine.assert_less_than(
                "Session Table Warning",
                utilization,
                self.WARNING_THRESHOLD,
                severity=Severity.MEDIUM,
                reason=f"Session table at {utilization:.1f}% capacity"
            )
            
            self.engine.log(
                f"Sessions: {session_status.active_sessions:,} / "
                f"{session_status.max_sessions:,} ({utilization:.1f}%)"
            )
            
            if session_status.sessions_per_second > 0:
                self.engine.log(f"CPS: {session_status.sessions_per_second:,}")
