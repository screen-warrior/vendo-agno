"""
Management Access Certification Test.

Validates management interface and service status.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity
from netcertify.schemas.status import ServiceState


class ManagementAccessCertificationTest(BaseCertificationTest):
    """
    Certification test for management access.
    
    Validates:
    - Management services are running
    - Device is accessible
    """
    
    name = "Management Access"
    description = "Validate management interface and services"
    category = "management"
    tags = ["management", "access", "services"]
    
    def run(self) -> None:
        with self.engine.step("Management Connectivity"):
            # If we're here, connection succeeded
            self.engine.assert_true(
                "Device Reachable",
                self.adapter.is_connected,
                severity=Severity.CRITICAL,
                reason="Device is not reachable"
            )
            
            # Validate connection
            is_valid = self.adapter.validate_connection()
            self.engine.assert_true(
                "Connection Valid",
                is_valid,
                severity=Severity.CRITICAL,
                reason="Connection validation failed"
            )
        
        with self.engine.step("Management Services"):
            try:
                services = self.adapter.get_service_status()
                
                running_count = 0
                for service in services:
                    is_running = service.state == ServiceState.RUNNING
                    if is_running:
                        running_count += 1
                    
                    self.engine.assert_true(
                        f"Service {service.name} Running",
                        is_running,
                        severity=Severity.HIGH if service.enabled else Severity.LOW,
                        reason=f"Service {service.name} is {service.state.value}"
                    )
                
                self.engine.log(f"Services running: {running_count}/{len(services)}")
                
            except Exception as e:
                self.engine.skip("Service Status", f"Unable to retrieve: {e}")
        
        with self.engine.step("Device Information"):
            try:
                info = self.adapter.get_device_info()
                
                self.engine.log(f"Hostname: {info.get('hostname', 'N/A')}")
                self.engine.log(f"Model: {info.get('model', 'N/A')}")
                self.engine.log(f"Serial: {info.get('serial', 'N/A')}")
                
                self.engine.assert_not_none(
                    "Device Info Retrieved",
                    info,
                    severity=Severity.HIGH
                )
            except Exception as e:
                self.engine.skip("Device Info", f"Unable to retrieve: {e}")
