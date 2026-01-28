"""
System Health Certification Test.

Validates system resource utilization and health status.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity


class SystemHealthCertificationTest(BaseCertificationTest):
    """
    Certification test for system health.
    
    Validates:
    - CPU utilization within acceptable bounds
    - Memory utilization within acceptable bounds
    - Disk utilization within acceptable bounds
    - System uptime is stable
    - Environmental conditions (temperature, power, fans)
    """
    
    name = "System Health"
    description = "Validate system resource utilization and health"
    category = "health"
    tags = ["health", "resources", "cpu", "memory", "disk", "baseline"]
    
    # Thresholds
    CPU_WARNING_THRESHOLD = 70.0
    CPU_CRITICAL_THRESHOLD = 90.0
    MEMORY_WARNING_THRESHOLD = 80.0
    MEMORY_CRITICAL_THRESHOLD = 95.0
    DISK_WARNING_THRESHOLD = 80.0
    DISK_CRITICAL_THRESHOLD = 95.0
    MIN_UPTIME_SECONDS = 3600  # 1 hour minimum stable uptime
    MAX_TEMPERATURE_CELSIUS = 75.0
    
    def run(self) -> None:
        """Execute system health certification tests."""
        
        if self.skip_if_unsupported("supports_system_health", "System Health Check"):
            return
        
        health = self.adapter.get_system_health()
        
        with self.engine.step("CPU Utilization"):
            # Critical CPU check
            self.engine.assert_less_than(
                "CPU Utilization Critical",
                health.cpu_utilization_percent,
                self.CPU_CRITICAL_THRESHOLD,
                severity=Severity.CRITICAL,
                reason=f"CPU at {health.cpu_utilization_percent:.1f}% exceeds critical threshold",
                remediation="Investigate high CPU processes and consider hardware upgrade"
            )
            
            # Warning CPU check
            self.engine.assert_less_than(
                "CPU Utilization Warning",
                health.cpu_utilization_percent,
                self.CPU_WARNING_THRESHOLD,
                severity=Severity.MEDIUM,
                reason=f"CPU at {health.cpu_utilization_percent:.1f}% exceeds warning threshold"
            )
            
            self.engine.log(f"CPU utilization: {health.cpu_utilization_percent:.1f}%")
        
        with self.engine.step("Memory Utilization"):
            mem_percent = health.memory_utilization_percent
            
            # Critical memory check
            self.engine.assert_less_than(
                "Memory Utilization Critical",
                mem_percent,
                self.MEMORY_CRITICAL_THRESHOLD,
                severity=Severity.CRITICAL,
                reason=f"Memory at {mem_percent:.1f}% exceeds critical threshold",
                remediation="Free up memory or increase system RAM"
            )
            
            # Warning memory check
            self.engine.assert_less_than(
                "Memory Utilization Warning",
                mem_percent,
                self.MEMORY_WARNING_THRESHOLD,
                severity=Severity.MEDIUM,
                reason=f"Memory at {mem_percent:.1f}% exceeds warning threshold"
            )
            
            self.engine.log(
                f"Memory: {health.memory_used_mb}MB / {health.memory_total_mb}MB "
                f"({mem_percent:.1f}%)"
            )
        
        with self.engine.step("Disk Utilization"):
            disk_percent = health.disk_utilization_percent
            
            # Critical disk check
            self.engine.assert_less_than(
                "Disk Utilization Critical",
                disk_percent,
                self.DISK_CRITICAL_THRESHOLD,
                severity=Severity.CRITICAL,
                reason=f"Disk at {disk_percent:.1f}% exceeds critical threshold",
                remediation="Clean up logs and temporary files"
            )
            
            # Warning disk check
            self.engine.assert_less_than(
                "Disk Utilization Warning",
                disk_percent,
                self.DISK_WARNING_THRESHOLD,
                severity=Severity.MEDIUM,
                reason=f"Disk at {disk_percent:.1f}% exceeds warning threshold"
            )
            
            self.engine.log(
                f"Disk: {health.disk_used_gb:.1f}GB / {health.disk_total_gb:.1f}GB "
                f"({disk_percent:.1f}%)"
            )
        
        with self.engine.step("System Uptime"):
            uptime_days = health.uptime_days
            
            self.engine.assert_greater_than(
                "Minimum Uptime",
                health.uptime_seconds,
                self.MIN_UPTIME_SECONDS,
                severity=Severity.LOW,
                reason=f"System uptime is only {uptime_days:.1f} days - may indicate recent reboot"
            )
            
            self.engine.log(f"System uptime: {uptime_days:.1f} days")
        
        with self.engine.step("Environmental Status"):
            # Temperature check
            if health.temperature_celsius is not None:
                self.engine.assert_less_than(
                    "System Temperature",
                    health.temperature_celsius,
                    self.MAX_TEMPERATURE_CELSIUS,
                    severity=Severity.HIGH,
                    reason=f"Temperature {health.temperature_celsius}°C exceeds threshold",
                    remediation="Check cooling systems and ambient temperature"
                )
            
            # Power status
            if health.power_status:
                self.engine.assert_equals(
                    "Power Status",
                    health.power_status.lower(),
                    "normal",
                    severity=Severity.HIGH,
                    reason=f"Power status is {health.power_status}"
                )
            
            # Fan status
            if health.fan_status:
                self.engine.assert_equals(
                    "Fan Status",
                    health.fan_status.lower(),
                    "normal",
                    severity=Severity.MEDIUM,
                    reason=f"Fan status is {health.fan_status}"
                )
