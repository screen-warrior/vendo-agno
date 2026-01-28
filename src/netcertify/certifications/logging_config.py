"""
Logging Configuration Certification Test.

Validates logging and syslog configuration.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity


class LoggingCertificationTest(BaseCertificationTest):
    """
    Certification test for logging configuration.
    
    Validates:
    - Logging is enabled
    - Syslog forwarding configured
    - Appropriate log types enabled
    """
    
    name = "Logging Configuration"
    description = "Validate logging and syslog settings"
    category = "compliance"
    tags = ["logging", "syslog", "audit", "compliance"]
    
    def run(self) -> None:
        if self.skip_if_unsupported("supports_logging", "Logging Check"):
            return
        
        logging_config = self.adapter.get_logging_configuration()
        
        with self.engine.step("Local Logging"):
            self.engine.assert_true(
                "Local Logging Enabled",
                logging_config.local_log_enabled,
                severity=Severity.MEDIUM,
                reason="Local logging should be enabled"
            )
        
        with self.engine.step("Syslog Configuration"):
            self.engine.assert_true(
                "Syslog Forwarding Enabled",
                logging_config.syslog_enabled,
                severity=Severity.HIGH,
                reason="Syslog forwarding required for centralized logging",
                remediation="Configure syslog server for log aggregation"
            )
            
            if logging_config.syslog_enabled:
                self.engine.assert_greater_than(
                    "Syslog Servers Configured",
                    len(logging_config.syslog_servers),
                    0,
                    severity=Severity.HIGH,
                    reason="No syslog servers configured"
                )
                
                for server in logging_config.syslog_servers:
                    self.engine.log(f"Syslog server: {server}")
        
        with self.engine.step("Log Types Enabled"):
            self.engine.assert_true(
                "Traffic Logging Enabled",
                logging_config.traffic_log_enabled,
                severity=Severity.MEDIUM,
                reason="Traffic logging recommended for audit"
            )
            
            self.engine.assert_true(
                "Threat Logging Enabled",
                logging_config.threat_log_enabled,
                severity=Severity.HIGH,
                reason="Threat logging required for security monitoring"
            )
            
            self.engine.assert_true(
                "Config Logging Enabled",
                logging_config.config_log_enabled,
                severity=Severity.MEDIUM,
                reason="Configuration change logging required for audit"
            )
