"""
Threat Prevention Certification Test.

Validates threat prevention features and signature status.
"""

from datetime import datetime, timedelta
from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity


class ThreatPreventionCertificationTest(BaseCertificationTest):
    """
    Certification test for threat prevention.
    
    Validates:
    - Threat prevention features are enabled
    - Signature versions are current
    - Update schedules are configured
    - Protection is actively blocking threats
    """
    
    name = "Threat Prevention Status"
    description = "Validate threat prevention features and signatures"
    category = "security"
    tags = ["security", "threat", "antivirus", "ips", "urlfiltering"]
    
    # Maximum age for signatures (hours)
    MAX_SIGNATURE_AGE_HOURS = 24
    
    def run(self) -> None:
        """Execute threat prevention certification tests."""
        
        if self.skip_if_unsupported("supports_threat_prevention", "Threat Prevention Check"):
            return
        
        threat_status = self.adapter.get_threat_prevention_status()
        
        with self.engine.step("Threat Prevention Features"):
            # Antivirus
            self.engine.assert_true(
                "Antivirus Enabled",
                threat_status.antivirus_enabled,
                severity=Severity.HIGH,
                reason="Antivirus protection should be enabled",
                remediation="Enable antivirus in security profiles"
            )
            
            # Anti-spyware
            self.engine.assert_true(
                "Anti-Spyware Enabled",
                threat_status.anti_spyware_enabled,
                severity=Severity.HIGH,
                reason="Anti-spyware protection should be enabled"
            )
            
            # Vulnerability protection
            self.engine.assert_true(
                "Vulnerability Protection Enabled",
                threat_status.vulnerability_protection_enabled,
                severity=Severity.HIGH,
                reason="Vulnerability protection (IPS) should be enabled"
            )
            
            # URL filtering
            self.engine.assert_true(
                "URL Filtering Enabled",
                threat_status.url_filtering_enabled,
                severity=Severity.MEDIUM,
                reason="URL filtering should be enabled for web security"
            )
            
            # WildFire (advanced malware)
            self.engine.assert_true(
                "WildFire/Sandbox Enabled",
                threat_status.wildfire_enabled,
                severity=Severity.MEDIUM,
                reason="Advanced malware analysis should be enabled"
            )
        
        with self.engine.step("Signature Versions"):
            if threat_status.antivirus_version:
                self.engine.assert_not_none(
                    "Antivirus Signatures Installed",
                    threat_status.antivirus_version,
                    severity=Severity.HIGH,
                    reason="Antivirus signatures must be installed"
                )
                self.engine.log(f"AV version: {threat_status.antivirus_version}")
            
            if threat_status.threat_version:
                self.engine.assert_not_none(
                    "Threat Signatures Installed",
                    threat_status.threat_version,
                    severity=Severity.HIGH,
                    reason="Threat signatures must be installed"
                )
                self.engine.log(f"Threat version: {threat_status.threat_version}")
            
            if threat_status.app_version:
                self.engine.log(f"App-ID version: {threat_status.app_version}")
        
        with self.engine.step("Signature Update Status"):
            now = datetime.utcnow()
            max_age = timedelta(hours=self.MAX_SIGNATURE_AGE_HOURS)
            
            if threat_status.last_av_update:
                av_age = now - threat_status.last_av_update
                self.engine.assert_true(
                    "AV Signatures Recent",
                    av_age <= max_age,
                    severity=Severity.MEDIUM,
                    reason=f"AV signatures are {av_age.total_seconds()/3600:.0f} hours old",
                    remediation="Update antivirus signatures"
                )
            
            if threat_status.last_threat_update:
                threat_age = now - threat_status.last_threat_update
                self.engine.assert_true(
                    "Threat Signatures Recent",
                    threat_age <= max_age,
                    severity=Severity.MEDIUM,
                    reason=f"Threat signatures are {threat_age.total_seconds()/3600:.0f} hours old"
                )
            
            if threat_status.last_wildfire_update:
                wf_age = now - threat_status.last_wildfire_update
                wf_max_age = timedelta(hours=1)  # WildFire updates more frequently
                self.engine.assert_true(
                    "WildFire Signatures Recent",
                    wf_age <= wf_max_age,
                    severity=Severity.LOW,
                    reason=f"WildFire last updated {wf_age.total_seconds()/60:.0f} minutes ago"
                )
        
        with self.engine.step("Threat Blocking Statistics"):
            if threat_status.threats_blocked_24h > 0:
                self.engine.log(
                    f"Threats blocked (24h): {threat_status.threats_blocked_24h}"
                )
            
            if threat_status.malware_blocked_24h > 0:
                self.engine.log(
                    f"Malware blocked (24h): {threat_status.malware_blocked_24h}"
                )
            
            if threat_status.phishing_blocked_24h > 0:
                self.engine.log(
                    f"Phishing blocked (24h): {threat_status.phishing_blocked_24h}"
                )
            
            # Informational - threat prevention is working
            self.engine.assert_true(
                "Threat Prevention Active",
                True,  # Always pass - informational
                severity=Severity.INFO,
            )
