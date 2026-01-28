"""
Security Policy Certification Test.

Validates security policy configuration and best practices.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity
from netcertify.schemas.configuration import PolicyAction


class SecurityPolicyCertificationTest(BaseCertificationTest):
    """
    Certification test for security policies.
    
    Validates:
    - Security policies are configured
    - Default deny rule exists
    - No overly permissive rules
    - Logging is enabled on policies
    """
    
    name = "Security Policy Compliance"
    description = "Validate security policy configuration and best practices"
    category = "security"
    tags = ["security", "policy", "firewall", "access-control"]
    
    def run(self) -> None:
        """Execute security policy certification tests."""
        
        if self.skip_if_unsupported("supports_security_policies", "Security Policy Check"):
            return
        
        policies = self.adapter.get_security_policies()
        zones = self.adapter.get_security_zones()
        
        with self.engine.step("Policy Configuration"):
            self.engine.assert_greater_than(
                "Security Policies Exist",
                len(policies),
                0,
                severity=Severity.CRITICAL,
                reason="No security policies configured",
                remediation="Configure security policies to control traffic flow"
            )
            
            self.engine.log(f"Found {len(policies)} security policies")
        
        with self.engine.step("Default Deny Policy"):
            # Look for a catch-all deny rule
            has_default_deny = False
            for policy in policies:
                if policy.action in [PolicyAction.DENY, PolicyAction.DROP]:
                    # Check if it's a catch-all (any-any)
                    is_any_src = "any" in [str(s).lower() for s in policy.source_addresses]
                    is_any_dst = "any" in [str(d).lower() for d in policy.destination_addresses]
                    is_any_zone_src = "any" in [str(z).lower() for z in policy.source_zones]
                    is_any_zone_dst = "any" in [str(z).lower() for z in policy.destination_zones]
                    
                    if (is_any_src and is_any_dst) or (is_any_zone_src and is_any_zone_dst):
                        has_default_deny = True
                        break
            
            self.engine.assert_true(
                "Default Deny Rule Exists",
                has_default_deny,
                severity=Severity.HIGH,
                reason="No default deny rule found",
                remediation="Add a catch-all deny rule at the end of the policy"
            )
        
        with self.engine.step("Overly Permissive Rules Check"):
            for policy in policies:
                if policy.action != PolicyAction.ALLOW:
                    continue
                
                # Check for any-any-any rules
                is_any_src = "any" in [str(s).lower() for s in policy.source_addresses]
                is_any_dst = "any" in [str(d).lower() for d in policy.destination_addresses]
                is_any_app = "any" in [str(a).lower() for a in policy.applications] if policy.applications else True
                is_any_svc = "any" in [str(s).lower() for s in policy.services] if policy.services else True
                
                is_overly_permissive = is_any_src and is_any_dst and (is_any_app or is_any_svc)
                
                self.engine.assert_false(
                    f"Policy {policy.name} Not Overly Permissive",
                    is_overly_permissive,
                    severity=Severity.HIGH,
                    reason=f"Policy '{policy.name}' allows any-to-any traffic",
                    remediation="Restrict source/destination addresses or applications"
                )
        
        with self.engine.step("Policy Logging Configuration"):
            for policy in policies:
                if policy.action == PolicyAction.ALLOW:
                    # Allow rules should have end logging
                    self.engine.assert_true(
                        f"Policy {policy.name} Logging Enabled",
                        policy.log_end or policy.log_start,
                        severity=Severity.MEDIUM,
                        reason=f"Policy '{policy.name}' has no logging enabled",
                        remediation="Enable session logging for audit trail"
                    )
        
        with self.engine.step("Zone Configuration"):
            if zones:
                self.engine.assert_greater_than(
                    "Security Zones Configured",
                    len(zones),
                    1,
                    severity=Severity.MEDIUM,
                    reason="Multiple security zones recommended for segmentation"
                )
                
                self.engine.log(f"Found {len(zones)} security zones")
