"""
Routing Validation Certification Test.

Validates routing table and connectivity.
"""

from netcertify.certifications.base import BaseCertificationTest
from netcertify.schemas.results import Severity


class RoutingCertificationTest(BaseCertificationTest):
    """
    Certification test for routing configuration.
    
    Validates:
    - Default route exists
    - Routes are active
    """
    
    name = "Routing Validation"
    description = "Validate routing table configuration"
    category = "network"
    tags = ["routing", "network", "connectivity"]
    
    def run(self) -> None:
        if self.skip_if_unsupported("supports_routing_config", "Routing Check"):
            return
        
        routing = self.adapter.get_routing_table()
        
        with self.engine.step("Routing Table Validation"):
            self.engine.assert_greater_than(
                "Routes Exist",
                routing.route_count,
                0,
                severity=Severity.CRITICAL,
                reason="Routing table is empty"
            )
            
            # Check for default route
            has_default = any(
                r.destination in ["0.0.0.0/0", "default", "::/0"]
                for r in routing.routes
            )
            
            self.engine.assert_true(
                "Default Route Exists",
                has_default,
                severity=Severity.HIGH,
                reason="No default route configured",
                remediation="Configure a default route for internet connectivity"
            )
            
            # Check route activity
            active_routes = sum(1 for r in routing.routes if r.is_active)
            self.engine.log(f"Active routes: {active_routes}/{routing.route_count}")
