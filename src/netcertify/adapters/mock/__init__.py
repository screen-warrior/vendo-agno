"""
Mock Adapter - Simulated firewall adapter for testing.

Provides a fully functional mock implementation for testing the certification
framework without requiring real firewall devices.
"""

from netcertify.adapters.mock.adapter import MockFirewallAdapter

__all__ = ["MockFirewallAdapter"]
