"""
NetCertify Adapters - Vendor-specific firewall drivers.

Adapters provide a unified interface to interact with different firewall vendors.
The test logic remains vendor-agnostic while adapters handle vendor-specific operations.
"""

from netcertify.adapters.base import BaseFirewallAdapter, AdapterCapabilities
from netcertify.adapters.registry import AdapterRegistry, get_adapter

__all__ = [
    "BaseFirewallAdapter",
    "AdapterCapabilities",
    "AdapterRegistry",
    "get_adapter",
]
