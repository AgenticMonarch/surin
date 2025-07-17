"""Base interfaces and abstract classes for SURIN components.

This module defines the core interfaces and data models used throughout the SURIN application.
It includes abstract base classes that define the contract for discovery modules and output
formatters, as well as data models for representing discovered subdomains and results.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Subdomain:
    """Data model representing a discovered subdomain.
    
    This class stores all information related to a discovered subdomain, including
    its name, resolved IP addresses, discovery methods, HTTP/HTTPS status, and
    detected services.
    
    Attributes:
        name: The full subdomain name (e.g., www.example.com)
        domain: The base domain name (e.g., example.com)
        ip_addresses: List of resolved IP addresses for this subdomain
        discovery_methods: List of methods that discovered this subdomain
        is_public: Boolean indicating if the subdomain resolves to a public IP
        http_status: HTTP status code when connecting to the subdomain
        https_status: HTTPS status code when connecting to the subdomain
        open_ports: List of detected open ports on the subdomain
        services: Dictionary mapping port numbers to detected services
    """
    name: str
    domain: str
    ip_addresses: List[str] = None
    discovery_methods: List[str] = None
    is_public: Optional[bool] = None
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    open_ports: List[int] = None
    services: Dict[str, Any] = None

    def __post_init__(self):
        """Initialize default values for optional attributes."""
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.discovery_methods is None:
            self.discovery_methods = []
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}


@dataclass
class Result:
    """Data model representing the complete discovery results.
    
    This class stores all discovered subdomains and aggregated statistics about
    the discovery process, including counts of subdomains found by each method,
    unique IP addresses, and network ranges.
    
    Attributes:
        subdomains: Dictionary mapping subdomain names to Subdomain objects
        stats: Dictionary containing statistics about the discovery results
    """
    subdomains: Dict[str, Subdomain] = None
    stats: Dict[str, Any] = None

    def __post_init__(self):
        """Initialize default values for optional attributes."""
        if self.subdomains is None:
            self.subdomains = {}
        if self.stats is None:
            self.stats = {
                'total_subdomains': 0,  # Total number of unique subdomains discovered
                'unique_ips': 0,        # Number of unique IP addresses
                'public_ips': 0,        # Number of public IP addresses
                'private_ips': 0,       # Number of private IP addresses
                'network_ranges': [],   # List of network ranges in CIDR notation
                'methods': {}           # Statistics per discovery method
            }


class DiscoveryModule(ABC):
    """Base interface for all subdomain discovery modules.
    
    This abstract base class defines the contract that all discovery modules must implement.
    Each discovery module is responsible for implementing a specific subdomain discovery
    technique, such as DNS enumeration, Certificate Transparency logs, or API-based discovery.
    
    Attributes:
        domain: The target domain to discover subdomains for
        config: Dictionary of additional configuration options
    """

    def __init__(self, domain: str, **kwargs):
        """Initialize the discovery module.
        
        Args:
            domain: The target domain to discover subdomains for
            **kwargs: Additional configuration options specific to the discovery method
        """
        self.domain = domain
        self.config = kwargs

    @abstractmethod
    def discover(self) -> List[str]:
        """Execute the discovery method and return subdomains.
        
        This method must be implemented by all discovery modules to perform the actual
        subdomain discovery process. It should handle all necessary API calls, DNS lookups,
        or other operations required to discover subdomains.
        
        Returns:
            List of discovered subdomain names (fully qualified domain names)
            
        Raises:
            APIError: If API operations fail
            NetworkError: If network operations fail
            ConfigurationError: If the module configuration is invalid
        """
        pass

    def validate(self) -> bool:
        """Validate module configuration.
        
        This method validates the module's configuration to ensure it has all required
        parameters and can function correctly. Subclasses should override this method
        if they require specific validation logic.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        return True

    @property
    def name(self) -> str:
        """Return the name of this discovery method.
        
        Returns:
            The name of the discovery method, derived from the class name
        """
        return self.__class__.__name__.replace('Module', '')


class OutputFormatter(ABC):
    """Base interface for output formatters.
    
    This abstract base class defines the contract that all output formatters must implement.
    Each formatter is responsible for converting the discovery results into a specific
    output format, such as text, JSON, or CSV.
    """

    @abstractmethod
    def format(self, result: Result) -> str:
        """Format the result for output.
        
        This method must be implemented by all output formatters to convert the
        discovery results into a formatted string representation.
        
        Args:
            result: The discovery result to format
            
        Returns:
            Formatted string representation in the specific output format
        """
        pass